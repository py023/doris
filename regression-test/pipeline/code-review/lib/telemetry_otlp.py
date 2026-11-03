# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Encode, size and upload OTLP spans with bounded retries."""

import base64
from copy import deepcopy
from datetime import datetime, timezone
import gzip
import hashlib
import json
import time
import urllib.error
import urllib.request

from telemetry_common import (
    compact_json_bytes,
    json_attr,
    json_payload_bytes,
    truncate_json,
    truncate_text,
)


OTLP_RETRYABLE_HTTP_STATUS_CODES = frozenset((429, 502, 503, 504))


def compact_context_event(event, max_chars):
    compact = {}
    for key in (
        "event_type",
        "line_number",
        "item_id",
        "item_type",
        "status",
        "server",
        "tool",
        "exit_code",
    ):
        if event.get(key) not in (None, ""):
            compact[key] = event.get(key)
    if event.get("command"):
        compact["command"] = truncate_text(event.get("command") or "", max_chars)
    for key in ("arguments", "result", "error", "payload", "item"):
        if key in event:
            compact[key] = truncate_json(event.get(key), max_chars)
    for key in ("aggregated_output", "text", "prompt"):
        if event.get(key):
            compact[key] = truncate_text(event.get(key) or "", max_chars, tail=True)
    return compact


def shrink_event_for_payload(event, max_payload_bytes, payload_bytes, minimize=False):
    body = event["body"]
    event_name = body.get("name")

    def candidate_with_limits(max_chars, max_context_events=None):
        candidate = deepcopy(event)
        candidate_body = candidate["body"]
        input_object = candidate_body.get("input")
        if isinstance(input_object, dict):
            context_events = input_object.get("events_since_previous_agent_message")
            if isinstance(context_events, list):
                compact_events = [
                    compact_context_event(context_event, max_chars)
                    for context_event in context_events
                ]
                if max_context_events is not None:
                    omitted_count = max(len(compact_events) - max_context_events, 0)
                    if max_context_events <= 0:
                        compact_events = []
                    else:
                        compact_events = compact_events[-max_context_events:]
                    if omitted_count:
                        input_object["events_since_previous_agent_message_omitted_count"] = (
                            omitted_count
                        )
                input_object["events_since_previous_agent_message"] = compact_events
            if isinstance(input_object.get("previous_agent_message"), dict):
                previous_message = input_object["previous_agent_message"]
                previous_message["text"] = truncate_text(
                    previous_message.get("text") or "", max_chars
                )
            if input_object.get("turn_input"):
                input_object["turn_input"] = truncate_text(
                    input_object.get("turn_input") or "", max_chars
                )
            if not (
                isinstance(context_events, list)
                or "previous_agent_message" in input_object
                or "turn_input" in input_object
            ):
                candidate_body["input"] = truncate_json(input_object, max_chars)
        elif input_object not in (None, ""):
            candidate_body["input"] = truncate_json(input_object, max_chars)

        output_object = candidate_body.get("output")
        if output_object not in (None, ""):
            candidate_body["output"] = truncate_json(output_object, max_chars)
        metadata = candidate_body.get("metadata")
        if metadata not in (None, ""):
            candidate_body["metadata"] = truncate_json(metadata, max_chars)
        status_message = candidate_body.get("statusMessage")
        if status_message not in (None, ""):
            candidate_body["statusMessage"] = truncate_text(str(status_message), max_chars)
        return candidate

    if minimize:
        # This policy floor keeps adaptive 413 retries above the fixed OTLP
        # envelope while removing every field that the exporter can shrink.
        candidate = candidate_with_limits(10, 0)
        if payload_bytes(candidate) < payload_bytes(event):
            return candidate
        return event

    def maximize_candidate(max_chars, max_context_events=None):
        best = candidate_with_limits(max_chars, max_context_events)
        lower = max_chars + 1
        upper = max_payload_bytes
        while lower <= upper:
            middle = (lower + upper) // 2
            candidate = candidate_with_limits(middle, max_context_events)
            if payload_bytes(candidate) <= max_payload_bytes:
                best = candidate
                lower = middle + 1
            else:
                upper = middle - 1
        return best

    for max_chars in (2_000, 1_000, 500, 200, 80):
        candidate = candidate_with_limits(max_chars)

        if payload_bytes(candidate) <= max_payload_bytes:
            return maximize_candidate(max_chars)

    for max_context_events in (50, 20, 10, 5, 2, 1, 0):
        for max_chars in (80, 40, 20, 10):
            candidate = candidate_with_limits(max_chars, max_context_events)
            if payload_bytes(candidate) <= max_payload_bytes:
                return maximize_candidate(max_chars, max_context_events)

    raise RuntimeError(
        "Litefuse ingestion event is too large after truncation: "
        f"{payload_bytes(event)} bytes > {max_payload_bytes} bytes; "
        f"type={event.get('type')}, name={event_name}"
    )


def otel_id(value, byte_count):
    expected_length = byte_count * 2
    normalized = str(value or "").lower()
    if len(normalized) == expected_length and all(
        char in "0123456789abcdef" for char in normalized
    ):
        return normalized
    return hashlib.blake2b(normalized.encode(), digest_size=byte_count).hexdigest()


def unix_nanos(timestamp):
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"OpenTelemetry timestamp has no timezone: {timestamp}")
    delta = parsed.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    seconds = delta.days * 86_400 + delta.seconds
    return str(seconds * 1_000_000_000 + delta.microseconds * 1_000)


def otel_any_value(value):
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, str):
        return {"stringValue": value}
    if isinstance(value, list) and all(isinstance(item, (bool, int, float, str)) for item in value):
        return {"arrayValue": {"values": [otel_any_value(item) for item in value]}}
    return {"stringValue": json_attr(value)}


def otel_attributes(values):
    return [
        {"key": key, "value": otel_any_value(value)}
        for key, value in values.items()
        if value is not None
    ]


def serialized_otel_value(value):
    if isinstance(value, str):
        return value
    return json_attr(value)


def metadata_otel_attributes(prefix, metadata):
    if not isinstance(metadata, dict):
        return {prefix: serialized_otel_value(metadata)} if metadata is not None else {}
    return {
        f"{prefix}.{key}": (
            value if isinstance(value, (str, int)) else serialized_otel_value(value)
        )
        for key, value in metadata.items()
        if value is not None
    }


def trace_body_from_payload(payload):
    for event in payload["batch"]:
        if event["type"] == "trace-create":
            return event["body"]
    raise RuntimeError("Litefuse payload is missing its trace-create context event")


def legacy_event_to_otel_span(event, trace_body):
    event_type = event.get("type")
    if event_type not in ("span-create", "generation-create"):
        raise RuntimeError(f"Unsupported trace event for OTLP conversion: {event_type}")
    body = event["body"]
    trace_id = otel_id(body.get("traceId"), 16)
    span_id = otel_id(body.get("id"), 8)
    parent_id = body.get("parentObservationId")
    start_time = body.get("startTime") or event.get("timestamp")
    end_time = body.get("endTime") or start_time

    attributes = {
        "langfuse.trace.name": trace_body.get("name"),
        "session.id": trace_body.get("sessionId"),
        "langfuse.trace.tags": trace_body.get("tags"),
        "langfuse.environment": body.get("environment") or trace_body.get("environment"),
        "langfuse.observation.type": (
            "generation" if event_type == "generation-create" else "span"
        ),
        "langfuse.observation.input": (
            serialized_otel_value(body["input"]) if body.get("input") is not None else None
        ),
        "langfuse.observation.output": (
            serialized_otel_value(body["output"]) if body.get("output") is not None else None
        ),
        "langfuse.observation.level": body.get("level"),
        "langfuse.observation.status_message": body.get("statusMessage"),
    }
    attributes.update(
        metadata_otel_attributes("langfuse.trace.metadata", trace_body.get("metadata") or {})
    )
    attributes.update(
        metadata_otel_attributes("langfuse.observation.metadata", body.get("metadata") or {})
    )
    if event_type == "generation-create":
        attributes["langfuse.observation.model.name"] = body.get("model")
        if body.get("usageDetails") is not None:
            attributes["langfuse.observation.usage_details"] = serialized_otel_value(
                body["usageDetails"]
            )
    if not parent_id:
        attributes["langfuse.internal.is_app_root"] = True

    span = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": body.get("name") or "codex.unknown",
        "kind": 1,
        "startTimeUnixNano": unix_nanos(start_time),
        "endTimeUnixNano": unix_nanos(end_time),
        "attributes": otel_attributes(attributes),
        "status": {
            # statusMessage is already carried by the explicit Langfuse attribute.
            # Do not duplicate a potentially large failure payload here.
            "code": 2 if body.get("level") == "ERROR" else 1,
        },
        "flags": 1,
    }
    if parent_id:
        span["parentSpanId"] = otel_id(parent_id, 8)
    return span


def otlp_payload(trace_body, events):
    return otlp_envelope(
        trace_body, [legacy_event_to_otel_span(event, trace_body) for event in events]
    )


def otlp_envelope(trace_body, spans):
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": otel_attributes(
                        {
                            "service.name": "doris-code-review",
                            "langfuse.environment": trace_body.get("environment"),
                        }
                    )
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "doris-litefuse-exporter", "version": "2"},
                        "spans": spans,
                    }
                ],
            }
        ]
    }


def otlp_span_count(payload):
    return sum(
        len(scope_spans.get("spans") or [])
        for resource_spans in payload.get("resourceSpans") or []
        for scope_spans in resource_spans.get("scopeSpans") or []
    )


def otlp_chunks(payload, max_payload_bytes, trace_body=None):
    trace_body = trace_body if trace_body is not None else trace_body_from_payload(payload)
    chunks = []
    events, spans = [], []
    envelope_size = json_payload_bytes(otlp_envelope(trace_body, []))
    size = envelope_size
    for event in payload["batch"]:
        if event["type"] not in ("span-create", "generation-create"):
            continue
        span = legacy_event_to_otel_span(event, trace_body)
        span_size = len(compact_json_bytes(span))
        if envelope_size + span_size > max_payload_bytes:
            event = shrink_event_for_payload(
                event,
                max_payload_bytes,
                payload_bytes=lambda candidate: json_payload_bytes(
                    otlp_payload(trace_body, [candidate])
                ),
            )
            span = legacy_event_to_otel_span(event, trace_body)
            span_size = len(compact_json_bytes(span))
        # JSON array size is additive; measure each ordinary span only once.
        if spans and size + span_size + 1 > max_payload_bytes:
            chunks.append(({"batch": events}, otlp_envelope(trace_body, spans), size))
            events, spans, size = [], [], envelope_size
        size += span_size + bool(spans)
        events.append(event)
        spans.append(span)
    if spans:
        chunks.append(({"batch": events}, otlp_envelope(trace_body, spans), size))
    if not chunks:
        raise RuntimeError("Litefuse payload contains no spans for OTLP ingestion")
    return chunks


def split_otlp_chunk(chunk, max_payload_bytes, trace_body):
    events = chunk["batch"]
    if len(events) < 2:
        raise RuntimeError("Cannot split an OTLP chunk with fewer than two spans")
    middle = len(events) // 2
    return otlp_chunks({"batch": events[:middle]}, max_payload_bytes, trace_body) + otlp_chunks(
        {"batch": events[middle:]}, max_payload_bytes, trace_body
    )


def shrink_singleton_otlp_retry(chunk, rejected_size, trace_body, attempt_count, retry_attempts):
    event = chunk["batch"][0]
    # Preserve a near-limit payload on the first rejection. If the server rejects
    # it again, bisect the remaining reducible envelope instead of retrying one
    # byte at a time. The last allowed retry uses the floor so a viable minimal
    # span is attempted before the budget is exhausted.
    if attempt_count == 1 and retry_attempts > 1:
        return otlp_chunks(chunk, rejected_size - 1, trace_body)

    def encoded_size(candidate):
        return json_payload_bytes(otlp_payload(trace_body, [candidate]))

    floor_event = shrink_event_for_payload(
        event,
        rejected_size,
        payload_bytes=encoded_size,
        minimize=True,
    )
    floor_size = encoded_size(floor_event)
    if floor_size >= rejected_size:
        raise RuntimeError(
            "Litefuse OTLP singleton cannot be reduced below the rejected size: "
            f"{rejected_size} bytes; name={(event.get('body') or {}).get('name')}"
        )
    next_limit = (
        floor_size
        if attempt_count == retry_attempts
        else floor_size + (rejected_size - floor_size) // 2
    )
    return otlp_chunks(chunk, next_limit, trace_body)


def post_payload_once(
    endpoint, public_key, secret_key, payload, timeout_seconds, gzip_enabled=False
):
    auth = base64.b64encode(f"{public_key}:{secret_key}".encode()).decode()
    data = compact_json_bytes(payload)
    if gzip_enabled:
        data = gzip.compress(data, compresslevel=1, mtime=0)
    request = urllib.request.Request(
        endpoint,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Basic {auth}",
            "x-langfuse-ingestion-version": "4",
            "x-langfuse-sdk-name": "doris-code-review",
            "x-langfuse-sdk-version": "2",
        },
        method="POST",
    )
    if gzip_enabled:
        request.add_header("Content-Encoding", "gzip")
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        body = response.read().decode()
        detail = json.loads(body) if body else {}
        partial_success = detail.get("partialSuccess") or detail.get("partial_success") or {}
        rejected_spans = int(
            partial_success.get("rejectedSpans") or partial_success.get("rejected_spans") or 0
        )
        if rejected_spans:
            raise RuntimeError(
                "Litefuse OTLP ingestion partially rejected "
                f"{rejected_spans} spans: {json_attr(partial_success)}"
            )
        return {
            "status": response.status,
            "success_count": otlp_span_count(payload),
            "wire_bytes": len(data),
        }


def post_payload(
    endpoint,
    public_key,
    secret_key,
    payload,
    max_payload_bytes,
    timeout_seconds,
    retry_attempts,
    retry_sleep_seconds,
    gzip_enabled=False,
):
    upload_started = time.monotonic()
    statuses = []
    success_count = 0
    request_sizes = []
    wire_request_sizes = []
    payload_too_large_retry_count = 0
    transport_retry_count = 0
    http_retry_count = 0
    post_attempt_count = 0
    singleton_413_attempts = {}
    singleton_413_sources = {}
    trace_body = trace_body_from_payload(payload)
    chunks = otlp_chunks(payload, max_payload_bytes, trace_body)
    while chunks:
        chunk, otlp_chunk, request_size = chunks.pop(0)
        post_attempt_count += 1
        try:
            status = post_payload_once(
                endpoint,
                public_key,
                secret_key,
                otlp_chunk,
                timeout_seconds,
                gzip_enabled=gzip_enabled,
            )
        except urllib.error.HTTPError as exc:
            if exc.code in OTLP_RETRYABLE_HTTP_STATUS_CODES:
                http_retry_count += 1
                if http_retry_count <= retry_attempts:
                    time.sleep(retry_sleep_seconds)
                    chunks.insert(0, (chunk, otlp_chunk, request_size))
                    continue
                error_body = exc.read().decode("utf-8", errors="replace")
                raise RuntimeError(
                    "Litefuse OTLP ingestion failed after HTTP retries: "
                    f"HTTP {exc.code}: {truncate_text(error_body, 4_000)}"
                ) from exc
            if exc.code != 413:
                error_body = exc.read().decode("utf-8", errors="replace")
                raise RuntimeError(
                    "Litefuse OTLP ingestion returned "
                    f"HTTP {exc.code}: {truncate_text(error_body, 4_000)}"
                ) from exc
            payload_too_large_retry_count += 1
            chunk_events = chunk["batch"]
            if len(chunk_events) > 1:
                chunks = split_otlp_chunk(chunk, max_payload_bytes, trace_body) + chunks
                continue
            event = chunk_events[0]
            body = event["body"]
            event_key = (
                event.get("type"),
                str(body.get("traceId") or ""),
                str(body.get("id") or ""),
            )
            singleton_413_sources.setdefault(event_key, chunk)
            singleton_413_attempts[event_key] = singleton_413_attempts.get(event_key, 0) + 1
            attempt_count = singleton_413_attempts[event_key]
            if attempt_count > retry_attempts:
                raise RuntimeError(
                    "Litefuse OTLP singleton remained too large after "
                    f"{retry_attempts} retries: {request_size} bytes; "
                    f"observation_id={body.get('id')}"
                ) from exc
            chunks = (
                shrink_singleton_otlp_retry(
                    singleton_413_sources[event_key],
                    request_size,
                    trace_body,
                    attempt_count,
                    retry_attempts,
                )
                + chunks
            )
            continue
        except (TimeoutError, urllib.error.URLError) as exc:
            transport_retry_count += 1
            if transport_retry_count > retry_attempts:
                raise RuntimeError(
                    "Litefuse OTLP ingestion failed after transport retries: "
                    f"{type(exc).__name__}: {exc}"
                ) from exc
            time.sleep(retry_sleep_seconds)
            chunk_events = chunk["batch"]
            if len(chunk_events) > 1:
                chunks = split_otlp_chunk(chunk, max_payload_bytes, trace_body) + chunks
            else:
                chunks.insert(
                    0,
                    (chunk, otlp_chunk, request_size),
                )
            continue
        statuses.append(status["status"])
        success_count += status["success_count"]
        request_sizes.append(request_size)
        wire_request_sizes.append(status["wire_bytes"])
    return {
        "compression": "gzip" if gzip_enabled else "none",
        "upload_seconds": round(time.monotonic() - upload_started, 3),
        "statuses": statuses,
        "request_count": len(statuses),
        "post_attempt_count": post_attempt_count,
        "request_sizes": request_sizes,
        # Like request_sizes, these sizes cover successful requests only.
        "wire_request_sizes": wire_request_sizes,
        "max_request_size": max(request_sizes),
        "payload_too_large_retries": payload_too_large_retry_count,
        "transport_retries": transport_retry_count,
        "http_retries": http_retry_count,
        "success_count": success_count,
    }
