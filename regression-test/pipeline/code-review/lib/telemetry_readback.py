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

"""Verify exported trace I/O within a shared readback deadline."""

import base64
from datetime import datetime, timedelta, timezone
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from telemetry_otlp import otel_id


def verification_request_timeout(deadline):
    if deadline is None:
        return 30
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Litefuse verification deadline exhausted")
    return min(30, remaining)


def fetch_json(base_url, public_key, secret_key, path, *, deadline, **query):
    auth = base64.b64encode(f"{public_key}:{secret_key}".encode()).decode()
    url = f"{base_url.rstrip('/')}/api/public/{path}"
    if query:
        url += "?" + urllib.parse.urlencode(query)
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Basic {auth}"},
        method="GET",
    )
    with urllib.request.urlopen(
        request, timeout=verification_request_timeout(deadline)
    ) as response:
        return json.loads(response.read().decode())


def fetch_trace(base_url, public_key, secret_key, trace_id, *, deadline=None):
    return fetch_json(base_url, public_key, secret_key, f"traces/{trace_id}", deadline=deadline)


def fetch_observations_v2(
    base_url,
    public_key,
    secret_key,
    trace_id,
    max_pages=10,
    *,
    deadline=None,
    start_time=None,
    end_time=None,
):
    now = datetime.now(timezone.utc)
    query = {
        "traceId": trace_id,
        "fromStartTime": start_time
        or (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "toStartTime": end_time or (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "fields": "core,basic,io,trace_context,model,usage",
        "limit": "1000",
    }
    rows = []
    cursor = ""
    for _ in range(max_pages):
        if cursor:
            query["cursor"] = cursor
        payload = fetch_json(
            base_url, public_key, secret_key, "v2/observations", deadline=deadline, **query
        )
        rows.extend(payload["data"])
        cursor = payload.get("meta", {}).get("cursor")
        if not cursor:
            return {**payload, "data": rows}
    raise RuntimeError(
        f"Litefuse v2 observations remained paginated after {max_pages} pages for trace {trace_id}"
    )


def fetch_observations_legacy(
    base_url, public_key, secret_key, trace_id, max_pages=10, *, deadline=None
):
    limit = 100
    rows = []
    for page in range(1, max_pages + 1):
        payload = fetch_json(
            base_url,
            public_key,
            secret_key,
            "observations",
            deadline=deadline,
            traceId=trace_id,
            limit=limit,
            page=page,
        )
        page_rows = payload["data"]
        rows.extend(page_rows)
        if len(page_rows) < limit:
            return {**payload, "data": rows}
    raise RuntimeError(
        f"Litefuse observations remained paginated after {max_pages} pages for trace {trace_id}"
    )


def observation_io_object(observation, field):
    value = observation.get(field)
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}


def context_event_types(events_value):
    if isinstance(events_value, list):
        return [
            event.get("item_type") or event.get("event_type")
            for event in events_value
            if isinstance(event, dict)
        ]
    if isinstance(events_value, dict) and "truncated_json" in events_value:
        return ["truncated_json"]
    return []


def context_events_readback_ok(input_object):
    context_window = input_object.get("context_window")
    event_count = 0
    if isinstance(context_window, dict):
        try:
            event_count = int(context_window.get("event_count") or 0)
        except (TypeError, ValueError):
            event_count = 0
    events_value = input_object.get("events_since_previous_agent_message")
    if isinstance(events_value, list):
        return True
    return event_count == 0 and events_value in (None, "", {})


def trace_verification_target(result, payload, *, subagent=False):
    observations = [
        event["body"]
        for event in payload["batch"]
        if event["type"] in ("span-create", "generation-create")
    ]
    start_times = [
        datetime.fromisoformat(body["startTime"].replace("Z", "+00:00")) for body in observations
    ]
    # Subagent sessions retain their original timestamps, including sessions
    # older than the v2 reader's default one-hour window.
    target = {
        "result": result,
        "subagent": subagent,
        "start_time": (min(start_times) - timedelta(seconds=1)).isoformat(),
        "end_time": (max(start_times) + timedelta(seconds=1)).isoformat(),
    }
    if subagent:
        target["expected_io"] = {
            otel_id(body["id"], 8): [
                field for field in ("input", "output") if body.get(field) is not None
            ]
            for body in observations
        }
    return target


def observation_has_expected_io(observation, target):
    if not target["subagent"]:
        return bool(observation.get("input") and observation.get("output"))
    # Empty objects, lists and strings are legitimate session event payloads.
    # Only require fields actually sent by the exporter (None is not exported).
    fields = target["expected_io"].get(str(observation.get("id")), ())
    return all(observation.get(field) is not None for field in fields)


def inspect_observations(
    args, target, observations, legacy_detail, read_source, legacy_trace_error
):
    result = target["result"]
    subagent = target["subagent"]
    root_name = "codex.subagent.review" if subagent else "codex.review"
    required_observation_count = max(
        1 if subagent else args.min_observations, result["observation_count"]
    )
    observations_missing_io = [
        observation
        for observation in observations
        if not observation_has_expected_io(observation, target)
    ]
    observation_ids = [
        str(observation.get("id")) for observation in observations if observation.get("id")
    ]
    unique_observation_count = len(set(observation_ids))
    observations_missing_id_count = len(observations) - len(observation_ids)
    duplicate_observation_count = len(observation_ids) - unique_observation_count
    step_observations = [
        observation
        for observation in observations
        if observation.get("name") not in (root_name, "codex.turn")
    ]
    agent_message_observations = [
        observation
        for observation in observations
        if observation.get("name") == "codex.agent_message"
    ]
    agent_message_input_objects = [
        observation_io_object(observation, "input") for observation in agent_message_observations
    ]
    agent_message_input_keys = sorted(
        {key for input_object in agent_message_input_objects for key in input_object.keys()}
    )
    agent_message_all_have_context_window = all(
        bool(input_object.get("context_window")) for input_object in agent_message_input_objects
    )
    agent_message_all_have_context_events = all(
        context_events_readback_ok(input_object) for input_object in agent_message_input_objects
    )
    agent_message_with_previous_count = sum(
        1
        for input_object in agent_message_input_objects
        if bool(input_object.get("previous_agent_message"))
    )
    agent_message_with_turn_input_count = sum(
        1 for input_object in agent_message_input_objects if bool(input_object.get("turn_input"))
    )
    agent_message_context_event_counts = [
        (input_object.get("context_window") or {}).get("event_count", 0)
        for input_object in agent_message_input_objects[:20]
        if isinstance(input_object.get("context_window"), dict)
    ]
    agent_message_event_type_samples = [
        context_event_types(input_object.get("events_since_previous_agent_message"))[:8]
        for input_object in agent_message_input_objects[:5]
    ]
    agent_message_structure_ok = (
        agent_message_all_have_context_window
        and agent_message_all_have_context_events
        and agent_message_with_turn_input_count == 1
        and (agent_message_with_previous_count == max(len(agent_message_observations) - 1, 0))
    )
    root_observation = next(
        (observation for observation in observations if observation.get("name") == root_name),
        {},
    )
    trace_input = legacy_detail.get("input") or root_observation.get("input")
    trace_output = legacy_detail.get("output") or root_observation.get("output")
    expected_ids = set(target.get("expected_io", {}))
    missing_expected_ids = sorted(expected_ids - set(observation_ids))
    last_diagnostic = {
        "read_source": read_source,
        "root_observation": bool(root_observation),
        "missing_expected_observation_count": len(missing_expected_ids),
        "missing_expected_observation_ids": missing_expected_ids[:20],
        "legacy_trace_input": bool(legacy_detail.get("input")),
        "legacy_trace_output": bool(legacy_detail.get("output")),
        "legacy_trace_error": legacy_trace_error,
        "trace_input": bool(trace_input),
        "trace_output": bool(trace_output),
        "observation_count": len(observations),
        "required_observation_count": required_observation_count,
        "unique_observation_count": unique_observation_count,
        "observations_missing_id_count": observations_missing_id_count,
        "duplicate_observation_count": duplicate_observation_count,
        "step_observation_count": len(step_observations),
        "agent_message_count": len(agent_message_observations),
        "agent_message_input_keys": agent_message_input_keys,
        "agent_message_all_have_context_window": agent_message_all_have_context_window,
        "agent_message_all_have_context_events": agent_message_all_have_context_events,
        "agent_message_with_previous_count": agent_message_with_previous_count,
        "agent_message_with_turn_input_count": agent_message_with_turn_input_count,
        "agent_message_context_event_counts": agent_message_context_event_counts,
        "agent_message_event_type_samples": agent_message_event_type_samples,
        "observations_missing_io": [
            observation.get("name") for observation in observations_missing_io[:20]
        ],
        "observation_names": [observation.get("name") for observation in observations[:20]],
    }
    ok = all(
        [
            root_observation,
            not missing_expected_ids,
            trace_input,
            trace_output,
            unique_observation_count >= required_observation_count,
            observations_missing_id_count == 0,
            duplicate_observation_count == 0,
            len(step_observations) >= (0 if subagent else args.min_step_observations),
            not observations_missing_io,
            not agent_message_observations or agent_message_structure_ok,
        ]
    )
    return ok, last_diagnostic


def inspect_trace(args, public_key, secret_key, target, deadline):
    result = target["result"]
    trace_id = result["trace_id"]
    required_observation_count = max(
        1 if target["subagent"] else args.min_observations, result["observation_count"]
    )
    legacy_trace_error = ""
    try:
        legacy_detail = fetch_trace(
            args.base_url, public_key, secret_key, trace_id, deadline=deadline
        )
    except (OSError, ValueError, RuntimeError) as exc:
        legacy_detail = {}
        legacy_trace_error = type(exc).__name__

    # Some deployments return all observation IO in trace detail. Apply the
    # same complete validation before downloading those observations again.
    ok, detail_diagnostic = inspect_observations(
        args,
        target,
        legacy_detail.get("observations") or [],
        legacy_detail,
        "legacy_trace",
        legacy_trace_error,
    )
    if ok:
        return ok, detail_diagnostic

    try:
        observations_payload = fetch_observations_legacy(
            args.base_url,
            public_key,
            secret_key,
            trace_id,
            max_pages=max(10, required_observation_count // 100 + 1),
            deadline=deadline,
        )
        observations = observations_payload["data"]
        read_source = "legacy_observations"
    except (OSError, ValueError, RuntimeError) as exc:
        try:
            observations_payload = fetch_observations_v2(
                args.base_url,
                public_key,
                secret_key,
                trace_id,
                max_pages=max(10, required_observation_count // 1000 + 1),
                deadline=deadline,
                start_time=target.get("start_time"),
                end_time=target.get("end_time"),
            )
            observations = observations_payload["data"]
            read_source = "v2_observations"
        except (OSError, ValueError, RuntimeError):
            return False, {
                **detail_diagnostic,
                "read_source": f"legacy_trace_fallback:{type(exc).__name__}",
            }
    return inspect_observations(
        args, target, observations, legacy_detail, read_source, legacy_trace_error
    )


def verify_traces(args, public_key, secret_key, targets):
    # All exported traces share polling rounds and one elapsed-time budget.
    # Never restart the wait budget for each subagent.
    deadline = time.monotonic() + args.verify_timeout_seconds
    pending = list(targets)
    for target in pending:
        target["result"]["verification_diagnostic"] = {"read_source": "not_polled"}
    for attempt in range(args.verify_attempts):
        for target in pending:
            if time.monotonic() >= deadline:
                break
            ok, diagnostic = inspect_trace(args, public_key, secret_key, target, deadline)
            result = target["result"]
            result["verification_diagnostic"] = diagnostic
            if ok:
                result["verified"] = diagnostic
                del result["verification_diagnostic"]
        pending = [target for target in pending if "verification_diagnostic" in target["result"]]
        if not pending:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0 or attempt + 1 == args.verify_attempts:
            break
        time.sleep(min(args.verify_sleep_seconds, remaining))
    diagnostics = {
        target["result"]["trace_id"]: target["result"]["verification_diagnostic"]
        for target in pending
    }
    raise RuntimeError(
        "Litefuse traces did not expose complete I/O in time; "
        f"pending_traces={json.dumps(diagnostics, sort_keys=True)}"
    )
