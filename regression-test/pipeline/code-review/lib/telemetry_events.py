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

"""Build trace observations from Codex exec events and subagent session logs."""

import json
import os
import secrets
import time

from telemetry_common import (
    iso_from_ns,
    json_attr,
    load_jsonl,
    ns_from_iso,
    truncate_json,
    truncate_text,
)


def find_final_message(events, output_text):
    if output_text.strip():
        return output_text
    for event in reversed(events):
        item = event.get("item") or {}
        if event.get("type") == "item.completed" and item.get("type") == "agent_message":
            text = item.get("text") or ""
            if text.strip():
                return text
    return ""


def latest_turn_result(events):
    for event in reversed(events):
        if event.get("type") == "turn.completed":
            return "completed", event.get("usage") or {}
        if event.get("type") == "turn.failed":
            return "failed", event.get("error") or {}
    return "unknown", {}


def event_context_payload(event, max_json_chars):
    item = event.get("item")
    payload = {
        "event_type": event.get("type"),
        "line_number": event.get("_line_number"),
    }
    if not item:
        event_payload = {key: value for key, value in event.items() if key != "_line_number"}
        payload["payload"] = truncate_json(event_payload, max_json_chars)
        return payload

    item_type = item.get("type", "unknown")
    payload.update(
        {
            "item_id": item.get("id", ""),
            "item_type": item_type,
            "status": item.get("status"),
        }
    )

    if item_type == "command_execution":
        payload.update(
            {
                "command": item.get("command") or "",
                "exit_code": item.get("exit_code"),
                "aggregated_output": truncate_text(
                    item.get("aggregated_output") or "", max_json_chars, tail=True
                ),
            }
        )
    elif item_type == "mcp_tool_call":
        payload.update(
            {
                "server": item.get("server"),
                "tool": item.get("tool"),
                "arguments": truncate_json(item.get("arguments"), max_json_chars),
                "result": truncate_json(item.get("result"), max_json_chars),
                "error": truncate_json(item.get("error"), max_json_chars),
            }
        )
    elif item_type == "collab_tool_call":
        payload.update(
            {
                "tool": item.get("tool"),
                "prompt": truncate_text(item.get("prompt") or "", max_json_chars),
                "sender_thread_id": item.get("sender_thread_id"),
                "receiver_thread_ids": item.get("receiver_thread_ids") or [],
                "agents_states": truncate_json(item.get("agents_states"), max_json_chars),
            }
        )
    elif item_type == "agent_message":
        payload["text"] = truncate_text(item.get("text") or "", max_json_chars)
    else:
        payload["item"] = truncate_json(item, max_json_chars)

    return {key: value for key, value in payload.items() if value not in (None, "")}


def build_agent_message_inputs(events, turn_input, max_json_chars, max_context_json_chars):
    inputs = {}
    previous_agent_message = None
    context_events = []
    for event in events:
        item = event.get("item") or {}
        is_agent_message = (
            event.get("type") == "item.completed" and item.get("type") == "agent_message"
        )
        if is_agent_message:
            current_id = item.get("id") or f"line:{event.get('_line_number', 0)}"
            input_payload = {
                "item_type": "agent_message",
                "context_window": {
                    "from": (
                        previous_agent_message.get("id") if previous_agent_message else "turn_start"
                    ),
                    "to": current_id,
                    "event_count": len(context_events),
                },
                "events_since_previous_agent_message": [
                    event_context_payload(context_event, max_context_json_chars)
                    for context_event in context_events
                ],
            }
            if previous_agent_message:
                input_payload["previous_agent_message"] = {
                    "id": previous_agent_message.get("id", ""),
                    "text": truncate_text(previous_agent_message.get("text") or "", max_json_chars),
                }
            else:
                input_payload["turn_input"] = truncate_text(turn_input, max_json_chars)
            inputs[event.get("_line_number")] = input_payload
            previous_agent_message = item
            context_events = []
        else:
            context_events.append(event)
    return inputs


def observation_shape(item, max_json_chars, agent_message_input=None):
    item_type = item.get("type", "unknown")
    status = item.get("status")

    if item_type == "command_execution":
        command = item.get("command") or ""
        return {
            "name": "codex.command",
            "type": "span",
            "input": {"command": command},
            "output": {
                "status": status,
                "exit_code": item.get("exit_code"),
                "aggregated_output": truncate_text(
                    item.get("aggregated_output") or "", max_json_chars, tail=True
                ),
            },
            "metadata": {"command": command[:240], "status": status, "step_kind": "tool"},
        }

    if item_type == "mcp_tool_call":
        return {
            "name": f"codex.mcp.{item.get('server', 'unknown')}.{item.get('tool', 'unknown')}",
            "type": "span",
            "input": {
                "server": item.get("server"),
                "tool": item.get("tool"),
                "arguments": truncate_json(item.get("arguments"), max_json_chars),
            },
            "output": {
                "status": status,
                "result": truncate_json(item.get("result"), max_json_chars),
                "error": truncate_json(item.get("error"), max_json_chars),
            },
            "metadata": {
                "server": item.get("server"),
                "tool": item.get("tool"),
                "status": status,
                "step_kind": "tool",
            },
        }

    if item_type == "collab_tool_call":
        return {
            "name": f"codex.collab.{item.get('tool', 'unknown')}",
            "type": "span",
            "input": {
                "tool": item.get("tool"),
                "prompt": truncate_text(item.get("prompt") or "", max_json_chars),
                "sender_thread_id": item.get("sender_thread_id"),
            },
            "output": {
                "status": status,
                "receiver_thread_ids": item.get("receiver_thread_ids") or [],
                "agents_states": truncate_json(item.get("agents_states"), max_json_chars),
            },
            "metadata": {"tool": item.get("tool"), "status": status, "step_kind": "tool"},
        }

    if item_type == "web_search":
        return {
            "name": "codex.web_search",
            "type": "span",
            "input": {"query": item.get("query"), "action": item.get("action")},
            "output": {"status": "completed", "query": item.get("query")},
            "metadata": {"query": (item.get("query") or "")[:240], "step_kind": "tool"},
        }

    if item_type == "file_change":
        return {
            "name": "codex.file_change",
            "type": "span",
            "input": {"changes": item.get("changes") or []},
            "output": {"status": status, "changes": item.get("changes") or []},
            "metadata": {"status": status},
        }

    if item_type == "todo_list":
        return {
            "name": "codex.todo_list",
            "type": "span",
            "input": {"item_type": item_type},
            "output": {"items": item.get("items") or []},
            "metadata": {"item_count": len(item.get("items") or [])},
        }

    if item_type == "reasoning":
        return {
            "name": "codex.reasoning",
            "type": "span",
            "input": {"item_type": item_type},
            "output": {"text": truncate_text(item.get("text") or "", max_json_chars)},
            "metadata": {},
        }

    if item_type == "agent_message":
        return {
            "name": "codex.agent_message",
            "type": "generation",
            "input": agent_message_input or {"item_type": item_type},
            "output": {"text": truncate_text(item.get("text") or "", max_json_chars)},
            "metadata": {},
        }

    if item_type == "error":
        return {
            "name": "codex.error",
            "type": "span",
            "input": {"item_type": item_type},
            "output": {"message": item.get("message") or ""},
            "metadata": {},
        }

    return {
        "name": f"codex.{item_type}",
        "type": "span",
        "input": {"item_type": item_type},
        "output": truncate_json(item, max_json_chars),
        "metadata": {"item_type": item_type},
    }


def ingestion_event(event_type, timestamp, body):
    return {
        "id": secrets.token_hex(16),
        "timestamp": timestamp,
        "type": event_type,
        "body": body,
    }


class TraceBuilder:
    """Share trace identity, metadata and observation encoding across both log formats."""

    def __init__(self, args, *, name, session_id, timestamp, input, output, metadata, tags):
        self.args = args
        self.id = secrets.token_hex(16)
        self.metadata = metadata
        self.batch = [
            ingestion_event(
                "trace-create",
                timestamp,
                {
                    "id": self.id,
                    "timestamp": timestamp,
                    "name": name,
                    "input": input,
                    "output": output,
                    "sessionId": session_id,
                    "environment": args.environment,
                    "metadata": metadata,
                    "tags": tags,
                },
            )
        ]

    def observation(self, name, input, output, *, start, end, type="span", metadata=None, **fields):
        body = {
            "id": secrets.token_hex(16),
            "traceId": self.id,
            "name": name,
            "startTime": start,
            "endTime": end,
            "input": input,
            "output": output,
            "environment": self.args.environment,
            "metadata": {
                **self.metadata,
                **{
                    key: value for key, value in (metadata or {}).items() if value not in (None, "")
                },
            },
            **fields,
        }
        if type == "generation":
            body["model"] = self.args.model
        self.batch.append(ingestion_event(f"{type}-create", start, body))
        return body["id"]


def build_ingestion_payload(args, input_text, output_text, events):
    now = time.time_ns()
    turn_status, turn_payload = latest_turn_result(events)
    trace_output = find_final_message(events, output_text) or json_attr(
        {"turn_status": turn_status}
    )
    metadata = {**main_trace_metadata(args), "codex_jsonl": True}
    # A delivery verdict does not replace the model turn's actual failure/usage.
    for event_type, key in (
        ("review.completed", "review_completion"),
        ("review.superseded", "review_superseded"),
    ):
        outcome = next(
            (event for event in reversed(events) if event.get("type") == event_type), None
        )
        if outcome is not None:
            metadata[key] = {
                key: value for key, value in outcome.items() if key not in ("type", "_line_number")
            }

    completed_items = [event for event in events if event["type"] == "item.completed"]
    agent_inputs = build_agent_message_inputs(
        events, input_text, args.max_json_chars, args.max_context_json_chars
    )
    timestamp = iso_from_ns(now)
    trace = TraceBuilder(
        args,
        name=args.trace_name,
        session_id=args.session_id,
        timestamp=timestamp,
        input=input_text,
        output=trace_output,
        metadata=metadata,
        tags=["doris-ai-review", "codex-jsonl"],
    )
    root = trace.observation(
        "codex.review",
        {"prompt": input_text},
        {"final_message": trace_output, "turn_status": turn_status},
        start=timestamp,
        end=iso_from_ns(now + (len(completed_items) + 3) * 1_000_000),
        metadata={
            "codex_event_count": len(events),
            "codex_completed_item_count": len(completed_items),
        },
    )
    if turn_status == "completed":
        turn_fields = {
            "usageDetails": {
                target: int(turn_payload.get(source) or 0)
                for target, source in (
                    ("input", "input_tokens"),
                    ("output", "output_tokens"),
                    ("cache_read_input_tokens", "cached_input_tokens"),
                    ("reasoning_output_tokens", "reasoning_output_tokens"),
                )
            }
        }
    else:
        turn_fields = {"statusMessage": truncate_text(json_attr(turn_payload), args.max_json_chars)}
    trace.observation(
        "codex.turn",
        {"prompt": input_text},
        {"status": turn_status, "final_message": trace_output},
        type="generation",
        start=iso_from_ns(now + 1_000_000),
        end=iso_from_ns(now + 2_000_000),
        metadata={"item_type": "turn"},
        parentObservationId=root,
        level="ERROR" if turn_status == "failed" else "DEFAULT",
        **turn_fields,
    )
    for offset, event in enumerate(completed_items, start=2):
        item = event["item"]
        shape = observation_shape(
            item, args.max_json_chars, agent_inputs.get(event.get("_line_number"))
        )
        shape["metadata"].update(
            item_id=item.get("id", ""),
            item_type=item.get("type", "unknown"),
            event_line=event.get("_line_number", 0),
        )
        start = now + offset * 1_000_000
        trace.observation(
            **shape,
            start=iso_from_ns(start),
            end=iso_from_ns(start + 750_000),
            parentObservationId=root,
            level="ERROR" if item.get("status") in ("failed", "declined") else "DEFAULT",
        )
    return trace.id, {"batch": trace.batch}, len(trace.batch) - 1


def main_trace_metadata(args):
    trace_metadata = {
        "repository": args.repository,
        "workflow": args.workflow,
        "run_id": args.run_id,
        "pr_number": args.pr_number,
        "head_sha": args.head_sha,
        "base_sha": args.base_sha,
        "model_reasoning_effort": args.reasoning_effort,
    }
    return {key: value for key, value in trace_metadata.items() if value not in (None, "")}


def receiver_thread_ids(events):
    thread_ids = set()
    for event in events:
        item = event.get("item") or {}
        if item.get("type") != "collab_tool_call":
            continue
        for thread_id in item.get("receiver_thread_ids") or []:
            if thread_id:
                thread_ids.add(str(thread_id))
    return thread_ids


def session_jsonl_files(root):
    if not root or not os.path.isdir(root):
        return []
    paths = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for filename in filenames:
            if filename.endswith(".jsonl"):
                paths.append(os.path.join(dirpath, filename))
    return sorted(paths)


def session_meta(events):
    for event in events:
        if event.get("type") != "session_meta":
            continue
        payload = event.get("payload")
        if isinstance(payload, dict):
            return payload
    return {}


def subagent_spawn(meta):
    source = meta.get("source")
    source = source if isinstance(source, dict) else {}
    subagent = source.get("subagent")
    subagent = subagent if isinstance(subagent, dict) else {}
    spawn = subagent.get("thread_spawn")
    return spawn if isinstance(spawn, dict) else {}


def is_subagent_meta(meta, expected_thread_ids):
    thread_id = str(meta.get("id") or "")
    if expected_thread_ids:
        return thread_id in expected_thread_ids
    if meta.get("thread_source") == "subagent":
        return True
    source = meta.get("source")
    return isinstance(source, dict) and bool(source.get("subagent"))


def compact_session_meta(meta, max_json_chars):
    compact = {}
    for key in (
        "id",
        "parent_thread_id",
        "timestamp",
        "cwd",
        "originator",
        "cli_version",
        "thread_source",
        "agent_nickname",
        "agent_role",
        "model_provider",
        "model",
    ):
        if meta.get(key) not in (None, ""):
            compact[key] = meta.get(key)
    for key in ("base_instructions", "user_instructions"):
        if key in meta:
            compact[f"{key}_present"] = True
    source = meta.get("source")
    if isinstance(source, dict):
        compact["source"] = truncate_json(source, max_json_chars)
    return compact


def session_content_text(content, max_chars):
    if isinstance(content, str):
        return truncate_text(content, max_chars)
    if not isinstance(content, list):
        return truncate_json(content, max_chars)
    parts = []
    for item in content:
        if isinstance(item, str):
            parts.append(item)
            continue
        if not isinstance(item, dict):
            parts.append(json_attr(item))
            continue
        for key in ("text", "input_text", "output_text"):
            if isinstance(item.get(key), str):
                parts.append(item[key])
                break
        else:
            parts.append(json_attr(item))
    return truncate_text("\n".join(parts), max_chars)


def session_first_user_message(events, max_chars):
    for event in events:
        if event.get("type") != "response_item":
            continue
        payload = event.get("payload") or {}
        if payload.get("type") == "message" and payload.get("role") == "user":
            text = session_content_text(payload.get("content"), max_chars)
            if isinstance(text, str) and text.strip():
                return text
    return ""


def session_final_assistant_message(events, max_chars):
    for event in reversed(events):
        payload = event.get("payload") or {}
        if event.get("type") == "response_item":
            if payload.get("type") == "message" and payload.get("role") == "assistant":
                text = session_content_text(payload.get("content"), max_chars)
                if isinstance(text, str) and text.strip():
                    return text
        elif event.get("type") == "event_msg" and payload.get("type") == "agent_message":
            text = payload.get("message") or ""
            if text.strip():
                return truncate_text(text, max_chars)
    return ""


def safe_name_component(value):
    text = str(value or "unknown")
    safe = "".join(char if char.isalnum() or char in "._-" else "_" for char in text).strip("._-")
    return safe[:120] or "unknown"


def jsonish(value):
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def session_call_outputs(events):
    outputs = {}
    for event in events:
        payload = event.get("payload") or {}
        if payload.get("type") != "function_call_output":
            continue
        call_id = payload.get("call_id")
        if call_id and call_id not in outputs:
            outputs[call_id] = (payload, event)
    return outputs


def session_event_timestamp(event, fallback_ns):
    timestamp = event.get("timestamp")
    if isinstance(timestamp, str) and timestamp:
        return timestamp
    return iso_from_ns(fallback_ns)


def session_observation_shape(event, call_outputs, max_json_chars):
    event_type = event.get("type") or "unknown"
    payload = event.get("payload") or {}

    if event_type == "session_meta":
        compact_meta = compact_session_meta(payload, max_json_chars)
        return {
            "name": "codex.subagent.session_meta",
            "type": "span",
            "input": compact_meta,
            "output": {
                "thread_source": compact_meta.get("thread_source"),
                "status": "recorded",
            },
            "metadata": {"session_event_type": event_type},
        }

    if event_type == "turn_context":
        return {
            "name": "codex.subagent.turn_context",
            "type": "span",
            "input": truncate_json(payload, max_json_chars),
            "output": {"status": "recorded"},
            "metadata": {"session_event_type": event_type},
        }

    if event_type == "event_msg":
        message_type = payload.get("type") or "unknown"
        message = payload.get("message") or ""
        body = {
            key: value
            for key, value in payload.items()
            if key not in ("message", "text_elements", "images", "local_images")
        }
        if payload.get("text_elements"):
            body["text_elements"] = truncate_json(payload.get("text_elements"), max_json_chars)
        if payload.get("images"):
            body["images"] = truncate_json(payload.get("images"), max_json_chars)
        return {
            "name": f"codex.subagent.event.{safe_name_component(message_type)}",
            "type": "generation" if message_type == "agent_message" else "span",
            "input": {
                "session_event_type": event_type,
                "message_type": message_type,
                "payload": truncate_json(body, max_json_chars),
            },
            "output": {
                "message": truncate_text(message, max_json_chars),
                "status": "recorded",
            },
            "metadata": {
                "session_event_type": event_type,
                "message_type": message_type,
            },
        }

    if event_type != "response_item":
        return {
            "name": f"codex.subagent.{safe_name_component(event_type)}",
            "type": "span",
            "input": {"session_event_type": event_type},
            "output": truncate_json(payload, max_json_chars),
            "metadata": {"session_event_type": event_type},
        }

    item_type = payload.get("type") or "unknown"
    if item_type == "message":
        role = payload.get("role") or "unknown"
        text = session_content_text(payload.get("content"), max_json_chars)
        is_assistant = role == "assistant"
        return {
            "name": f"codex.subagent.message.{safe_name_component(role)}",
            "type": "generation" if is_assistant else "span",
            "input": {
                "session_event_type": event_type,
                "item_type": item_type,
                "role": role,
                "phase": payload.get("phase"),
                **({} if is_assistant else {"content": text}),
            },
            "output": ({"text": text} if is_assistant else {"status": "recorded", "role": role}),
            "metadata": {
                "session_event_type": event_type,
                "item_type": item_type,
                "role": role,
                "phase": payload.get("phase"),
            },
        }

    if item_type == "function_call":
        call_id = payload.get("call_id")
        output_payload, output_event = call_outputs.get(call_id, ({}, {}))
        return {
            "name": f"codex.subagent.tool.{safe_name_component(payload.get('name'))}",
            "type": "span",
            "input": {
                "name": payload.get("name"),
                "call_id": call_id,
                "arguments": truncate_json(jsonish(payload.get("arguments")), max_json_chars),
            },
            "output": {
                "call_id": call_id,
                "output": truncate_json(jsonish(output_payload.get("output")), max_json_chars),
                "status": "completed" if output_payload else "unknown",
            },
            "metadata": {
                "session_event_type": event_type,
                "item_type": item_type,
                "tool_name": payload.get("name"),
                "call_id": call_id,
                "output_line": output_event.get("_line_number"),
            },
        }

    if item_type == "function_call_output":
        return {
            "name": "codex.subagent.tool_output",
            "type": "span",
            "input": {"call_id": payload.get("call_id")},
            "output": truncate_json(jsonish(payload.get("output")), max_json_chars),
            "metadata": {
                "session_event_type": event_type,
                "item_type": item_type,
                "call_id": payload.get("call_id"),
            },
        }

    if item_type == "reasoning":
        encrypted_content_present = bool(payload.get("encrypted_content"))
        return {
            "name": "codex.subagent.reasoning",
            "type": "span",
            "input": {
                "session_event_type": event_type,
                "item_type": item_type,
                "encrypted_content_present": encrypted_content_present,
            },
            "output": {
                "summary": truncate_json(payload.get("summary"), max_json_chars),
                "encrypted_content_present": encrypted_content_present,
                "status": "recorded",
            },
            "metadata": {"session_event_type": event_type, "item_type": item_type},
        }

    return {
        "name": f"codex.subagent.response_item.{safe_name_component(item_type)}",
        "type": "span",
        "input": {"session_event_type": event_type, "item_type": item_type},
        "output": truncate_json(payload, max_json_chars),
        "metadata": {"session_event_type": event_type, "item_type": item_type},
    }


def build_subagent_session_payload(args, session_path, session_events):
    now = time.time_ns()
    meta = session_meta(session_events)
    spawn = subagent_spawn(meta)
    thread_id = str(meta.get("id") or os.path.basename(session_path))
    trace_input = session_first_user_message(session_events, args.max_input_chars) or json_attr(
        compact_session_meta(meta, args.max_json_chars)
    )
    trace_output = session_final_assistant_message(
        session_events, args.max_output_chars
    ) or json_attr({"session_status": "recorded"})
    metadata = {
        **main_trace_metadata(args),
        "codex_session_jsonl": True,
        "subagent_session": True,
        "main_session_id": args.session_id,
        "thread_id": thread_id,
        "parent_thread_id": spawn.get("parent_thread_id") or meta.get("parent_thread_id") or "",
        "agent_nickname": meta.get("agent_nickname") or spawn.get("agent_nickname") or "",
        "agent_role": meta.get("agent_role") or spawn.get("agent_role") or "",
        "session_file": session_path,
        "session_event_count": len(session_events),
    }
    metadata = {key: value for key, value in metadata.items() if value not in (None, "")}
    session_id = f"{args.session_id}:subagent:{thread_id}"
    timestamp = (
        session_event_timestamp(session_events[0], now) if session_events else iso_from_ns(now)
    )
    base_ns = ns_from_iso(timestamp) or now
    starts = [
        ns_from_iso(event.get("timestamp")) or base_ns + offset * 1_000_000
        for offset, event in enumerate(session_events, start=2)
    ]
    trace = TraceBuilder(
        args,
        name=args.subagent_trace_name,
        session_id=session_id,
        timestamp=timestamp,
        input=trace_input,
        output=trace_output,
        metadata=metadata,
        tags=["doris-ai-review-subagent", "codex-session-jsonl"],
    )
    root = trace.observation(
        "codex.subagent.review",
        {"prompt": trace_input},
        {"final_message": trace_output},
        start=timestamp,
        end=iso_from_ns(max(starts, default=base_ns) + 1_000_000),
    )
    call_outputs = session_call_outputs(session_events)
    function_call_ids = {
        event["payload"]["call_id"]
        for event in session_events
        if event["type"] == "response_item"
        and event["payload"].get("type") == "function_call"
        and event["payload"].get("call_id")
    }
    for offset, event in enumerate(session_events, start=2):
        payload = event.get("payload") or {}
        if (
            event["type"] == "response_item"
            and payload.get("type") == "function_call_output"
            and payload.get("call_id") in function_call_ids
        ):
            continue
        shape = session_observation_shape(event, call_outputs, args.max_json_chars)
        shape["metadata"].update(
            session_event_type=event["type"], session_line=event.get("_line_number")
        )
        start_time = session_event_timestamp(event, base_ns + offset * 1_000_000)
        trace.observation(
            **shape,
            start=start_time,
            end=iso_from_ns(starts[offset - 2] + 750_000),
            parentObservationId=root,
        )
    return {
        "trace_id": trace.id,
        "session_id": session_id,
        "thread_id": thread_id,
        "path": session_path,
        "event_count": len(session_events),
        "observation_count": len(trace.batch) - 1,
        "payload": {"batch": trace.batch},
    }


def build_subagent_session_payloads(args, main_events):
    expected_thread_ids = receiver_thread_ids(main_events)
    payloads = []
    for path in session_jsonl_files(args.subagent_sessions_dir):
        events = load_jsonl(path)
        meta = session_meta(events)
        if not is_subagent_meta(meta, expected_thread_ids):
            continue
        payloads.append(build_subagent_session_payload(args, path, events))
        if len(payloads) >= args.max_subagent_sessions:
            break
    return payloads
