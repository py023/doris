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

"""JSON and timestamp helpers shared by telemetry encoding and transport."""

from datetime import datetime, timezone
import json


def read_text(path, max_chars, tail=False, optional=False):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            data = handle.read()
    except FileNotFoundError:
        if optional:
            return ""
        raise
    return truncate_text(data, max_chars, tail)


def truncate_text(data, max_chars, tail=False):
    if max_chars <= 0 or len(data) <= max_chars:
        return data
    if tail:
        return f"[truncated to last {max_chars} chars]\n" + data[-max_chars:]
    return data[:max_chars] + f"\n[truncated to first {max_chars} chars]"


def truncate_json(value, max_chars):
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if max_chars <= 0 or len(text) <= max_chars:
        return value
    return {"truncated_json": truncate_text(text, max_chars)}


def json_attr(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def json_payload_bytes(value):
    return len(compact_json_bytes(value))


def load_jsonl(path):
    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                event = json.loads(stripped)
            except json.JSONDecodeError as exc:
                events.append(
                    {
                        "type": "error",
                        "message": f"invalid jsonl line {line_number}: {exc}",
                    }
                )
                continue
            event["_line_number"] = line_number
            events.append(event)
    return events


def iso_from_ns(ns):
    return (
        datetime.fromtimestamp(ns / 1_000_000_000, timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def ns_from_iso(timestamp):
    if not isinstance(timestamp, str) or not timestamp:
        return None
    try:
        normalized = timestamp.replace("Z", "+00:00")
        return int(datetime.fromisoformat(normalized).timestamp() * 1_000_000_000)
    except ValueError:
        return None


def compact_json_bytes(payload):
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
