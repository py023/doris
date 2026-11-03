#!/usr/bin/env python3
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

"""Export Codex review traces and optionally verify their persisted I/O."""

import argparse
import json
import os

from telemetry_common import load_jsonl, read_text
from telemetry_events import build_ingestion_payload, build_subagent_session_payloads
from telemetry_otlp import otlp_chunks, post_payload
from telemetry_readback import trace_verification_target, verify_traces


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="https://litefuse.cloud")
    parser.add_argument("--endpoint", default=None)
    parser.add_argument("--input-file", required=True)
    parser.add_argument("--events-file", required=True)
    parser.add_argument("--output-file", default="")
    parser.add_argument("--trace-name", default="doris-ai-review")
    parser.add_argument("--subagent-trace-name", default="doris-ai-review-subagent")
    parser.add_argument("--subagent-sessions-dir", default="")
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--repository", default="")
    parser.add_argument("--workflow", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--pr-number", default="")
    parser.add_argument("--head-sha", default="")
    parser.add_argument("--base-sha", default="")
    parser.add_argument("--model", default="gpt-5.6-sol")
    parser.add_argument("--reasoning-effort", default="")
    parser.add_argument("--environment", default="github-actions")
    parser.add_argument("--max-input-chars", type=int, default=200_000)
    parser.add_argument("--max-output-chars", type=int, default=200_000)
    parser.add_argument("--max-json-chars", type=int, default=40_000)
    parser.add_argument("--max-context-json-chars", type=int, default=0)
    parser.add_argument("--max-payload-bytes", type=int, default=4_000_000)
    parser.add_argument("--max-subagent-sessions", type=int, default=100)
    parser.add_argument("--post-timeout-seconds", type=int, default=120)
    parser.add_argument("--post-retry-attempts", type=int, default=5)
    parser.add_argument("--post-retry-sleep-seconds", type=int, default=5)
    parser.add_argument(
        "--gzip",
        action="store_true",
        help="Gzip OTLP uploads; payload size limits still apply before compression",
    )
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verify-attempts", type=int, default=24)
    parser.add_argument("--verify-sleep-seconds", type=int, default=5)
    parser.add_argument(
        "--verify-timeout-seconds",
        type=int,
        default=120,
        help="Shared elapsed-time budget for reading back all exported traces",
    )
    parser.add_argument("--min-observations", type=int, default=3)
    parser.add_argument("--min-step-observations", type=int, default=1)
    return parser.parse_args()


def export_payload(args, payload):
    if args.dry_run:
        sizes = [size for _, _, size in otlp_chunks(payload, args.max_payload_bytes)]
        return {
            "batch_count": len(payload["batch"]),
            "request_count": len(sizes),
            "request_sizes": sizes,
            "max_request_size": max(sizes),
        }
    return {
        "status": post_payload(
            args.endpoint or f"{args.base_url.rstrip('/')}/api/public/otel/v1/traces",
            os.environ["LANGFUSE_PUBLIC_KEY"],
            os.environ["LANGFUSE_SECRET_KEY"],
            payload,
            args.max_payload_bytes,
            args.post_timeout_seconds,
            args.post_retry_attempts,
            args.post_retry_sleep_seconds,
            gzip_enabled=args.gzip,
        )
    }


def main():
    args = parse_args()
    if args.max_context_json_chars <= 0:
        args.max_context_json_chars = args.max_json_chars

    input_text = read_text(args.input_file, args.max_input_chars)
    output_text = (
        read_text(args.output_file, args.max_output_chars, tail=True, optional=True)
        if args.output_file
        else ""
    )
    events = load_jsonl(args.events_file)
    trace_id, payload, observation_count = build_ingestion_payload(
        args, input_text, output_text, events
    )
    subagent_payloads = (
        build_subagent_session_payloads(args, events) if args.subagent_sessions_dir else []
    )

    result = {
        "dry_run": args.dry_run,
        "event_count": len(events),
        "observation_count": observation_count,
        "trace_id": trace_id,
        "session_id": args.session_id,
        "trace_name": args.trace_name,
        "subagent_trace_count": len(subagent_payloads),
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        **export_payload(args, payload),
    }
    result["subagent_traces"] = [
        {
            **{key: value for key, value in child.items() if key != "payload"},
            **export_payload(args, child["payload"]),
        }
        for child in subagent_payloads
    ]
    if args.dry_run:
        result["event_types"] = [event["type"] for event in payload["batch"][:10]]

    if args.verify and not args.dry_run:
        targets = [trace_verification_target(result, payload)]
        targets.extend(
            trace_verification_target(subagent_result, subagent_payload["payload"], subagent=True)
            for subagent_result, subagent_payload in zip(
                result["subagent_traces"], subagent_payloads
            )
        )
        try:
            verify_traces(
                args, os.environ["LANGFUSE_PUBLIC_KEY"], os.environ["LANGFUSE_SECRET_KEY"], targets
            )
        except Exception as exc:
            result["verification_error"] = str(exc)
            print(json.dumps(result, sort_keys=True))
            raise
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
