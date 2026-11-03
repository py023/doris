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

#!/usr/bin/env python3
"""Resolve the SHA-wide code-review status from PR/base-specific sources."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path


SOURCE_CONTEXT_RE = re.compile(
    r"code-review/source/(?:automated|local|skip)/pr-(\d+)/base-([0-9a-fA-F]{40})"
)
SHA_RE = re.compile(r"[0-9a-fA-F]{40}")


class ResolutionError(ValueError):
    """The supplied GitHub API data cannot be resolved safely."""


@dataclass(frozen=True)
class Resolution:
    state: str
    description: str


def resolve_status(
    pulls: list[dict], statuses: list[dict], *, head_sha: str
) -> Resolution:
    if SHA_RE.fullmatch(head_sha) is None:
        raise ResolutionError("head SHA is not a full SHA")

    open_contexts: set[tuple[int, str]] = set()
    for item in pulls:
        if item["state"] != "open":
            continue
        if item["head"]["sha"].casefold() != head_sha.casefold():
            continue
        base_sha = item["base"]["sha"]
        if SHA_RE.fullmatch(base_sha) is None:
            raise ResolutionError("pull request base SHA is invalid")
        open_contexts.add((item["number"], base_sha.casefold()))

    if not open_contexts:
        return Resolution(
            "pending", f"No open pull request currently uses {head_sha[:12]}."
        )

    latest_by_context: dict[str, dict[str, object]] = {}
    for item in statuses:
        context = item["context"]
        previous = latest_by_context.get(context)
        if previous is None or item["id"] > previous["id"]:
            latest_by_context[context] = item

    approved_contexts: set[tuple[int, str]] = set()
    blocked_contexts: set[tuple[int, str]] = set()
    incomplete_contexts: set[tuple[int, str]] = set()
    for context, item in latest_by_context.items():
        match = SOURCE_CONTEXT_RE.fullmatch(context)
        if match is None:
            continue
        key = (int(match.group(1)), match.group(2).casefold())
        if item["state"] == "success":
            approved_contexts.add(key)
        elif item["state"] == "failure" and context.startswith("code-review/source/automated/"):
            blocked_contexts.add(key)
            # State remains the sole gating signal. Use the runner's description
            # only to explain an already-blocking result, never to grant a pass.
            if (item.get("description") or "").startswith("Review did not converge after "):
                incomplete_contexts.add(key)

    # Preserve the authorized local PASS / skip override. Otherwise a completed
    # automated review with P0/P1 or incomplete coverage blocks instead of pending.
    blocked = sorted((open_contexts - approved_contexts) & blocked_contexts)
    if blocked:
        number, base_sha = blocked[0]
        if (number, base_sha) in incomplete_contexts:
            return Resolution(
                "failure", f"Review did not converge for PR #{number} at {base_sha[:12]}.",
            )
        return Resolution(
            "failure", f"Review completed with P0/P1 for PR #{number} at {base_sha[:12]}.",
        )

    missing = sorted(open_contexts - approved_contexts)
    if missing:
        number, base_sha = missing[0]
        remaining = len(missing) - 1
        suffix = f" (+{remaining} more)" if remaining else ""
        return Resolution(
            "pending",
            f"Awaiting code review for PR #{number} at {base_sha[:12]}{suffix}.",
        )

    count = len(open_contexts)
    noun = "context" if count == 1 else "contexts"
    return Resolution(
        "success",
        f"Code review passed for {count} open PR {noun} on {head_sha[:12]}.",
    )


def load_list(path: Path, name: str) -> list[object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list):
        raise ResolutionError(f"{name} JSON must be an array")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pulls-file", type=Path, required=True)
    parser.add_argument("--statuses-file", type=Path, required=True)
    parser.add_argument("--head-sha", required=True)
    args = parser.parse_args()

    resolution = resolve_status(
        load_list(args.pulls_file, "pulls"),
        load_list(args.statuses_file, "statuses"),
        head_sha=args.head_sha,
    )
    print(f"state={resolution.state}")
    print(f"description={resolution.description}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
