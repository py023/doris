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

"""Interpret terminal Codex failures, never arbitrary tool-result text."""

import re
from dataclasses import dataclass
from datetime import datetime, timezone


AUTH_FAILURES = {
    "refresh_token_reused": "Your access token could not be refreshed because your refresh token was already used.",
    "refresh_token_invalidated": "Your session has ended. Please log in again.",
}


@dataclass(frozen=True)
class Failure:
    message: str
    invalid_auth: str = ""
    retry_after: int | None = None


def interpret(events, stderr, exit_code, *, now, usage_limit_backoff):
    terminal = [event for event in events if event.get("type") in {"turn.failed", "error"}]
    failed = [event for event in terminal if event["type"] == "turn.failed"]

    def last_line(messages):
        # Match jq -r ... | tail -n 1, including a final empty message.
        output = "".join(message + "\n" for message in messages if message is not None)
        return output.split("\n")[-2] if output else ""

    reason = last_line((event.get("error") or {}).get("message") for event in failed)
    if not reason:
        reason = last_line(event["message"] if event.get("message") is not None
                           else (event.get("error") or {}).get("message")
                           for event in terminal if event["type"] == "error")
    lines = [line for line in stderr.splitlines() if line.strip()]
    reason = reason or (lines[-1] if lines else f"Codex exited with status {exit_code}")
    codes = {(event.get("error") or {}).get("code") or event.get("code") for event in terminal}
    invalid = ""
    for code, text in AUTH_FAILURES.items():
        stderr_code = re.search(r'"code"\s*:\s*"' + re.escape(code) + r'"', stderr)
        refresh_log = re.search(r'ERROR codex_login::auth(?:::manager)?: Failed to refresh token '
                                r'.*error_code: Some\("' + re.escape(code) + r'"\)', stderr)
        if text.casefold() in reason.casefold() or reason == code or code in codes or stderr_code or refresh_log:
            invalid = code
            break
    retry_after = None
    if "you've hit your usage limit" in reason.casefold():
        match = re.search(r"[Tt]ry again at ((?:[A-Za-z]{3} \d{1,2}(?:st|nd|rd|th)?, \d{4} )?"
                          r"\d{1,2}:\d{2} (?:AM|PM))", reason)
        if match:
            value = re.sub(r"(\d)(?:st|nd|rd|th),", r"\1,", match[1])
            try:
                if "," in value:
                    parsed = datetime.strptime(value, "%b %d, %Y %I:%M %p").replace(tzinfo=timezone.utc)
                else:
                    parsed_time = datetime.strptime(value, "%I:%M %p")
                    parsed = datetime.fromtimestamp(now, timezone.utc).replace(
                        hour=parsed_time.hour, minute=parsed_time.minute, second=0, microsecond=0)
                retry_after = int(parsed.timestamp())
            except ValueError:
                pass
        if retry_after is None or retry_after <= now:
            retry_after = int(now + usage_limit_backoff)
    return Failure(reason, invalid, retry_after)
