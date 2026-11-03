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

"""GitHub API access through gh, with bounded retries and redacted failure diagnostics."""

import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from process import redact

LIMIT = 65536
ATTEMPTS = 3
# No HTTP status means a transport failure or timeout; with 429 and 5xx it is worth retrying.
TRANSIENT = {None, 429, 500, 502, 503, 504}
HEADERS = {
    "content-type", "content-length", "date", "x-github-request-id",
    "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining",
    "x-ratelimit-reset", "x-ratelimit-resource",
}


class ReviewSuperseded(Exception):
    """The review target moved on: a new head, a closed PR, or another run's review."""


def excerpt(value):
    value = redact(value)
    return value[:LIMIT] + ("\n[truncated]" if len(value) > LIMIT else "")


def split_trace(stderr):
    """Keep only the final HTTP exchange; discard every outgoing header/body.

    GH_DEBUG=api writes HTTP diagnostics to stderr, independently of gh api's
    response parser. Its body is a formatted, size-limited debug excerpt, not
    a byte-for-byte copy. Unknown debug formatting is discarded, never dumped.
    """
    text = stderr.decode("utf-8", errors="replace") if isinstance(stderr, bytes) else (stderr or "")
    response = {"method": None, "path": None, "status": None, "headers": {},
                "body_excerpt": "", "body_source": "gh_debug", "request_count": 0}
    ordinary, body, mode = [], [], "ordinary"
    for line in text.splitlines():
        if line.startswith("* Request at "):
            count = response["request_count"] + 1
            response.update(method=None, path=None, status=None, headers={}, request_count=count)
            body, mode = [], "request"
        elif line.startswith("> "):
            match = re.match(r"> ([A-Z]+) (\S+) HTTP/", line)
            if match:
                response["method"] = match[1]
                response["path"] = redact(urlsplit(match[2]).path)
            mode = "request"
        elif re.match(r"< HTTP/\S+ \d{3}", line):
            response["status"] = int(line.split()[2])
            response["headers"] = {}
            body, mode = [], "headers"
        elif mode == "headers" and line.startswith("< "):
            name, sep, value = line[2:].partition(":")
            if sep and name.lower() in HEADERS:
                response["headers"][name.lower()] = excerpt(value.strip())
        elif line.startswith("* Request took "):
            mode = "ordinary"
        elif mode == "headers" and not line:
            mode = "body"
        elif mode == "body":
            body.append(line)
        elif mode == "ordinary" and not line.startswith("* "):
            ordinary.append(line)
    # A transport failure has no response; never mistake request data for its body.
    content = "" if mode == "request" else "\n".join(body).strip()
    response.update(body_excerpt=excerpt(content), body_truncated=len(content) > LIMIT)
    return response, excerpt("\n".join(ordinary).strip())


def record_failure(error, stdout="", stderr="", *, diagnostic=None):
    """Persist one redacted failure record; argv is never recorded, as -f/--input can carry secrets."""
    response, ordinary = split_trace(stderr) if diagnostic is None else (diagnostic, excerpt(stderr))
    record = {
        "time": datetime.now(timezone.utc).isoformat(),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "job": os.environ.get("GITHUB_JOB"),
        "gh_version": os.environ.get("REVIEW_GH_VERSION"),
        "error_type": type(error).__name__,
        "returncode": getattr(error, "returncode", None),
        "timeout_seconds": getattr(error, "timeout", None),
        "http": response,
        "stderr": ordinary,
        "stdout_excerpt": excerpt(stdout),
    }
    record["summary"] = redact(
        f"GitHub request failed: {response['method'] or 'unknown'} {response['path'] or 'unknown'}; "
        f"HTTP={response['status']}; request_id={response['headers'].get('x-github-request-id', 'unknown')}; "
        f"{record['error_type']}; exit={record['returncode']}; timeout={record['timeout_seconds']}")
    directory = os.environ.get("REVIEW_GITHUB_DIAGNOSTICS_DIR")
    if directory:
        try:
            path = Path(directory)
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Unique files support concurrent helper calls without append races.
            filename = path / f"{time.time_ns()}-{uuid.uuid4().hex}.json"
            with open(filename, "x", opener=lambda p, f: os.open(p, f, 0o600)) as handle:
                handle.write(json.dumps(record, ensure_ascii=True, indent=2) + "\n")
        except OSError as exc:
            print(f"Could not persist GitHub diagnostic ({type(exc).__name__})", file=sys.stderr)
    print(record["summary"], file=sys.stderr, flush=True)
    return ordinary, record


def request_json(path, *, payload=None, pages=False, env=None, timeout=None, retry=None):
    """Call gh api and parse its JSON response.

    Reads, and writes the caller marks idempotent with retry=True, retry transient failures.
    A raised CalledProcessError or TimeoutExpired carries the response status as http_status.
    """
    command = ["gh", "api", path] + (["--paginate", "--slurp"] if pages else [])
    if payload is not None:
        command += ["--method", "POST", "--input", "-"]
    environment = {**(os.environ if env is None else env), "GH_DEBUG": "api", "NO_COLOR": "1"}
    retry = payload is None if retry is None else retry
    for attempt in range(1, ATTEMPTS + 1):
        try:
            result = subprocess.run(command, env=environment, timeout=timeout, text=True, check=True,
                                    capture_output=True, input=None if payload is None else json.dumps(payload))
            break
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            ordinary, record = record_failure(error, error.stdout, error.stderr)
            error.http_status = record["http"]["status"]
            if retry and attempt < ATTEMPTS and error.http_status in TRANSIENT:
                time.sleep(2 ** attempt)
                continue
            error.stderr = ordinary + "\n" + record["summary"]
            raise
        except OSError as error:
            record_failure(error)
            raise
    response, ordinary = split_trace(result.stderr)
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        record_failure(error, result.stdout, ordinary, diagnostic=response)
        raise
    return [item for page in data for item in page] if pages else data


class GitHub:
    """Repository-scoped API; with a deadline, every call fits the remaining shared budget."""

    def __init__(self, repository, *, env=None, timeout=None, deadline=None):
        self.repository, self.env, self.timeout, self.deadline = repository, env, timeout, deadline

    def remaining(self):
        if self.deadline is None:
            return self.timeout
        seconds = self.deadline - time.monotonic()
        if seconds <= 0:
            raise TimeoutError("Review's shared time budget was exhausted")
        return seconds if self.timeout is None else min(self.timeout, seconds)

    def api(self, path, *, payload=None, pages=False, retry=None):
        return request_json(f"repos/{self.repository}/{path}", payload=payload, pages=pages,
                            env=self.env, timeout=self.remaining(), retry=retry)

    def pull(self, number):
        return self.api(f"pulls/{number}")

    def require_target(self, number, head, base=None):
        """Return the PR, or stop when it closed, moved to a new head, or (if given) changed base."""
        pr = self.pull(number)
        if pr["state"] != "open":
            raise ReviewSuperseded(f"PR #{number} is no longer open; stopping its review")
        if pr["head"]["sha"] != head:
            raise ReviewSuperseded(f"PR head changed to {pr['head']['sha']}; stopping superseded review")
        if base is not None and pr["base"]["sha"] != base:
            raise ValueError("PR base changed; refusing a stale review")
        return pr

    def status(self, head, context, state, description, url):
        # Re-posting the same commit status is harmless, so status writes retry.
        return self.api(f"statuses/{head}", retry=True, payload={
            "context": context, "state": state, "description": description, "target_url": url,
        })

    def comment(self, number, body):
        return self.api(f"issues/{number}/comments", payload={"body": body})
