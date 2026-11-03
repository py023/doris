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

LIMIT = 65536


SECRET_FIELD = (r"(?:access_token|refresh_token|id_token|token|api_key|secret|"
                r"client_secret|password|authorization|cookie|set-cookie)")


HEADERS = {
    "content-type", "content-length", "date", "x-github-request-id",
    "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining",
    "x-ratelimit-reset", "x-ratelimit-resource",
}


def redact(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    value = value or ""
    # Artifacts do not inherit Actions' secret masker. Never store the request
    # headers or body; also redact credentials echoed by an error response.
    for name, secret in os.environ.items():
        if re.search(r"(?:TOKEN|SECRET|PASSWORD|(?:^|_)KEY|(?:^|_)AK|(?:^|_)SK)$", name) and secret:
            for encoded in (secret, json.dumps(secret)[1:-1]):
                value = value.replace(encoded, "[REDACTED]")
    value = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+)\b", "[REDACTED]", value)
    value = re.sub(
        r'(?i)(["\']?' + SECRET_FIELD + r'["\']?\s*[:=]\s*)'
        r'("(?:\\.|[^"\\])*"|[^\r\n,}]+)', r'\1"[REDACTED]"', value,
    )
    value = re.sub(r"(https?://)[^/\s:@]+:[^/@\s]+@", r"\1[REDACTED]@", value)
    value = re.sub(r"(?i)([?&](?:token|access_token|signature|sig|key)=)[^&\s\"']+", r"\1[REDACTED]", value)
    return value


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
    ordinary = []
    mode = "ordinary"
    body = []
    for line in text.splitlines():
        if line.startswith("* Request at "):
            count = response["request_count"] + 1
            response = {**response, "method": None, "path": None, "status": None,
                        "headers": {}, "body_excerpt": "", "request_count": count}
            body = []
            mode = "request"
        elif line.startswith("> "):
            match = re.match(r"> ([A-Z]+) (\S+) HTTP/", line)
            if match:
                response["method"] = match[1]
                response["path"] = redact(urlsplit(match[2]).path)
            mode = "request"
        elif re.match(r"< HTTP/\S+ \d{3}", line):
            response["status"] = int(line.split()[2])
            response["headers"] = {}
            body = []
            mode = "headers"
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
    response["body_excerpt"] = excerpt("\n".join(body).strip())
    response["body_truncated"] = len("\n".join(body).strip()) > LIMIT
    if mode == "request":
        # A transport failure has no response; do not mistake request data for
        # its body. subprocess timeout/type still identifies the failure.
        response["body_excerpt"] = ""
    return response, excerpt("\n".join(ordinary).strip())


def record_failure(command, error, stdout="", stderr="", *, diagnostic=None):
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
    # Do not record argv: -f/--body/--input can contain credentials or entire
    # reviews. Endpoint metadata comes only from the outgoing request line.
    summary = (
        f"GitHub request failed: {response['method'] or 'unknown'} {response['path'] or 'unknown'}; "
        f"HTTP={response['status']}; request_id={response['headers'].get('x-github-request-id', 'unknown')}; "
        f"{record['error_type']}; exit={record['returncode']}; timeout={record['timeout_seconds']}"
    )
    record["summary"] = redact(summary)
    directory = os.environ.get("REVIEW_GITHUB_DIAGNOSTICS_DIR")
    if directory:
        try:
            path = Path(directory)
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            data = json.dumps(record, ensure_ascii=True, indent=2) + "\n"
            # Unique files support concurrent helper calls without append races.
            filename = path / f"{time.time_ns()}-{uuid.uuid4().hex}.json"
            with open(filename, "x", opener=lambda p, f: os.open(p, f, 0o600)) as handle:
                handle.write(data)
        except OSError as exc:
            print(f"Could not persist GitHub diagnostic ({type(exc).__name__})", file=sys.stderr)
    print(record["summary"], file=sys.stderr, flush=True)
    return ordinary, record


def request_json(path, *, payload=None, pages=False, env=None, timeout=None):
    command = ["gh", "api", path]
    if pages:
        command += ["--paginate", "--slurp"]
    if payload is not None:
        command += ["--method", "POST", "--input", "-"]
    environment = {**(os.environ if env is None else env), "GH_DEBUG": "api", "NO_COLOR": "1"}
    try:
        result = subprocess.run(command, env=environment, timeout=timeout, text=True, check=True,
                                capture_output=True, input=None if payload is None else json.dumps(payload))
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        ordinary, record = record_failure(command, error, error.stdout, error.stderr)
        error.stderr = ordinary + "\n" + record["summary"]
        raise
    except OSError as error:
        record_failure(command, error)
        raise
    response, ordinary = split_trace(result.stderr)
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        record_failure(command, error, result.stdout, ordinary, diagnostic=response)
        raise
    return [item for page in data for item in page] if pages else data


class GitHub:
    def __init__(self, repository, *, env, timeout):
        self.repository = repository
        self.env = env
        self.timeout = timeout

    def api(self, path, *, payload=None, pages=False):
        return request_json(f"repos/{self.repository}/{path}", payload=payload, pages=pages,
                            env=self.env, timeout=self.timeout)

    def pull(self, number):
        return self.api(f"pulls/{number}")

    def status(self, head, context, state, description, url):
        return self.api(f"statuses/{head}", payload={
            "context": context, "state": state,
            "description": description, "target_url": url,
        })

    def comment(self, number, body):
        return self.api(f"issues/{number}/comments", payload={"body": body})
