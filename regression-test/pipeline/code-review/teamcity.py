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

"""TeamCity entry point: `python3 teamcity.py review|sync`, as configured in settings.kts.

It runs from the build's agent-side checkout of master, decodes the event that
`main.py forward` queued, stages the env.REVIEW_* credentials as private files and
runs the worker. Agents need Linux, Python 3.11+, git and gh; review agents also
need rg and ossutil 1.7.19. No PR revision, path or script is accepted from the event.
"""

import base64
import json
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

CONTROLLER = Path(__file__).resolve().parent
# Credential variable -> (worker flag, the runs that use it). Telemetry keys are optional.
CREDENTIALS = {
    "REVIEW_GITHUB_TOKEN": ("--github-token-file", {"review", "sync"}),
    "REVIEW_OSS_ACCESS_KEY": ("--oss-access-key-file", {"review", "canary"}),
    "REVIEW_OSS_SECRET_KEY": ("--oss-secret-key-file", {"review", "canary"}),
    "REVIEW_TELEMETRY_PUBLIC_KEY": ("--telemetry-public-key-file", {"review"}),
    "REVIEW_TELEMETRY_SECRET_KEY": ("--telemetry-secret-key-file", {"review"}),
}
OPTIONAL = {"REVIEW_TELEMETRY_PUBLIC_KEY", "REVIEW_TELEMETRY_SECRET_KEY"}


def main():
    if sys.version_info < (3, 11):
        raise RuntimeError("The review controller requires Python 3.11 or newer")
    sys.path.insert(0, str(CONTROLLER))
    # Import the worker from this trusted checkout; running it in-process lets
    # cancellation unwind its finalizers before the credential files are deleted.
    from main import MAX_EVENT_PARTS, Event, cancel
    from main import main as worker
    mode, *arguments = sys.argv[1:]
    if mode not in {"review", "sync"}:
        raise ValueError("Expected review or sync")
    os.umask(0o077)
    signal.signal(signal.SIGTERM, cancel)
    # No credential stays in the environment that the worker and Codex inherit.
    credentials = {variable: os.environ.pop(variable, "") for variable in CREDENTIALS}
    count = int(os.environ["REVIEW_EVENT_PARTS"])
    if not 0 < count <= MAX_EVENT_PARTS:
        raise ValueError("Invalid number of event chunks; was this build queued by main.py forward?")
    encoded = "".join(os.environ[f"REVIEW_EVENT_{index:04d}"] for index in range(count))
    event = json.loads(base64.b64decode(encoded, validate=True))
    parsed = Event(os.environ["REVIEW_EVENT_NAME"], event)
    if not parsed.wanted(mode):
        return 0
    run = "canary" if parsed.canary else mode
    with tempfile.TemporaryDirectory(prefix="review-input-") as temporary:
        directory = Path(temporary)
        event_path = directory / "event.json"
        event_path.write_text(json.dumps(event))
        arguments += ["--temp-dir", str(directory), "--event-file", str(event_path),
                      "--event-name", os.environ["REVIEW_EVENT_NAME"], "--request-id", os.environ["REVIEW_REQUEST_ID"],
                      "--run-id", os.environ["REVIEW_BUILD_ID"], "--run-url", os.environ["REVIEW_BUILD_URL"]]
        for variable, (flag, runs) in CREDENTIALS.items():
            if run not in runs or (variable in OPTIONAL and not credentials[variable]):
                continue
            path = directory / variable.lower()  # An empty required credential is rejected by the worker.
            path.write_text(credentials[variable])
            path.chmod(0o600)
            arguments += [flag, str(path)]
        if run == "review":
            revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=CONTROLLER, text=True).strip()
            arguments += ["--trusted-revision", revision]
        return worker([mode, *arguments])


if __name__ == "__main__":
    sys.exit(main())
