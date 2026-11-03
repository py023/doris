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

"""TeamCity adapter. Can also be pasted into Python -> Custom script.

Prerequisites: trusted master checkout; Linux agents with Python 3.11+, git, gh,
rg, and ossutil 1.7.19. Configure Parameters as listed in settings.kts.
Pass review or sync and the business CLI flags in Script arguments.
No PR revision/path or script is accepted from the forwarded event.
"""

import base64
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile


def main():
    # FIXME: Set REVIEW_CONTROLLER_DIR to the independently checked-out master
    # directory (regression-test/pipeline/code-review); never the PR checkout.
    controller = Path(os.environ["REVIEW_CONTROLLER_DIR"]).resolve()
    mode, *arguments = sys.argv[1:]
    if mode not in {"review", "sync"}:
        raise ValueError("Expected review or sync")
    os.umask(0o077)

    def cancelled(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, cancelled)
    with tempfile.TemporaryDirectory(prefix="review-input-", dir=os.environ.get("REVIEW_TEMP_DIR")) as temporary:
        directory = Path(temporary)
        count = int(os.environ["REVIEW_EVENT_PARTS"])
        if not 0 < count <= 128:
            raise ValueError("Invalid number of event chunks")
        encoded = "".join(os.environ[f"REVIEW_EVENT_{index:04d}"] for index in range(count))
        event = json.loads(base64.b64decode(encoded, validate=True))
        event_path = directory / "event.json"
        event_path.write_text(json.dumps(event))
        sys.path.insert(0, str(controller / "lib"))
        from events import Event
        parsed = Event(os.environ["REVIEW_EVENT_NAME"], event)
        # A filtered event needs no service credentials. Canary uses OSS only.
        if mode == "review" and not (parsed.review or parsed.canary):
            return 0
        if mode == "sync" and not (parsed.local_pass or parsed.skip or parsed.status_heads):
            return 0
        arguments.extend(["--temp-dir", str(directory)])
        secrets = [] if parsed.canary else [("REVIEW_GITHUB_TOKEN", "--github-token-file")]
        if mode == "review":
            secrets += [("REVIEW_OSS_ACCESS_KEY", "--oss-access-key-file"),
                        ("REVIEW_OSS_SECRET_KEY", "--oss-secret-key-file")]
            for variable, flag in (("REVIEW_TELEMETRY_PUBLIC_KEY", "--telemetry-public-key-file"),
                                   ("REVIEW_TELEMETRY_SECRET_KEY", "--telemetry-secret-key-file")):
                if not parsed.canary and os.environ.get(variable):
                    secrets.append((variable, flag))
        for variable, flag in secrets:
            secret_path = directory / variable.lower()
            secret_path.write_text(os.environ.pop(variable))
            secret_path.chmod(0o600)
            arguments.extend([flag, str(secret_path)])
        # Unused canary credentials must not remain in Codex's environment.
        for variable in ("REVIEW_GITHUB_TOKEN", "REVIEW_TELEMETRY_PUBLIC_KEY", "REVIEW_TELEMETRY_SECRET_KEY"):
            os.environ.pop(variable, None)
        arguments.extend(["--event-file", str(event_path), "--event-name", os.environ["REVIEW_EVENT_NAME"],
                          "--request-id", os.environ["REVIEW_REQUEST_ID"],
                          "--run-id", os.environ["REVIEW_BUILD_ID"], "--run-url", os.environ["REVIEW_BUILD_URL"]])
        if mode == "review" and not parsed.canary:
            revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=controller, text=True).strip()
            arguments.extend(["--trusted-revision", revision])
        # Import from the trusted checkout so cancellation always unwinds the
        # worker's finalizers before this adapter deletes its secret files.
        from cli import main as worker
        return worker([mode, *arguments])


if __name__ == "__main__":
    sys.exit(main())
