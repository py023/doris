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

"""The original five ordered, fail-fast runtime checks, without GitHub writes."""

import logging

from process import environment, step
from run_review_with_resume import read_events, run_attempt


def run_canary(options, runtime, workspace):
    with step("Runtime canary", options.canary_job_timeout):
        env = runtime.install(workspace, canary=True)
        snapshot = runtime.auth.acquire(workspace, source=options.canary_auth_object)
        runtime.configure(workspace, canary=True)
        try:
            with environment(env, remove=("GH_TOKEN", "GITHUB_TOKEN")):
                with step("Test ChatGPT model access and goal mode", options.canary_step_timeout):
                    for case in options.canary_case:
                        label, model, effort, mode = case.split(":")
                        if mode not in {"plain", "goal"}:
                            raise ValueError("Canary case must be LABEL:MODEL:EFFORT:plain|goal")
                        prefix = workspace.path / f"codex-canary-{label}"
                        events, stderr, output = (prefix.with_suffix(suffix)
                                                  for suffix in (".jsonl", ".stderr", ".txt"))
                        command = ["timeout", "--signal=INT", "--kill-after=10s", str(options.canary_timeout),
                                   "codex", "exec", "--skip-git-repo-check", "--json", "--model", model,
                                   "--config", f"model_reasoning_effort={effort}", "--sandbox", "read-only",
                                   "--color", "never", "--output-last-message", str(output)]
                        if mode == "goal":
                            command.append("--goal")
                        command.append(("Create a goal to reply OK, mark it complete, then reply OK. "
                                        if mode == "goal" else "Reply with exactly OK. ")
                                       + "Do not access files or external services.")
                        code = run_attempt(command, events, stderr, None, reaper=workspace.reaper)
                        logging.info("%s: exit_status=%s", label, code)
                        if code or not any(e.get("type") == "turn.completed" for e in read_events(events)):
                            return 1
        finally:
            # Unlike normal Review, concurrent changes fail the canary job.
            snapshot.sync(canary=True)
    return 0
