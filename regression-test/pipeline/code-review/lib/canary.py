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

"""Probe model access and goal mode using the original GitHub Actions policy."""

import logging

from process import environment, step
from run_review_with_resume import read_events, run_attempt

logger = logging.getLogger(__name__)


def run_canary(options, runtime, workspace):
    def run_model(label, model, *, goal=False, effort="low"):
        prefix = workspace.path / f"codex-canary-{label}"
        events, stderr, output = (prefix.with_suffix(suffix) for suffix in (".jsonl", ".stderr", ".txt"))
        command = ["timeout", "--signal=INT", "--kill-after=10s", str(options.canary_timeout),
                   "codex", "exec", "--skip-git-repo-check", "--json", "--model", model,
                   "--config", f"model_reasoning_effort={effort}", "--sandbox", "read-only",
                   "--color", "never", "--output-last-message", str(output)]
        if goal:
            command.append("--goal")
        command.append(("Create a goal to reply OK, mark it complete, then reply OK. "
                        if goal else "Reply with exactly OK. ")
                       + "Do not access files or external services.")
        code = run_attempt(command, events, stderr, None, reaper=workspace.reaper)
        logger.info("%s: exit_status=%s", label, code)
        return code == 0 and any(e.get("type") == "turn.completed" for e in read_events(events))

    with step("Runtime canary", options.canary_job_timeout):
        env = runtime.install(workspace, canary=True)
        snapshot = runtime.auth.acquire(workspace, source=options.canary_auth_object)
        runtime.configure(workspace, canary=True)
        try:
            with (
                environment(env, remove=("GH_TOKEN", "GITHUB_TOKEN")),
                step("Test ChatGPT model access and goal mode", options.canary_step_timeout),
            ):
                sol = run_model("sol", "gpt-6-sol")
                # The previous model is informational, not a required check.
                prior = run_model("prior-sol", "gpt-5.6-sol")
                sol_goal = sol and run_model("sol-goal", "gpt-6-sol", goal=True)
                sol61 = run_model("sol61", "gpt-6.1-sol", effort="xhigh")
                sol61_goal = sol61 and run_model("sol61-goal", "gpt-6.1-sol", goal=True, effort="xhigh")
                logger.info("model_canary: gpt-6-sol=%s gpt-5.6-sol=%s gpt-6-sol-goal=%s "
                            "gpt-6.1-sol-xhigh=%s gpt-6.1-sol-xhigh-goal=%s",
                            int(not sol), int(not prior), int(not sol_goal),
                            int(not sol61), int(not sol61_goal))
        finally:
            # Unlike normal Review, concurrent changes fail the canary job.
            snapshot.sync(canary=True)
    return int(not (sol and sol_goal and sol61 and sol61_goal))
