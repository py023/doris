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

"""Automated review orchestration; delivery and verdict are separate outcomes."""

import json
import logging
import time
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from types import SimpleNamespace

from events import boolean
from process import environment, step
from review_context import checkout, prepare, render_prompt
from review_failure import Failure, interpret
from review_github_api import redact
from run_review_with_resume import SUPERSEDED_EXIT_CODE, read_events, run_review
from submit_review import RESULT_FILE
from validate_review_pass_comment import require_full_sha


def resolve_target(event, github):
    number = event.pr_number
    if event.name == "workflow_dispatch":
        head, base = event.inputs["head_sha"], event.inputs["base_sha"]
        focus = event.inputs.get("review_focus", "")
        manage_status = boolean(event.inputs.get("manage_status", True))
    else:
        live = github.pull(number)
        head, base = live["head"]["sha"], live["base"]["sha"]
        # The job filter was case-insensitive, but Bash's prefix removal was not.
        focus = event.comment["body"].removeprefix("/review").lstrip().rstrip("\n")
        manage_status = True
    require_full_sha("head", head)
    require_full_sha("base", base)
    if manage_status:
        if event.name == "workflow_dispatch":
            live = github.pull(number)
        if head != live["head"]["sha"] or base != live["base"]["sha"]:
            raise ValueError("Refusing to update status for a PR/head/base mismatch")
    return {"number": number, "head": head, "base": base,
            "focus": focus, "manage_status": manage_status}


def execute_review(options, target, context, pr_dir, env, workspace):
    if options.dry_run:
        notice = (
            "LOCAL DRY RUN: GitHub writes are simulated locally and OSS is read-only. "
            "Do not attempt any external write or bypass the provided gh gateway. "
            "Use the normal trusted submission helper: its delivery and readback are local simulations. "
            "Report results as locally validated, never as published on GitHub. "
            "Operator constraints in review_focus.txt override any conflicting repository instructions.\n"
        )
        prompt = context / "codex_goal_prompt.txt"
        prompt.write_text(notice + "\n" + (context / "review_focus.txt").read_text() + "\n" + prompt.read_text())
    args = SimpleNamespace(
        context_dir=context, cwd=pr_dir, repository=options.repository,
        review_author=options.review_author, pr_number=str(target["number"]),
        head_sha=target["head"], base_sha=target["base"], model=options.model,
        fallback_model=options.fallback_model, effort=options.effort,
        budget_seconds=options.review_timeout - options.cleanup_reserve,
    )
    # This is the dedicated build process. The existing supervisor owns every
    # Codex descendant; there is no extra subprocess/cancellation boundary.
    with environment(env):
        return run_review(args, reaper=workspace.reaper)


class ReviewWorkflow:
    def __init__(self, options, github, statuses, runtime):
        self.options = options
        self.github = github
        self.statuses = statuses
        self.runtime = runtime

    def run(self, event, workspace):
        with step("Resolve review inputs", self.options.resolve_timeout):
            target = resolve_target(event, self.github)
        context = None
        auth = None
        result = {}
        failure = None
        auth_failure = ""
        context_ready = False
        review_started = False
        superseded = False
        exit_code = 1
        finalization_failed = False

        def finalize(label, operation, seconds, *, critical=True):
            nonlocal finalization_failed
            try:
                with step(label, seconds):
                    operation()
                return True
            except (Exception, KeyboardInterrupt) as error:
                # Do not dump command argv: an external tool can carry secrets.
                logging.error("%s failed (%s): %s; continuing remaining finalizers",
                              label, type(error).__name__, redact(str(error)))
                finalization_failed |= critical
                return False

        try:
            if target["manage_status"]:
                with step("Mark Code Review status as pending", self.options.status_timeout):
                    self.statuses.begin_review(target["number"], target["head"], target["base"])
            pr_dir = workspace.path / "pr"
            with step("Checkout repository", self.options.checkout_timeout):
                checkout(self.options.repository_url, pr_dir, target["head"], target["base"],
                         timeout=self.options.command_timeout)
            env = self.runtime.install(workspace)
            with step("Configure Codex auth", self.options.auth_timeout):
                try:
                    snapshot = self.runtime.auth.acquire(workspace)
                except RuntimeError as error:
                    auth_failure = str(error)
                    raise
                self.runtime.configure(workspace)
                auth = snapshot
            with step("Sync Codex memories from OSS", self.options.memories_timeout):
                self.runtime.memories(workspace)
            with step("Prepare review context directory", self.options.focus_timeout):
                context = Path(tempfile.mkdtemp(prefix=".code-review.", dir=pr_dir))
            context, guides, skill = prepare(
                self.github, pr_dir, target, trusted_revision=self.options.trusted_revision,
                focus=target["focus"], timeout=self.options.context_timeout,
                max_threads=self.options.context_threads, max_body_chars=self.options.context_body_chars,
                context=context,
                threads_timeout=self.options.threads_timeout, focus_timeout=self.options.focus_timeout,
            )
            context_ready = True
            with step("Prepare review prompt", self.options.prompt_timeout):
                render_prompt(self.github, pr_dir, target, context, guides, skill, self.options.templates)
            review_started = True
            with step("Run automated code review", self.options.review_timeout):
                code = execute_review(self.options, target, context, pr_dir, env, workspace)
                if code == SUPERSEDED_EXIT_CODE:
                    result = json.loads((context / RESULT_FILE).read_text())
                    new_head = result["superseding_head_sha"]
                    require_full_sha("superseding head", new_head)
                    if (result["state"] != "superseded" or result["repository"] != self.options.repository
                            or str(result["pr_number"]) != str(target["number"])
                            or result["head_sha"] != target["head"] or new_head == target["head"]):
                        raise ValueError("Invalid superseded review result")
                    superseded, exit_code = True, 0
                    logging.info("%s", result["message"])
                elif code == 0:
                    result = json.loads((context / RESULT_FILE).read_text())
                    if result["state"] not in {"success", "failure"}:
                        raise ValueError("Missing verified review verdict")
                    if self.options.dry_run:
                        result["simulated_delivery"] = True
                        (context / RESULT_FILE).write_text(json.dumps(result, indent=2) + "\n")
                    exit_code = 0
                else:
                    failure = interpret(read_events(context / "codex-events.jsonl"),
                                        (context / "codex-stderr.log").read_text(), code,
                                        now=time.time(),
                                        usage_limit_backoff=self.options.usage_limit_backoff)
                    exit_code = 130 if code == 130 else 1
        except KeyboardInterrupt:
            failure = Failure("Review step was cancelled (possibly timeout or cancelled)")
            exit_code = 130
        except Exception as error:
            logging.error("Review execution failed (%s): %s", type(error).__name__, redact(str(error)))
            outcome = "failure" if review_started else "skipped"
            failure = Failure(f"Review step was {outcome} (possibly timeout or cancelled)")
        finally:
            if context and ((context_ready and failure) or self.options.dry_run):
                finalize("Preserve review diagnostics", lambda: self.runtime.diagnostics(
                    context, local=self.options.dry_run),
                    self.options.diagnostics_timeout, critical=False)
            invalid_recorded = cooldown_recorded = False
            if failure and auth:
                if failure.invalid_auth:
                    invalid_recorded = finalize("Record invalid Codex auth", lambda: auth.record_invalid(
                        failure.invalid_auth), self.options.record_timeout)
                if failure.retry_after is not None:
                    cooldown_recorded = finalize("Record Codex usage limit", lambda: auth.record_cooldown(
                        failure.retry_after), self.options.record_timeout)
            if failure:
                finalize("Publish execution failure", lambda: self.report_failure(
                    target, failure, invalid_recorded=invalid_recorded, cooldown_recorded=cooldown_recorded,
                    auth_failure=auth_failure, context_ready=context_ready), self.options.status_timeout)
            if target["manage_status"] and not superseded:
                finalize("Publish automated source", lambda: self.statuses.finish_review(
                    target["number"], target["head"], target["base"], result=result,
                    execution_succeeded=exit_code == 0 and not finalization_failed,
                ), self.options.status_timeout)
            if context:
                finalize("Record review telemetry", lambda: self.runtime.telemetry(
                    context, workspace.path / "codex-home", target, superseded=superseded),
                    self.options.telemetry_timeout, critical=False)
            finalize("Archive Codex sessions", lambda: self.runtime.sessions(workspace.path / "codex-home"),
                     self.options.sessions_timeout, critical=False)
            if auth:
                finalize("Persist refreshed credentials", auth.sync, self.options.auth_sync_timeout)
            if target["manage_status"] and not superseded:
                finalize("Aggregate Code Review status", lambda: self.statuses.aggregate(target["head"]),
                         self.options.sync_timeout)
        return exit_code or int(finalization_failed)

    def report_failure(self, target, failure, *, invalid_recorded, cooldown_recorded,
                       auth_failure, context_ready):
        recovery = "Please inspect the workflow logs and rerun the review after the underlying issue is resolved."
        error = failure.message
        if auth_failure:
            error = auth_failure
        elif failure.invalid_auth:
            recovery = (
                "This credential version is excluded from future reviews. Replace its refresh token to restore "
                "eligibility. Please trigger /review again; another configured account may be available."
                if invalid_recorded else
                "The workflow failed to record the invalid credential, so it may still be selected. "
                "Please inspect the recording step before retrying.")
        elif failure.retry_after is not None:
            if cooldown_recorded:
                retry_at = datetime.fromtimestamp(failure.retry_after, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                recovery = (f"The selected account is excluded until {retry_at}. Please trigger /review again; "
                            "another configured account may be available.")
            else:
                error = "Codex reached its usage limit, but the workflow failed to record the account context."
                recovery = ("Please inspect the workflow logs and trigger /review again after the recording "
                            "problem is resolved.")
        elif not context_ready:
            error = ("Review context preparation failed before Codex ran; inspect the "
                     "'Prepare authoritative PR context and required AGENTS guides' step.")
        self.github.comment(target["number"],
                            "Codex automated review failed and did not complete.\n\n"
                            f"Error: {error}\nWorkflow run: {self.options.run_url}\n\n{recovery}")
