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

"""Verify orchestration outcomes against the existing status resolver."""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from events import Event
from locking import Locks
from review_workflow import ReviewWorkflow
from status_workflow import StatusWorkflow
from submit_review import validate_submission


class FakeGitHub:
    repository = "apache/doris"

    def __init__(self):
        self.pr = {"state": "open", "number": 123, "head": {"sha": "a" * 40},
                   "base": {"sha": "b" * 40, "ref": "master"}}
        self.statuses, self.comments = [], []

    def pull(self, number):
        return self.pr

    def api(self, path, **kwargs):
        if path.startswith("pulls?"):
            return [self.pr]
        if path.endswith("/statuses?per_page=100"):
            return self.statuses
        raise AssertionError(path)

    def status(self, head, context, state, description, url):
        self.statuses.insert(0, dict(id=len(self.statuses) + 1, head=head, context=context,
                                    state=state, description=description, target_url=url))

    def comment(self, number, body):
        self.comments.append(body)


class ReviewPromptContractTest(unittest.TestCase):
    def test_prompt_supports_both_delivery_outcomes(self):
        prompt = (Path(__file__).resolve().parents[1] / "prompts/review.txt").read_text()
        example = next(line.strip() for line in prompt.splitlines() if line.strip().startswith('{"body":'))
        submission = json.loads(example.replace("<diff_position>", "1"))
        validate_submission(submission)
        validate_submission(dict(submission, converged=False, rounds=3, incomplete_reason="Coverage incomplete"))
        self.assertIn("do not start a fourth round", prompt)
        self.assertIn("MUST NOT prevent delivery of verified findings", prompt)


class ReviewConvergenceWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.github = FakeGitHub()
        self.statuses = StatusWorkflow(self.github, Locks(self.root / "locks", timeout=1),
                                       run_url="https://fixture/build/1", skip_policy={})

    def test_verified_verdict_flows_through_source_and_aggregate(self):
        for converged, p0, p1, expected in (
            (True, 0, 0, "success"), (True, 1, 0, "failure"), (True, 0, 1, "failure"),
            (False, 0, 0, "failure"), (False, 0, 1, "failure"),
        ):
            with self.subTest(converged=converged, p0=p0, p1=p1):
                result = dict(state=expected, p0=p0, p1=p1, converged=converged, rounds=3)
                self.statuses.finish_review(123, "a" * 40, "b" * 40, result=result, execution_succeeded=True)
                resolution = self.statuses.aggregate("a" * 40)
                self.assertEqual(expected, resolution.state)
                self.assertEqual(not converged, "did not converge" in resolution.description)

    def run_workflow(self, code, result, *, auth_sync_failure=False, diagnostics_failure=False,
                     credential_failure=None):
        context = self.root / "context"
        context.mkdir(exist_ok=True)
        (context / "review-result.json").write_text(json.dumps(result))
        (context / "codex-events.jsonl").write_text(json.dumps({"type": "turn.failed", "error": {"message": "fixture error"}}))
        (context / "codex-stderr.log").write_text("")
        options = SimpleNamespace(repository="apache/doris", repository_url="fixture", trusted_revision="c" * 40,
                                  dry_run=False, command_timeout=1, context_threads=30, context_body_chars=1200,
                                  templates=self.root, usage_limit_backoff=3600, run_url="https://fixture/build/1")
        for name in ("resolve", "status", "checkout", "auth", "memories", "focus", "context", "threads",
                     "prompt", "review", "diagnostics", "record", "telemetry", "sessions", "auth_sync", "sync"):
            setattr(options, name + "_timeout", 10)
        runtime = mock.Mock()
        if diagnostics_failure:
            options.dry_run = True
            runtime.diagnostics.side_effect = OSError("artifact unavailable")
        if credential_failure:
            runtime.auth.acquire.return_value.record_invalid.side_effect = OSError("marker upload failed")
        snapshot = runtime.auth.acquire.return_value
        if auth_sync_failure:
            snapshot.sync.side_effect = OSError("fixture writeback failed")
        event = Event("issue_comment", {"issue": {"number": 123}, "comment": {"body": "/review focus"}})
        workspace = SimpleNamespace(path=self.root)
        (self.root / "pr").mkdir(exist_ok=True)
        with mock.patch("review_workflow.checkout"), mock.patch("review_workflow.prepare", return_value=(context, "", "")), \
             mock.patch("review_workflow.render_prompt"), \
             mock.patch("review_workflow.execute_review", return_value=code), \
             mock.patch("review_workflow.interpret", return_value=credential_failure) if credential_failure else mock.patch(
                 "review_workflow.interpret", wraps=__import__("review_failure").interpret):
            status = ReviewWorkflow(options, self.github, self.statuses, runtime).run(event, workspace)
        return status, snapshot, workspace

    def test_verified_request_changes_is_successful_execution(self):
        code, snapshot, _ = self.run_workflow(0, dict(state="failure", p0=0, p1=1, converged=True, rounds=1))
        self.assertEqual(0, code)
        self.assertEqual("failure", self.github.statuses[0]["state"])
        self.assertEqual([], self.github.comments)
        snapshot.record_invalid.assert_not_called()
        snapshot.record_cooldown.assert_not_called()
        snapshot.sync.assert_called_once()

    def test_execution_failure_leaves_pending_and_comments(self):
        code, snapshot, _ = self.run_workflow(1, {})
        self.assertEqual(1, code)
        self.assertEqual("pending", self.github.statuses[0]["state"])
        self.assertIn("fixture error", self.github.comments[0])
        snapshot.sync.assert_called_once()

    def test_late_auth_failure_preserves_verified_verdict_without_recovery(self):
        code, _, workspace = self.run_workflow(0, dict(state="success", p0=0, p1=0, converged=True, rounds=1),
                                               auth_sync_failure=True)
        self.assertEqual(1, code)
        self.assertFalse((workspace.path / "auth-snapshot.json").exists())
        self.assertEqual("success", self.github.statuses[0]["state"])

    def test_diagnostics_failure_does_not_fail_completed_review(self):
        code, _, _ = self.run_workflow(0, dict(state="success", p0=0, p1=0, converged=True, rounds=1),
                                      diagnostics_failure=True)
        self.assertEqual(0, code)
        self.assertEqual("success", self.github.statuses[0]["state"])

    def test_cooldown_is_written_even_when_invalid_marker_upload_fails(self):
        from review_failure import Failure
        code, snapshot, _ = self.run_workflow(1, {}, credential_failure=Failure(
            "refresh_token_reused", "refresh_token_reused", 1700000000))
        self.assertEqual(1, code)
        snapshot.record_invalid.assert_called_once_with("refresh_token_reused")
        snapshot.record_cooldown.assert_called_once_with(1700000000)
        snapshot.sync.assert_called_once()
        self.assertIn("failed to record the invalid credential", self.github.comments[0])

    def test_only_matching_superseded_result_suppresses_final_status(self):
        for head, state, expected in (("a" * 40, "superseded", 0), ("b" * 40, "superseded", 1),
                                      ("a" * 40, "success", 1)):
            with self.subTest(head=head, state=state):
                self.github.statuses.clear()
                code, snapshot, _ = self.run_workflow(75, dict(state=state, repository="apache/doris",
                    pr_number=123, head_sha=head, superseding_head_sha="c" * 40, message="head changed"))
                self.assertEqual(expected, code)
                if code == 0:
                    self.assertEqual(2, len(self.github.statuses))  # Only initial pending writes.
                snapshot.sync.assert_called_once()

    def test_sync_runs_previous_head_even_when_current_head_fails(self):
        event = Event("pull_request_target", {"action": "synchronize", "before": "b" * 40,
                       "pull_request": {"head": {"sha": "a" * 40}}})
        with mock.patch.object(self.statuses, "aggregate", side_effect=[OSError("offline"), None]) as aggregate:
            with self.assertRaises(RuntimeError):
                self.statuses.synchronize(event)
        self.assertEqual([mock.call("a" * 40), mock.call("b" * 40)], aggregate.call_args_list)

    def test_local_pass_checks_creator_permission_and_current_context(self):
        from tests.test_validate_review_pass_comment import make_comment
        comment = {"body": make_comment(), "html_url": "https://fixture/comment",
                   "user": {"login": "doris-committer"}}
        event = Event("issue_comment", {"issue": {"number": 123}, "comment": comment,
                                       "sender": {"login": "doris-committer"}})
        api = self.github.api

        def response(path, **kwargs):
            if path.endswith("/permission"):
                return {"permission": "write"}
            if path.startswith("compare/"):
                return {"status": "identical"}
            return api(path, **kwargs)

        with mock.patch.object(self.github, "api", side_effect=response):
            self.statuses.accept_local(event)
        self.assertEqual("success", self.github.statuses[0]["state"])
        self.assertTrue(any("/local/" in s["context"] for s in self.github.statuses))
        self.github.statuses.clear()
        event.data["sender"]["login"] = "different-editor"
        self.statuses.accept_local(event)
        self.assertEqual([], self.github.statuses)


class RuntimeCanaryWorkflowTest(unittest.TestCase):
    def test_every_model_is_required_and_failure_stops_later_cases(self):
        from canary import run_canary
        cases = ["sol:gpt-6-sol:low:plain", "prior-sol:gpt-5.6-sol:low:plain",
                 "sol-goal:gpt-6-sol:low:goal", "sol61:gpt-6.1-sol:xhigh:plain",
                 "sol61-goal:gpt-6.1-sol:xhigh:goal"]
        for failure_index in range(6):
            with self.subTest(failure_index=failure_index), tempfile.TemporaryDirectory() as directory:
                options = SimpleNamespace(canary_auth_object="oss://fixture/auth.json.4", canary_case=cases,
                                          canary_timeout=180, canary_step_timeout=1080, canary_job_timeout=1500)
                workspace = SimpleNamespace(path=Path(directory), reaper=mock.Mock())
                runtime = mock.Mock()
                runtime.install.return_value = {}
                calls = []

                def attempt(command, events, stderr, timeout, reaper):
                    self.assertIs(workspace.reaper, reaper)
                    calls.append((command[command.index("--model") + 1], "--goal" in command))
                    events.write_text('{"type": "turn.completed"}\n')
                    return 1 if len(calls) - 1 == failure_index else 0

                with mock.patch("canary.run_attempt", side_effect=attempt):
                    code = run_canary(options, runtime, workspace)
                self.assertEqual(0 if failure_index == 5 else 1, code)
                expected = [("gpt-6-sol", False), ("gpt-5.6-sol", False), ("gpt-6-sol", True),
                            ("gpt-6.1-sol", False), ("gpt-6.1-sol", True)]
                self.assertEqual(expected[:min(5, failure_index + 1)], calls)
                runtime.auth.acquire.return_value.sync.assert_called_once_with(canary=True)
                runtime.memories.assert_not_called()


if __name__ == "__main__":
    unittest.main()
