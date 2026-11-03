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

"""Trusted event transport, serialization and workspace cleanup."""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tarfile
import time
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from events import Event
from forward import build_request, enqueue, event_snapshot
from lifecycle import Workspace
from locking import Locks, LockTimeout
from local_services import LocalGitHub, ReadOnlyObjectStore
from process import environment
from review_runtime import Runtime
from review_workflow import resolve_target


class ReviewCheckoutWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.locks = Locks(self.root / "locks", timeout=0.02)

    def test_invocation_environment_restores_after_failure_and_cancellation(self):
        original = {"GH_TOKEN": "original", "REVIEW_TEST": "before"}
        for error in (RuntimeError, KeyboardInterrupt):
            with self.subTest(error=error), mock.patch.dict(os.environ, original, clear=True):
                with self.assertRaises(error):
                    with environment({"REVIEW_TEST": "during", "CODEX_HOME": "/fixture"}, remove=("GH_TOKEN",)):
                        self.assertNotIn("GH_TOKEN", os.environ)
                        self.assertEqual("during", os.environ["REVIEW_TEST"])
                        os.environ["CHILD_VARIABLE"] = "temporary"
                        raise error()
                self.assertEqual(original, dict(os.environ))

    def test_diagnostics_redact_nested_values_without_breaking_json(self):
        context = self.root / "context"
        context.mkdir()
        value = {"item": {"output": 'if (auth_info.token == "test") {\n  return true;\n}',
                          "credentials": [{"access_token": "private-value"}]},
                 "converged": False, "rounds": 3}
        for name in ("review-submission.json", "codex-events.jsonl"):
            (context / name).write_text(json.dumps(value) + "\n")
        runtime = Runtime(SimpleNamespace(artifacts_dir=self.root / "artifacts"), None, None, {})
        runtime.diagnostics(context, local=True)
        for name in ("review-submission.json", "codex-events.jsonl"):
            content = (self.root / "artifacts/review" / name).read_text()
            sanitized = json.loads(content)
            self.assertNotIn("private-value", content)
            self.assertEqual("[REDACTED]", sanitized["item"]["credentials"][0]["access_token"])
            self.assertFalse(sanitized["converged"])
            self.assertEqual(3, sanitized["rounds"])

    def comment(self, body="/review", association="MEMBER"):
        return {"action": "created", "repository": {"full_name": "apache/doris"},
                "issue": {"number": 123, "pull_request": {"url": "unused"}, "body": "unused"},
                "comment": {"id": 10, "body": body, "author_association": association,
                            "html_url": "https://fixture/comment", "user": {"id": 7, "login": "maintainer"}},
                "sender": {"login": "maintainer"}}

    def test_large_untrusted_event_roundtrips_without_controller_overrides(self):
        data = self.comment("/review %env.TOKEN% $(exit 1) ' \" 中文\n" * 5000)
        data["ref"], data["sha"] = "malicious", "untrusted"
        request = build_request(data, event_name="issue_comment", build_type="Review", request_id="1:1",
                                origin_url="https://fixture/run", chunk_size=16000)
        self.assertEqual({"buildType", "properties"}, set(request))
        properties = {p["name"]: p["value"] for p in request["properties"]["property"]}
        count = int(properties["env.REVIEW_EVENT_PARTS"])
        encoded = "".join(properties[f"env.REVIEW_EVENT_{i:04d}"] for i in range(count))
        snapshot = json.loads(base64.b64decode(encoded, validate=True))
        self.assertEqual(data["comment"]["body"], snapshot["comment"]["body"])
        self.assertNotIn("sha", snapshot)
        self.assertNotIn("ref", snapshot)
        self.assertNotIn("body", snapshot["issue"])
        self.assertTrue(all(len(value) <= 16000 for value in properties.values()))

    def test_policy_retains_creation_body_and_independent_local_skip_handlers(self):
        for association, allowed in (("MEMBER", True), ("OWNER", True), ("COLLABORATOR", True), ("CONTRIBUTOR", False)):
            data = self.comment(association=association)
            snapshot = event_snapshot(data)
            data["comment"]["body"] = "edited later"
            self.assertEqual(allowed, Event("issue_comment", snapshot).review)
        event = Event("issue_comment", event_snapshot(self.comment("<!-- doris-repo-review:v1:begin --> skip buildall")))
        self.assertTrue(event.local_pass and event.skip)
        self.assertFalse(event.review)

    def test_all_pr_actions_and_previous_head_survive_transport(self):
        for action in ("opened", "synchronize", "reopened", "ready_for_review", "edited", "closed"):
            data = {"repository": {"full_name": "apache/doris"}, "action": action, "before": "b" * 40,
                    "pull_request": {"number": 123, "head": {"sha": "a" * 40}}}
            heads = Event("pull_request_target", event_snapshot(data)).status_heads
            self.assertEqual(["a" * 40, "b" * 40] if action == "synchronize" else ["a" * 40], heads)

    def test_comment_resolves_live_target_and_dispatch_rejects_stale_target(self):
        pr = {"head": {"sha": "a" * 40}, "base": {"sha": "b" * 40}}
        github = SimpleNamespace(pull=lambda _: pr)
        event = Event("issue_comment", self.comment("/review  focus"))
        self.assertEqual("focus", resolve_target(event, github)["focus"])
        pr["head"]["sha"] = "d" * 40
        self.assertEqual("d" * 40, resolve_target(event, github)["head"])
        dispatch = Event("workflow_dispatch", {"inputs": {"pr_number": "123", "head_sha": "a" * 40,
                                                            "base_sha": "b" * 40, "manage_status": True}})
        with self.assertRaisesRegex(ValueError, "mismatch"):
            resolve_target(dispatch, github)

    def test_same_pr_serializes_and_distinct_prs_do_not_block(self):
        with self.locks.hold("pull-requests", "repo:1"), self.locks.hold("pull-requests", "repo:2"):
            with self.assertRaises(LockTimeout):
                self.locks.hold("pull-requests", "repo:1").acquire()
        with self.locks.hold("pull-requests", "repo:1"):
            pass

    def test_enqueue_failure_does_not_repeat_post(self):
        for error in (TimeoutError(), urllib.error.HTTPError("http://fixture", 503, "unavailable", {}, None)):
            with self.subTest(error=type(error).__name__), \
                 mock.patch("forward.urllib.request.urlopen", side_effect=error) as send:
                with self.assertRaisesRegex(RuntimeError, "inspect its queue"):
                    enqueue("http://fixture", "fake-only", {}, timeout=1)
                send.assert_called_once()

    def test_workspace_is_private_and_removed_even_after_auth_writeback_failure(self):
        for fail in (False, True):
            try:
                with Workspace(self.root) as first, Workspace(self.root) as second:
                    self.assertNotEqual(first.path, second.path)
                    (first.path / "auth.json").write_text("private snapshot")
                    if fail:
                        raise OSError("auth writeback failed")
            except OSError:
                pass
            self.assertFalse(first.path.exists())
            self.assertFalse(second.path.exists())

    def test_comment_filters_match_github_case_insensitive_expressions(self):
        for body, review, skip, local in [
            ("/REVIEW", True, False, False), ("Skip BuildAll", False, True, False),
            ("/REVIEW skip buildall", True, False, False),
            ("<!-- DORIS-REPO-REVIEW:V1:BEGIN -->", False, False, True),
            (" /review", False, False, False),
        ]:
            with self.subTest(body=body):
                event = Event("issue_comment", self.comment(body))
                self.assertEqual((review, skip, local), (event.review, event.skip, event.local_pass))
        github = SimpleNamespace(pull=lambda _: {"head": {"sha": "a" * 40}, "base": {"sha": "b" * 40}})
        self.assertEqual("/REVIEW focus", resolve_target(
            Event("issue_comment", self.comment("/REVIEW focus")), github)["focus"])

    def test_package_is_downloaded_and_verified_for_each_build(self):
        from packages import digest, install_codex
        from tests.test_review_auth_quarantine import MemoryStore
        bundle = self.root / "bundle"
        (bundle / "bin").mkdir(parents=True)
        (bundle / "bin/codex").write_bytes(b"fixture binary")
        (bundle / "SHA256SUMS").write_text(digest(bundle / "bin/codex") + "  bin/codex\n")
        (bundle / "codex-package.json").write_text('{"version": "fixture"}')
        archive = self.root / "package.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for child in bundle.iterdir():
                output.add(child, arcname=child.name)
        store = MemoryStore()
        store.objects["oss://fixture/package"] = archive.read_bytes()
        checksum = digest(archive)
        for index in range(2):
            with Workspace(self.root) as workspace:
                binary = install_codex(store, workspace.path, source="oss://fixture/package",
                                       checksum=checksum, version="fixture")
                self.assertEqual(b"fixture binary", binary.read_bytes())
        self.assertEqual(["oss://fixture/package"] * 2, store.reads)
        store.objects["oss://fixture/package"] = b"corrupted archive"
        with Workspace(self.root) as workspace, self.assertRaisesRegex(ValueError, "archive SHA256"):
            install_codex(store, workspace.path, source="oss://fixture/package", checksum=checksum, version="fixture")

    def test_step_budget_covers_all_calls_and_restores_outer_budget(self):
        from process import StepTimeout, step
        with self.assertRaisesRegex(StepTimeout, "outer"):
            with step("outer", 0.03):
                with step("inner", 1):
                    time.sleep(0.1)
        with step("later step", 1):
            with self.assertRaisesRegex(StepTimeout, "short step"):
                with step("short step", 0.01):
                    time.sleep(0.1)
            time.sleep(0.01)

    def test_session_stat_failure_attempts_upload_but_marker_listing_failure_propagates(self):
        from object_store import ObjectStore
        store = ObjectStore("ossutil", config_file=self.root / "config")
        with mock.patch.object(store, "_run", side_effect=subprocess.CalledProcessError(1, "ossutil")):
            self.assertFalse(store.session_exists("oss://fixture/session"))
            with self.assertRaises(subprocess.CalledProcessError):
                store.exists("oss://fixture/invalid")

    def test_canary_adapter_neither_requires_nor_exports_github_credentials(self):
        import importlib.util
        controller = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location("teamcity_adapter", controller / "teamcity.py")
        adapter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(adapter)
        payload = build_request({"repository": {"full_name": "apache/doris"},
                                 "inputs": {"runtime_canary": True}}, event_name="workflow_dispatch",
                                build_type="Review", request_id="1:1", origin_url="http://fixture", chunk_size=16000)
        env = {p["name"].removeprefix("env."): p["value"] for p in payload["properties"]["property"]}
        env.update(REVIEW_CONTROLLER_DIR=str(controller), REVIEW_TEMP_DIR=str(self.root),
                   REVIEW_BUILD_ID="1", REVIEW_BUILD_URL="http://fixture/build/1",
                   REVIEW_OSS_ACCESS_KEY="fixture-access", REVIEW_OSS_SECRET_KEY="fixture-secret",
                   REVIEW_TELEMETRY_PUBLIC_KEY="unused-public", REVIEW_TELEMETRY_SECRET_KEY="unused-secret")
        def worker(arguments):
            self.assertNotIn("--github-token-file", arguments)
            self.assertNotIn("--trusted-revision", arguments)
            self.assertNotIn("REVIEW_TELEMETRY_SECRET_KEY", os.environ)
            self.assertNotIn("REVIEW_OSS_SECRET_KEY", os.environ)
            self.assertEqual("fixture-secret", Path(arguments[arguments.index("--oss-secret-key-file") + 1]).read_text())
            return 0
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(sys, "argv", ["teamcity.py", "review"]), \
             mock.patch("cli.main", side_effect=worker), mock.patch("subprocess.check_output") as revision:
            self.assertEqual(0, adapter.main())
            revision.assert_not_called()
        self.assertEqual([], list(self.root.iterdir()))

    def test_forward_to_teamcity_adapter_and_sync_without_external_writes(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"])) ))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"id": 1, "webUrl": "http://fixture/build/1"}')

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        controller = Path(__file__).resolve().parents[1]
        event = self.root / "event.json"
        event.write_text(json.dumps(self.comment("skip buildall")))
        token = self.root / "token"
        token.write_text("fake-only")
        try:
            result = subprocess.run([sys.executable, str(controller / "main.py"), "forward",
                "--event-file", str(event), "--event-name", "issue_comment", "--request-id", "1:1",
                "--origin-url", "http://fixture/action", "--teamcity-url", f"http://127.0.0.1:{server.server_port}",
                "--teamcity-build-type", "ReviewSync", "--teamcity-token-file", str(token)],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stderr)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        binary = self.root / "bin"
        binary.mkdir()
        gh = binary / "gh"
        gh.write_text(f"#!{sys.executable}\n" + '''import json, os, sys
from pathlib import Path
if sys.argv[1:] == ["--version"]:
    print("gh fixture-version")
    sys.exit(0)
path = sys.argv[2]
log = Path(os.environ["TEST_WRITES"])
writes = json.loads(log.read_text()) if log.exists() else []
pr = {"state":"open", "number":123, "head":{"sha":"a"*40}, "base":{"sha":"b"*40,"ref":"master"}}
if "--method" in sys.argv:
    value = json.load(sys.stdin)
    value["id"] = len(writes) + 1
    writes.insert(0, value)
    log.write_text(json.dumps(writes))
    print(json.dumps(value))
elif path.endswith("pulls/123"):
    print(json.dumps(pr))
elif "/pulls?" in path:
    print(json.dumps([[pr]]))
elif "/statuses?" in path:
    print(json.dumps([writes]))
else:
    raise AssertionError(path)
''')
        gh.chmod(0o700)
        policy = self.root / "skip.json"
        policy.write_text(json.dumps({"all_branches": ["7"], "branches": {}}))
        inputs = self.root / "inputs"
        inputs.mkdir()
        env = {**os.environ, **{p["name"].removeprefix("env."): p["value"]
                                for p in requests[0]["properties"]["property"]},
               "PATH": str(binary) + os.pathsep + os.environ["PATH"], "TEST_WRITES": str(self.root / "writes"),
               "REVIEW_CONTROLLER_DIR": str(controller), "REVIEW_TEMP_DIR": str(inputs),
               "REVIEW_BUILD_ID": "1", "REVIEW_BUILD_URL": "http://fixture/build/1",
               "REVIEW_GITHUB_TOKEN": "fake-only"}
        command = [sys.executable, str(controller / "teamcity.py"), "sync", "--repository", "apache/doris",
                   "--state-root", str(self.root / "state"), "--artifacts-dir", str(self.root / "artifacts"),
                   "--skip-policy", str(policy)]
        for execution in (1, 2):
            result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stderr)
            writes = json.loads((self.root / "writes").read_text())
            self.assertEqual(4 * execution, len(writes))
            self.assertEqual("success", writes[0]["state"])
            self.assertEqual([], list(inputs.iterdir()))


class LocalReadOnlyWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.options = SimpleNamespace(repository="apache/doris", artifacts_dir=self.root,
                                       api_timeout=5, review_author="local-bot", rclone="rclone",
                                       rclone_remote="oss:", rclone_endpoint=None, oss_timeout=5,
                                       state_root=self.root / "state")
        self.gateway = LocalGitHub(self.options, dict(os.environ, REVIEW_GH_VERSION="gh fixture"))
        self.gateway.url = "http://localhost/dry-run"

    def test_no_write_ever_reaches_authenticated_transport(self):
        for args in (
            ["api", "repos/apache/doris/pulls/1", "-X", "DELETE"],
            ["api", "repos/apache/doris/pulls/1", "-F", "state=closed"],
            ["api", "repos/apache/doris/pulls/1", "--method", "POST", "--input", "-"],
            ["api", "repos/apache/doris/../../user"],
            ["pr", "review", "1", "--approve"],
        ):
            with self.subTest(args=args), mock.patch.object(self.gateway, "read") as read:
                with self.assertRaises(ValueError):
                    self.gateway.call(args, "{}")
                read.assert_not_called()

    def test_simulated_delivery_can_be_read_back_without_real_post(self):
        endpoint = "repos/apache/doris/pulls/1/reviews"
        payload = dict(commit_id="a" * 40, body="local only", event="REQUEST_CHANGES",
                       comments=[dict(path="a.cc", position=1, body="[P1] issue")])
        with mock.patch.object(self.gateway, "read", return_value=[]) as read:
            posted = json.loads(self.gateway.call(["api", endpoint, "--method", "POST", "--input", "-"],
                                                 json.dumps(payload)))
            read.assert_not_called()
            reviews = json.loads(self.gateway.call(["api", endpoint, "--paginate", "--slurp"], ""))
            self.assertEqual(posted, reviews[0][0])
            self.assertEqual("CHANGES_REQUESTED", posted["state"])
            self.assertTrue(posted["simulated"])
            read.reset_mock()
            comments = json.loads(self.gateway.call(["api", endpoint + f"/{posted['id']}/comments"], ""))
            self.assertEqual("[P1] issue", comments[0]["body"])
            read.assert_not_called()

    def test_status_overlay_uses_newest_local_status(self):
        head = "a" * 40
        endpoint = "repos/apache/doris/statuses/" + head
        for state in ("pending", "success"):
            self.gateway.call(["api", endpoint, "--method", "POST", "--input", "-"],
                              json.dumps(dict(context="code-review", state=state)))
        with mock.patch.object(self.gateway, "read", return_value=[dict(id=1, state="failure")]):
            statuses = json.loads(self.gateway.call(["api", f"repos/apache/doris/commits/{head}/statuses"], ""))
        self.assertEqual(["success", "pending", "failure"], [item["state"] for item in statuses])

    def test_object_upload_records_metadata_without_running_rclone(self):
        source = self.root / "auth.json"
        source.write_text('{"secret": "do-not-record"}')
        store = ReadOnlyObjectStore(self.options)
        with mock.patch.object(store, "_run") as run:
            store.upload(source, "oss://bucket/auth.json")
            run.assert_not_called()
        journal = store.journal.read_text()
        self.assertNotIn("do-not-record", journal)
        self.assertEqual("oss://bucket/auth.json", json.loads(journal)["destination"])
        recovery = Path(json.loads(journal)["private_recovery_file"])
        self.assertEqual(source.read_bytes(), recovery.read_bytes())
        self.assertEqual(0o600, recovery.stat().st_mode & 0o777)

    def test_optional_download_does_not_hide_auth_failure(self):
        store = ReadOnlyObjectStore(self.options)
        with mock.patch.object(store, "_run", side_effect=subprocess.CalledProcessError(1, "rclone")):
            with self.assertRaises(subprocess.CalledProcessError):
                store.download("oss://bucket/auth.context", self.root / "context", optional=True)
        with mock.patch.object(store, "_run", side_effect=subprocess.CalledProcessError(3, "rclone")):
            self.assertFalse(store.download("oss://bucket/auth.context", self.root / "context", optional=True))

    def test_rclone_empty_success_cannot_reuse_previous_auth_candidate(self):
        store = ReadOnlyObjectStore(self.options)
        destination = self.root / "candidate"
        destination.write_text("previous candidate")
        with mock.patch.object(store, "_run"):
            self.assertFalse(store.download("oss://bucket/missing", destination, optional=True))
            self.assertFalse(destination.exists())
            with self.assertRaises(FileNotFoundError):
                store.download("oss://bucket/missing", destination)

    def test_dry_run_cli_keeps_live_state_separate(self):
        from cli import main
        event = self.root / "event.json"
        event.write_text(json.dumps({"repository": {"full_name": "apache/doris"}, "action": "opened",
                                     "pull_request": {"number": 1, "head": {"sha": "a" * 40}}}))
        live = self.root / "state/workspaces/live"
        live.mkdir(parents=True)
        (live / "auth-snapshot.json").write_text("live recovery data")
        environment = dict(os.environ, REVIEW_GH_VERSION="fixture")
        with mock.patch("cli.configure_environment", return_value=environment), \
             mock.patch.object(LocalGitHub, "read", return_value=[]) as reads:
            code = main(["sync", "--dry-run", "--event-file", str(event), "--event-name", "pull_request_target",
                         "--repository", "apache/doris", "--request-id", "test", "--run-id", "test",
                         "--run-url", "https://fixture/local", "--state-root", str(self.root / "state"),
                         "--artifacts-dir", str(self.root)])
        self.assertEqual(0, code)
        self.assertTrue(reads.called)
        self.assertEqual("live recovery data", (live / "auth-snapshot.json").read_text())
        self.assertFalse((self.root / "state/locks").exists())
        self.assertEqual(1, len(list((self.root / "state/dry-run/locks/status").glob("*.lock"))))
        self.assertEqual(2, len(self.gateway.journal.read_text().splitlines()))

    @unittest.skipUnless(shutil.which("bwrap"), "bubblewrap not installed")
    def test_codex_sandbox_cannot_read_host_credentials_or_inherit_tokens(self):
        secret = self.root / "host-secret"
        secret.write_text("must stay outside the sandbox")
        workspace = SimpleNamespace(path=self.root / "workspace")
        workspace.path.mkdir()
        binary = self.root / "package/bin/codex"
        binary.parent.mkdir(parents=True)
        binary.write_text(f"#!{sys.executable}\nimport json, os\n"
                          f"print(json.dumps([os.path.exists({str(secret)!r}), "
                          "os.environ.get('GH_TOKEN'), os.environ.get('OPENAI_API_KEY')]))\n")
        binary.chmod(0o700)
        env = dict(os.environ, GH_TOKEN="host-token", OPENAI_API_KEY="host-key",
                   CODEX_HOME=str(workspace.path / "codex-home"), REVIEW_GH_VERSION="fixture")
        with LocalGitHub(self.options, env) as gateway:
            isolated = gateway.isolate_codex(binary, workspace, env)
            result = subprocess.run(["codex"], env=isolated, cwd=workspace.path,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual([False, None, None], json.loads(result.stdout))


if __name__ == "__main__":
    unittest.main()
