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

"""Exercise OSS auth lifecycle without credentials, network or model calls."""

import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from auth_pool import AuthPool
from review_failure import AUTH_FAILURES, interpret


class MemoryStore:
    def __init__(self):
        self.objects = {}
        self.reads = []
        self.fail_upload = False

    def list(self, prefix):
        return sorted(key for key in self.objects if key.startswith(prefix))

    def exists(self, key):
        return key in self.list(key)

    def download(self, key, path, *, optional=False, **transport):
        self.reads.append(key)
        if key not in self.objects:
            if optional:
                return False
            raise FileNotFoundError(key)
        Path(path).write_bytes(self.objects[key])
        return True

    def upload(self, path, key, **transport):
        if self.fail_upload:
            raise OSError("fixture upload failure")
        self.objects[key] = Path(path).read_bytes()


class ReviewAuthQuarantineTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = MemoryStore()
        self.prefix = "oss://fixture/auth.json."
        self.pool = AuthPool(self.store, self.prefix)
        self.seed("1", "refresh-original")

    def seed(self, slot, token):
        self.store.objects[self.prefix + slot] = json.dumps({
            "auth_mode": "chatgpt", "tokens": {"access_token": "access", "refresh_token": token},
        }).encode()

    def acquire(self, name="run"):
        path = self.root / name
        path.mkdir(exist_ok=True)
        return self.pool.acquire(SimpleNamespace(path=path))

    def marker(self, slot="1", token="refresh-original"):
        return self.prefix + slot + ".invalid." + hashlib.sha256(token.encode()).hexdigest()

    def test_permanent_auth_codes_in_terminal_events_and_stderr(self):
        for code, message in AUTH_FAILURES.items():
            for events, stderr in (
                ([{"type": "turn.failed", "error": {"code": code, "message": "Refresh failed"}}], ""),
                ([{"type": "error", "message": message}], ""),
                ([], json.dumps({"code": code})),
                ([], f'ERROR codex_login::auth::manager: Failed to refresh token error_code: Some("{code}")'),
            ):
                with self.subTest(code=code, events=events, stderr=stderr):
                    result = interpret(events, stderr, 1, now=time.time(), usage_limit_backoff=3600)
                    self.assertEqual(code, result.invalid_auth)

    def test_failure_message_selection_matches_original_jq_tail_pipeline(self):
        for events, expected in [
            ([{"type": "error", "message": "top level", "error": {"message": "nested"}}], "top level"),
            ([{"type": "turn.failed", "message": "not an error.message"}], "stderr fallback"),
            ([{"type": "turn.failed", "error": {"message": "old failure"}},
              {"type": "turn.failed", "error": {"message": ""}},
              {"type": "error", "message": "latest error"}], "latest error"),
            ([{"type": "turn.failed", "error": {"message": "first line\nlast line"}}], "last line"),
        ]:
            with self.subTest(events=events):
                result = interpret(events, "stderr fallback", 1, now=1700000000, usage_limit_backoff=1800)
                self.assertEqual(expected, result.message)

    def test_tool_quotes_and_access_token_401_do_not_quarantine(self):
        for message in [*AUTH_FAILURES.values(), "401 token_revoked", "Request timed out"]:
            result = interpret([{"type": "item.completed", "item": {"output": message}}],
                               "generic failure", 1, now=time.time(), usage_limit_backoff=3600)
            self.assertEqual("", result.invalid_auth)
        result = interpret([{"type": "error", "message": "401 token_revoked"}], "", 1,
                           now=time.time(), usage_limit_backoff=3600)
        self.assertEqual("", result.invalid_auth)

    def test_marker_excludes_token_and_replacement_restores_eligibility(self):
        snapshot = self.acquire()
        snapshot.record_invalid("refresh_token_reused")
        self.assertIn(self.marker(), self.store.objects)
        with self.assertRaisesRegex(RuntimeError, "No eligible"):
            self.acquire("retry")
        self.seed("1", "replacement")
        self.assertEqual("replacement", json.loads(
            self.acquire("replacement").workspace.joinpath("codex-home/auth.json").read_text())["tokens"]["refresh_token"])

    def test_formatting_and_metadata_do_not_bypass_quarantine(self):
        self.acquire().record_invalid("refresh_token_invalidated")
        value = json.loads(self.store.objects[self.prefix + "1"])
        value["last_refresh"] = "new metadata"
        self.store.objects[self.prefix + "1"] = json.dumps(value, indent=4).encode()
        with self.assertRaises(RuntimeError):
            self.acquire("retry")

    def test_old_failure_does_not_quarantine_replacement(self):
        old = self.acquire()
        self.seed("1", "replacement")
        old.record_invalid("refresh_token_invalidated")
        self.assertNotIn(self.marker(token="replacement"), self.store.objects)
        self.acquire("replacement")

    def test_cooldown_and_quarantine_are_independent_and_latest_write_wins(self):
        snapshot = self.acquire()
        deadline = int(time.time()) + 600
        snapshot.record_cooldown(deadline)
        snapshot.record_cooldown(deadline - 10)
        snapshot.record_invalid("refresh_token_reused")
        self.assertEqual(deadline - 10, json.loads(self.store.objects[self.prefix + "1.context"])["retry_after_epoch"])
        self.assertIn(self.marker(), self.store.objects)
        with self.assertRaisesRegex(RuntimeError, "Earliest"):
            self.acquire("cooldown")

    def test_malformed_context_is_ignored_but_marker_read_failure_is_fatal(self):
        self.store.objects[self.prefix + "1.context"] = b"not-json"
        self.acquire()
        with mock.patch.object(self.store, "exists", side_effect=OSError("lookup failed")):
            with self.assertRaisesRegex(RuntimeError, "Failed to check invalid-token marker"):
                self.acquire("lookup")

    def test_selected_snapshot_downloads_only_once(self):
        snapshot = self.acquire()
        self.assertEqual(1, self.store.reads.count(self.prefix + "1"))
        snapshot.sync()
        self.assertEqual(1, self.store.reads.count(self.prefix + "1"))
        self.assertFalse((snapshot.workspace / "auth-snapshot.json").exists())

    def test_concurrent_snapshots_do_not_hold_account_lock_and_stale_write_is_skipped(self):
        first, second = self.acquire("one"), self.acquire("two")
        for snapshot, refresh in ((first, "first-refresh"), (second, "second-refresh")):
            path = snapshot.workspace / "codex-home/auth.json"
            value = json.loads(path.read_text())
            value["tokens"]["refresh_token"] = refresh
            path.write_text(json.dumps(value))
        first.sync()
        second.sync()
        self.assertEqual("first-refresh", json.loads(self.store.objects[self.prefix + "1"])["tokens"]["refresh_token"])

    def test_failed_write_does_not_schedule_later_recovery(self):
        snapshot = self.acquire()
        path = snapshot.workspace / "codex-home/auth.json"
        path.write_text(path.read_text().replace("refresh-original", "refreshed"))
        self.store.fail_upload = True
        with self.assertRaises(OSError):
            snapshot.sync()
        self.assertFalse((snapshot.workspace / "auth-snapshot.json").exists())
        self.assertIn(b"refresh-original", self.store.objects[self.prefix + "1"])

    def test_canary_ignores_pool_filters_and_rejects_concurrent_writeback(self):
        self.store.objects[self.prefix + "1.context"] = json.dumps({
            "version": 1, "state": "usage_limited", "retry_after_epoch": int(time.time()) + 600}).encode()
        self.store.objects[self.marker()] = b"{}"
        path = self.root / "canary"
        path.mkdir()
        snapshot = self.pool.acquire(SimpleNamespace(path=path), source=self.prefix + "1")
        self.assertEqual([self.prefix + "1"], self.store.reads)
        local = path / "codex-home/auth.json"
        local.write_text(local.read_text().replace("refresh-original", "local-refresh"))
        self.seed("1", "concurrent-refresh")
        with self.assertRaisesRegex(RuntimeError, "changed concurrently"):
            snapshot.sync(canary=True)
        self.assertIn(b"concurrent-refresh", self.store.objects[self.prefix + "1"])

    def test_invalid_cooldowns_do_not_exclude_an_account(self):
        for index, value in enumerate([
            {"version": True, "state": "usage_limited", "retry_after_epoch": int(time.time()) + 600},
            {"version": 1, "state": "usage_limited", "retry_after_epoch": True},
            {"version": 1, "state": "usage_limited", "retry_after_epoch": 10**30},
            [], None,
        ]):
            with self.subTest(value=value):
                self.store.objects[self.prefix + "1.context"] = json.dumps(value).encode()
                self.acquire(f"invalid-{index}")

    def test_unknown_reason_and_marker_upload_failures_are_not_hidden(self):
        snapshot = self.acquire()
        with self.assertRaises(ValueError):
            snapshot.record_invalid("unknown")
        self.store.fail_upload = True
        with self.assertRaises(OSError):
            snapshot.record_invalid("refresh_token_reused")

    def test_exact_marker_match_does_not_confuse_prefix_matches(self):
        self.store.objects[self.marker() + ".other"] = b"{}"
        self.acquire()

    def test_usage_limit_deadline_and_fallback(self):
        now = 1700000000
        for message, expected in (
            ("You've hit your usage limit. Try again at Nov 15th, 2023 10:00 AM", 1700042400),
            ("You've hit your usage limit", now + 3600),
        ):
            failure = interpret([{"type": "turn.failed", "error": {"message": message}}], "", 1,
                                now=now, usage_limit_backoff=3600)
            self.assertEqual(expected, failure.retry_after)


if __name__ == "__main__":
    unittest.main()
