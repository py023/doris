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

"""Private auth snapshots and the original OSS compare-before-write protocol."""

import hashlib
import json
import logging
import random
import re
import subprocess
import time
from pathlib import Path

from submit_review import write_json
from packages import digest
from process import sh
from review_failure import AUTH_FAILURES


def validate_auth(path):
    data = json.loads(Path(path).read_text())
    if data.get("auth_mode") != "chatgpt":
        raise ValueError("Expected ChatGPT credentials")
    for key in ("access_token", "refresh_token"):
        token = data.get("tokens", {}).get(key)
        if not isinstance(token, str) or not token:
            raise ValueError(f"Auth snapshot is missing {key}")
    return data


class AuthPool:
    def __init__(self, store, prefix):
        self.store, self.prefix = store, prefix

    def cooldown(self, source, destination):
        if not self.store.download(source + ".context", destination, optional=True):
            return 0
        try:
            data = json.loads(destination.read_text())
            retry = data["retry_after_epoch"]
            if (isinstance(data["version"], bool) or data["version"] != 1 or data["state"] != "usage_limited"
                    or isinstance(retry, bool) or not isinstance(retry, (int, float))
                    or not float(retry).is_integer()):
                raise ValueError("Invalid cooldown")
            date = sh("date", "-u", "-d", f"@{int(retry)}", "+%s", capture=True, check=False)
            if date.returncode:
                raise ValueError("Invalid cooldown timestamp")
            return int(date.stdout)
        except (ValueError, KeyError, TypeError, OverflowError):
            logging.warning("Ignoring unusable account cooldown for %s", source.rsplit("/", 1)[-1])
            return 0

    def acquire(self, workspace, *, source=None):
        home = workspace.path / "codex-home"
        home.mkdir(mode=0o700, exist_ok=True)
        # Canary reads the configured snapshot directly, bypassing selection,
        # cooldown and quarantine just as its separate workflow job did.
        if source:
            self.store.download(source, home / "auth.json")
            return self.snapshot(workspace, source, home / "auth.json")
        try:
            listing = self.store.list(self.prefix)
        except (OSError, subprocess.SubprocessError) as error:
            raise RuntimeError("Failed to list Codex review auth objects from OSS.") from error
        candidates = [item for item in listing
                      if re.fullmatch(re.escape(self.prefix) + r"[0-9]+", item)]
        if not candidates:
            raise RuntimeError("No numbered Codex review auth objects were found in OSS.")
        random.shuffle(candidates)
        earliest = None
        now = int(time.time())
        try:
            for candidate in candidates:
                retry = self.cooldown(candidate, home / "candidate.context")
                if retry > now:
                    earliest = retry if earliest is None else min(earliest, retry)
                    continue
                path = home / "candidate.json"
                self.store.download(candidate, path)
                data = validate_auth(path)
                refresh_hash = hashlib.sha256(data["tokens"]["refresh_token"].encode()).hexdigest()
                try:
                    invalid = self.store.exists(candidate + ".invalid." + refresh_hash)
                except (OSError, subprocess.SubprocessError) as error:
                    raise RuntimeError(f"Failed to check invalid-token marker for {candidate.rsplit('/', 1)[-1]}.") from error
                if invalid:
                    continue
                path.replace(home / "auth.json")
                logging.info("Selected auth snapshot %s", candidate.rsplit("/", 1)[-1])
                return self.snapshot(workspace, candidate, home / "auth.json")
        finally:
            (home / "candidate.json").unlink(missing_ok=True)
            (home / "candidate.context").unlink(missing_ok=True)
        suffix = (" Earliest usage-limit retry is " +
                  sh("date", "-u", "-d", f"@{earliest}", "+%Y-%m-%dT%H:%M:%SZ", capture=True).stdout.strip() + "."
                  if earliest else "")
        raise RuntimeError("No eligible Codex review credentials: all are usage-limited or have an invalid refresh token."
                           + suffix + " Credentials with invalid refresh tokens must be replaced.")

    def snapshot(self, workspace, source, path):
        data = validate_auth(path)
        path.chmod(0o600)
        return AuthSnapshot(self, workspace.path, {
            "source": source, "original_hash": digest(path),
            "refresh_hash": hashlib.sha256(data["tokens"]["refresh_token"].encode()).hexdigest(),
        })


class AuthSnapshot:
    def __init__(self, pool, workspace, metadata):
        self.pool, self.workspace, self.metadata = pool, workspace, metadata

    def sync(self, *, canary=False):
        source = self.metadata["source"]
        path = self.workspace / "codex-home/auth.json"
        validate_auth(path)
        if digest(path) != self.metadata["original_hash"]:
            remote = self.workspace / "auth-current.json"
            transport = {} if canary else {"retry_times": 3, "connect_timeout": 10, "read_timeout": 30}
            try:
                self.pool.store.download(source, remote, **transport)
                if digest(remote) == self.metadata["original_hash"]:
                    self.pool.store.upload(path, source, **transport)
                elif canary:
                    raise RuntimeError("Auth changed concurrently; refusing to overwrite it.")
                else:
                    logging.warning("OSS auth changed; skipping stale writeback for %s", source.rsplit("/", 1)[-1])
            finally:
                remote.unlink(missing_ok=True)

    def record_invalid(self, reason):
        source = self.metadata["source"]
        path = self.workspace / "auth-failure.json"
        try:
            if reason not in AUTH_FAILURES:
                raise ValueError("Unsupported refresh failure")
            token_hash = self.metadata["refresh_hash"]
            write_json(path, {"version": 1, "state": "auth_invalid", "reason": reason,
                              "refresh_token_sha256": token_hash})
            self.pool.store.upload(path, source + ".invalid." + token_hash,
                                   retry_times=3, connect_timeout=10, read_timeout=30)
        finally:
            path.unlink(missing_ok=True)

    def record_cooldown(self, retry_after):
        path = self.workspace / "auth-context.json"
        try:
            write_json(path, {"version": 1, "state": "usage_limited", "retry_after_epoch": retry_after})
            self.pool.store.upload(path, self.metadata["source"] + ".context")
        finally:
            path.unlink(missing_ok=True)
