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

"""Codex runtime: object storage, pinned package, credential pool, memories and the canary."""

import hashlib
import json
import logging
import os
import random
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from process import read_jsonl, require, sh, step, supervise, write_json
from submit_review import REJECTION_FILE, SUBMISSION_FILE
from telemetry import Exporter

# Informational only: a regression on the previous model does not fail the canary.
CANARY_PRIOR_MODEL = "gpt-5.6-sol"
TRANSPORT = {"retry_times": 3, "connect_timeout": 10, "read_timeout": 30}


class ObjectStore:
    def __init__(self, executable, *, config_file, timeout=None):
        self.command = (executable, "-c", str(config_file))
        self.timeout = timeout

    def _run(self, *arguments, capture=True, **transport):
        flags = [f"--{key.replace('_', '-')}={value}" for key, value in transport.items()]
        return sh(*self.command, *flags, *arguments, timeout=self.timeout, capture=capture)

    def list(self, prefix):
        lines = self._run("ls", prefix, "-s").stdout.splitlines()
        return [line.strip() for line in lines if line.strip().startswith("oss://")]

    def download(self, source, destination, *, optional=False, **transport):
        try:
            self._run("cp", "-f", source, str(destination), **transport)
            return True
        except subprocess.CalledProcessError:
            if not optional:
                raise
            return False

    def upload(self, source, destination, **transport):
        self._run("cp", "-f", str(source), destination, **transport)

    def exists(self, source):
        return source in self.list(source)

    def stat_exists(self, source):
        """Existence by stat; any stat failure counts as missing, so the caller uploads again."""
        try:
            self._run("stat", source)
            return True
        except subprocess.CalledProcessError:
            return False


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def extract(archive, destination, *, prefix=None):
    if prefix is not None:
        listing = sh("tar", "-tzf", str(archive), capture=True).stdout.splitlines()
        require(all(name in {prefix, prefix + "/"} or name.startswith(prefix + "/") for name in listing),
                f"Archive contains content outside {prefix}")
    sh("tar", "-xzf", str(archive), "-C", str(destination))


def install_codex(store, directory, *, source, checksum, version):
    archive, package = directory / "codex-package.tar.gz", directory / "codex-package"
    store.download(source, archive)
    require(digest(archive) == checksum, "Codex archive SHA256 does not match the configured package")
    package.mkdir()
    extract(archive, package)
    sh("sha256sum", "--check", "SHA256SUMS", cwd=package)
    require(json.loads((package / "codex-package.json").read_text())["version"] == version,
            "Codex package version mismatch")
    return package / "bin/codex"


def restore_memories(store, source, home):
    archive = home / "memories.tar.gz"
    try:
        if store.download(source, archive, optional=True) and archive.stat().st_size:
            extract(archive, home, prefix="memories")
        else:
            logging.info("No memories archive available; continuing with empty memories")
    finally:
        archive.unlink(missing_ok=True)
    memories = home / "memories"
    memories.mkdir(mode=0o700, exist_ok=True)
    (memories / "memory_summary.md").touch(exist_ok=True)
    sh("chmod", "-R", "go-rwx", str(memories), check=False)


def validate_auth(path):
    data = json.loads(Path(path).read_text())
    require(isinstance(data, dict) and data.get("auth_mode") == "chatgpt", "Expected ChatGPT credentials")
    tokens = data.get("tokens")
    for key in ("access_token", "refresh_token"):
        token = tokens.get(key) if isinstance(tokens, dict) else None
        require(isinstance(token, str) and token, f"Auth snapshot is missing {key}")
    return data


def refresh_hash(data):
    return hashlib.sha256(data["tokens"]["refresh_token"].encode()).hexdigest()


def utc(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def name(source):
    return source.rsplit("/", 1)[-1]


class AuthPool:
    """Numbered auth snapshots in OSS, excluding usage-limited and invalidated ones."""

    def __init__(self, store, prefix):
        self.store, self.prefix = store, prefix

    def cooldown(self, source, destination):
        """The epoch before which this account must not be used; 0 when unrestricted or unreadable."""
        if not self.store.download(source + ".context", destination, optional=True):
            return 0
        try:
            data = json.loads(destination.read_text())
            retry = data["retry_after_epoch"]
            require(data["version"] == 1 and data["state"] == "usage_limited" and type(retry) is int,
                    "Invalid cooldown")
            utc(retry)  # Rejects an out-of-range epoch.
            return retry
        except (ValueError, KeyError, TypeError, OverflowError, OSError):
            logging.warning("Ignoring unusable account cooldown for %s", name(source))
            return 0

    def acquire(self, workspace, *, source=None):
        home = workspace.path / "codex-home"
        home.mkdir(mode=0o700, exist_ok=True)
        auth = home / "auth.json"
        if source:
            # The canary reads its configured snapshot directly, without selection.
            self.store.download(source, auth)
            return self.snapshot(workspace, source, auth)
        candidates = [item for item in self.store.list(self.prefix)
                      if re.fullmatch(re.escape(self.prefix) + r"[0-9]+", item)]
        if not candidates:
            raise RuntimeError("No numbered Codex review auth objects were found in OSS.")
        random.shuffle(candidates)
        earliest, now = None, int(time.time())
        path = home / "candidate.json"
        for candidate in candidates:
            retry = self.cooldown(candidate, home / "candidate.context")
            if retry > now:
                earliest = min(earliest or retry, retry)
                continue
            self.store.download(candidate, path)
            try:
                data = validate_auth(path)
            except ValueError as error:
                logging.warning("Skipping unusable auth snapshot %s: %s", name(candidate), error)
                continue
            if self.store.exists(f"{candidate}.invalid.{refresh_hash(data)}"):
                continue
            path.replace(auth)
            (home / "candidate.context").unlink(missing_ok=True)
            logging.info("Selected auth snapshot %s", name(candidate))
            return self.snapshot(workspace, candidate, auth)
        path.unlink(missing_ok=True)
        retry = f" Earliest usage-limit retry is {utc(earliest)}." if earliest else ""
        raise RuntimeError("No eligible Codex review credentials: all are usage-limited, unreadable or have an "
                           f"invalid refresh token.{retry} Credentials with invalid refresh tokens must be replaced.")

    def snapshot(self, workspace, source, path):
        data = validate_auth(path)
        path.chmod(0o600)
        return AuthSnapshot(self.store, workspace.path, source, digest(path), refresh_hash(data))


class AuthSnapshot:
    """The credential this build uses, and its write-back after Codex refreshed it."""

    def __init__(self, store, workspace, source, original_hash, refresh):
        self.store, self.workspace, self.source = store, workspace, source
        self.original_hash, self.refresh = original_hash, refresh

    def sync(self, *, canary=False):
        path = self.workspace / "codex-home/auth.json"
        validate_auth(path)
        if digest(path) == self.original_hash:
            return
        remote, transport = self.workspace / "auth-current.json", {} if canary else TRANSPORT
        self.store.download(self.source, remote, **transport)
        if digest(remote) == self.original_hash:
            self.store.upload(path, self.source, **transport)
        elif canary:
            raise RuntimeError("Auth changed concurrently; refusing to overwrite it.")
        else:
            logging.warning("OSS auth changed; skipping stale writeback for %s", name(self.source))

    def record_invalid(self, reason):
        path = self.workspace / "auth-failure.json"
        write_json(path, {"version": 1, "state": "auth_invalid", "reason": reason,
                          "refresh_token_sha256": self.refresh})
        self.store.upload(path, f"{self.source}.invalid.{self.refresh}", **TRANSPORT)

    def record_cooldown(self, retry_after):
        path = self.workspace / "auth-context.json"
        write_json(path, {"version": 1, "state": "usage_limited", "retry_after_epoch": retry_after})
        self.store.upload(path, self.source + ".context")


class Runtime:
    def __init__(self, options, store, auth, env):
        self.options, self.store, self.auth, self.env = options, store, auth, env

    def install(self, workspace, *, canary=False):
        """Install the pinned package and return the environment that runs it."""
        options = self.options
        with step("Install pinned Codex package", options.install_timeout):
            binary = install_codex(self.store, workspace.path, source=options.codex_package,
                                   checksum=options.codex_checksum, version=options.codex_version)
        home = workspace.path / "codex-home"
        home.mkdir(mode=0o700, exist_ok=True)
        env = {**self.env, "PATH": str(binary.parent) + os.pathsep + self.env.get("PATH", ""), "CODEX_HOME": str(home)}
        with step("Verify pinned Codex runtime", options.verify_timeout):
            # The canary vets a staged package before its binary checksum is pinned.
            if not canary:
                require(digest(binary) == options.codex_binary_checksum,
                        "Codex binary SHA256 does not match the pinned runtime")
            sh(str(binary), "--version", env=env)
            require("--goal" in sh(str(binary), "exec", "--help", env=env, capture=True).stdout,
                    "Codex runtime does not support --goal")
            if not canary:
                sh(str(binary), "exec", "--goal", "resume", "--help", env=env, capture=True)
        return env

    def configure(self, workspace, *, canary=False):
        config = [
            'cli_auth_credentials_store = "file"', 'approval_policy = "never"',
            '[features]', 'memories = true', '[memories]', 'use_memories = true', 'generate_memories = true',
        ]
        if not canary:
            config += ['[shell_environment_policy]', 'inherit = "all"']
        # JSON quoting is also valid for these TOML basic string values.
        config += ['[otel]', 'environment = ' + json.dumps(self.options.environment),
                   'exporter = "none"', 'metrics_exporter = "none"', 'trace_exporter = "none"', '']
        path = workspace.path / "codex-home/config.toml"
        path.write_text("\n".join(config))
        path.chmod(0o600)

    def memories(self, workspace):
        if self.options.memories_object:
            restore_memories(self.store, self.options.memories_object, workspace.path / "codex-home")

    def sessions(self, home):
        if not self.options.sessions_prefix:
            return
        sessions = home / "sessions"
        for path in sessions.rglob("*.jsonl"):
            if path.is_symlink() or not path.is_file():
                continue
            remote = self.options.sessions_prefix.rstrip("/") + "/" + path.relative_to(sessions).as_posix()
            if not self.store.stat_exists(remote):
                self.store.upload(path, remote)

    def diagnostics(self, context):
        # Never copy CODEX_HOME/auth.json or the entire private workspace.
        output = self.options.artifacts_dir / "review"
        output.mkdir(parents=True, exist_ok=True)
        for file_name in (SUBMISSION_FILE, REJECTION_FILE):
            if (context / file_name).exists():
                shutil.copyfile(context / file_name, output / file_name)

    def telemetry(self, context, home, target):
        if not self.options.telemetry_url:
            return
        if not all((context / file_name).is_file() and (context / file_name).stat().st_size
                   for file_name in ("codex_goal_prompt.txt", "codex-events.jsonl")):
            return
        model = context / "codex-review-model.txt"
        model = model.read_text().strip() if model.exists() else self.options.model
        Exporter(self.options, self.env, model=model).export(context, home, target)

    def canary(self, workspace):
        """Check model access and goal mode of the staged runtime; exit status 0 when every required probe passes."""
        options = self.options
        env = None  # Set below to the installed runtime's environment, without GitHub credentials.

        def probe(label, model, effort, *, goal=False):
            prefix = workspace.path / f"codex-canary-{label}"
            events, stderr, output = (prefix.with_suffix(suffix) for suffix in (".jsonl", ".stderr", ".txt"))
            command = ["codex", "exec", "--skip-git-repo-check", "--json", "--model", model,
                       "--config", f"model_reasoning_effort={effort}", "--sandbox", "read-only",
                       "--color", "never", "--output-last-message", str(output)] + (["--goal"] if goal else [])
            command.append(("Create a goal to reply OK, mark it complete, then reply OK. " if goal
                            else "Reply with exactly OK. ") + "Do not access files or external services.")
            try:
                code = supervise(command, events, stderr, options.canary_timeout, reaper=workspace.reaper, env=env)
            except subprocess.TimeoutExpired:
                code = None
            logging.info("%s: exit_status=%s", label, code)
            return code == 0 and any(event.get("type") == "turn.completed" for event in read_jsonl(events))

        with step("Runtime canary", options.canary_job_timeout):
            env = {key: value for key, value in self.install(workspace, canary=True).items()
                   if key not in {"GH_TOKEN", "GITHUB_TOKEN"}}
            snapshot = self.auth.acquire(workspace, source=options.canary_auth_object)
            self.configure(workspace, canary=True)
            try:
                with step("Test ChatGPT model access and goal mode", options.canary_step_timeout):
                    fallback = probe("fallback", options.fallback_model, "low")
                    prior = probe("prior", CANARY_PRIOR_MODEL, "low")
                    fallback_goal = fallback and probe("fallback-goal", options.fallback_model, "low", goal=True)
                    primary = probe("primary", options.model, options.effort)
                    primary_goal = primary and probe("primary-goal", options.model, options.effort, goal=True)
                    # 0 marks a passed probe, matching the canary's summary format.
                    logging.info("model_canary: %s=%d %s=%d %s-goal=%d %s-%s=%d %s-%s-goal=%d",
                                 options.fallback_model, not fallback, CANARY_PRIOR_MODEL, not prior,
                                 options.fallback_model, not fallback_goal, options.model, options.effort,
                                 not primary, options.model, options.effort, not primary_goal)
            finally:
                # Unlike a normal review, a concurrent credential change fails the canary.
                snapshot.sync(canary=True)
        return int(not (fallback and fallback_goal and primary and primary_goal))
