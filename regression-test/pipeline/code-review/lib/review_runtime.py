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

import hashlib
import json
import logging
import os
import random
import re
import shutil
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

from process import environment, sh, step, write_json
from review_workflow import read_events, run_attempt
from telemetry import export


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

    def session_exists(self, source):
        # The original session step attempted upload whenever stat failed.
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
        if any(name not in {prefix, prefix + "/"} and not name.startswith(prefix + "/") for name in listing):
            raise ValueError(f"Archive contains content outside {prefix}")
    sh("tar", "-xzf", str(archive), "-C", str(destination))


def install_codex(store, directory, *, source, checksum, version):
    archive = directory / "codex-package.tar.gz"
    package = directory / "codex-package"
    store.download(source, archive)
    if digest(archive) != checksum:
        raise ValueError("Codex archive SHA256 does not match the configured package")
    package.mkdir()
    extract(archive, package)
    sh("sha256sum", "--check", "SHA256SUMS", cwd=package)
    if json.loads((package / "codex-package.json").read_text())["version"] != version:
        raise ValueError("Codex package version mismatch")
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
        listing = self.store.list(self.prefix)
        candidates = [item for item in listing
                      if re.fullmatch(re.escape(self.prefix) + r"[0-9]+", item)]
        if not candidates:
            raise RuntimeError("No numbered Codex review auth objects were found in OSS.")
        random.shuffle(candidates)
        earliest = None
        now = int(time.time())
        for candidate in candidates:
            retry = self.cooldown(candidate, home / "candidate.context")
            if retry > now:
                earliest = retry if earliest is None else min(earliest, retry)
                continue
            path = home / "candidate.json"
            self.store.download(candidate, path)
            data = validate_auth(path)
            refresh_hash = hashlib.sha256(data["tokens"]["refresh_token"].encode()).hexdigest()
            invalid = self.store.exists(candidate + ".invalid." + refresh_hash)
            if invalid:
                continue
            path.replace(home / "auth.json")
            logging.info("Selected auth snapshot %s", candidate.rsplit("/", 1)[-1])
            return self.snapshot(workspace, candidate, home / "auth.json")
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
            self.pool.store.download(source, remote, **transport)
            if digest(remote) == self.metadata["original_hash"]:
                self.pool.store.upload(path, source, **transport)
            elif canary:
                raise RuntimeError("Auth changed concurrently; refusing to overwrite it.")
            else:
                logging.warning("OSS auth changed; skipping stale writeback for %s", source.rsplit("/", 1)[-1])

    def record_invalid(self, reason):
        path = self.workspace / "auth-failure.json"
        token_hash = self.metadata["refresh_hash"]
        write_json(path, {"version": 1, "state": "auth_invalid", "reason": reason,
                          "refresh_token_sha256": token_hash})
        self.pool.store.upload(path, self.metadata["source"] + ".invalid." + token_hash,
                               retry_times=3, connect_timeout=10, read_timeout=30)

    def record_cooldown(self, retry_after):
        path = self.workspace / "auth-context.json"
        write_json(path, {"version": 1, "state": "usage_limited", "retry_after_epoch": retry_after})
        self.pool.store.upload(path, self.metadata["source"] + ".context")



class Runtime:
    def __init__(self, options, store, auth, env):
        self.options, self.store, self.auth, self.env = options, store, auth, env

    def install(self, workspace, *, canary=False):
        options = self.options
        with step("Install pinned Codex package", options.canary_job_timeout if canary else options.install_timeout):
            binary = install_codex(self.store, workspace.path,
                                   source=options.codex_package, checksum=options.codex_checksum,
                                   version=options.codex_version)
        env = {**self.env, "PATH": str(binary.parent) + os.pathsep + self.env.get("PATH", "")}
        home = workspace.path / "codex-home"
        home.mkdir(mode=0o700, exist_ok=True)
        env["CODEX_HOME"] = str(home)
        with step("Verify pinned Codex runtime", options.canary_job_timeout if canary else options.verify_timeout):
            if not canary and digest(binary) != options.codex_binary_checksum:
                raise ValueError("Codex binary SHA256 does not match the pinned runtime")
            sh(str(binary), "--version", env=env)
            help_text = sh(str(binary), "exec", "--help", env=env, capture=True).stdout
            if "--goal" not in help_text:
                raise ValueError("Codex runtime does not support --goal")
            if not canary:
                sh(str(binary), "exec", "--goal", "resume", "--help", env=env, capture=True)
        return env

    def configure(self, workspace, *, canary=False):
        home = workspace.path / "codex-home"
        # json quoting is also valid for these TOML basic string values.
        config = [
            'cli_auth_credentials_store = "file"', 'approval_policy = "never"',
            '[features]', 'memories = true', '[memories]',
            'use_memories = true', 'generate_memories = true',
        ]
        if not canary:
            config += ['[shell_environment_policy]', 'inherit = "all"']
        config += ['[otel]', 'environment = ' + json.dumps(self.options.environment),
                   'exporter = "none"', 'metrics_exporter = "none"', 'trace_exporter = "none"', '']
        (home / "config.toml").write_text("\n".join(config))
        (home / "config.toml").chmod(0o600)

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
            if not self.store.session_exists(remote):
                self.store.upload(path, remote)

    def diagnostics(self, context):
        # Never copy CODEX_HOME/auth.json or the entire private workspace.
        output = self.options.artifacts_dir / "review"
        output.mkdir(parents=True, exist_ok=True)
        for name in ("review-submission.json", "review-submission-rejected.json"):
            source = context / name
            if source.exists():
                shutil.copyfile(source, output / name)

    def telemetry(self, context, home, target, *, superseded):
        if not self.options.telemetry_url:
            return
        inputs = [context / name for name in ("codex_goal_prompt.txt", "codex-events.jsonl")]
        if not all(path.exists() and path.stat().st_size for path in inputs):
            return
        model = context / "codex-review-model.txt"
        options = SimpleNamespace(**{**vars(self.options),
            "model": model.read_text().strip() if model.exists() else self.options.model})
        export(options, context, home, target, self.env)



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
