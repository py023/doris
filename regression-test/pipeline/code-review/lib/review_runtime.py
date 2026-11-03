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

"""Tool preparation and auxiliary outputs, kept out of review policy."""

import json
import logging
import os
import shutil
import sys
from pathlib import Path

from packages import digest, install_codex, restore_memories
from process import sh, step


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
        for name in ("review-submission.json", "review-submission-rejected.json", "review-api-errors.jsonl"):
            source = context / name
            if source.exists():
                shutil.copyfile(source, output / name)

    def telemetry(self, context, home, target, *, superseded):
        options = self.options
        if not options.telemetry_url:
            logging.info("Telemetry is disabled (no telemetry URL configured)")
            return
        prompt, events = context / "codex_goal_prompt.txt", context / "codex-events.jsonl"
        if not prompt.exists() or not events.exists() or not prompt.stat().st_size or not events.stat().st_size:
            return
        model_path = context / "codex-review-model.txt"
        model = model_path.read_text().strip() if model_path.exists() else options.model
        sh(sys.executable, str(Path(__file__).with_name("emit_litefuse_otel_io.py")),
           "--base-url", options.telemetry_url, "--input-file", str(prompt),
           "--events-file", str(events), "--output-file", str(context / "codex-final-message.txt"),
           "--trace-name", options.trace_name, "--subagent-trace-name", options.subagent_trace_name,
           "--subagent-sessions-dir", str(home / "sessions"), "--session-id", options.request_id,
           "--repository", options.repository, "--workflow", options.workflow_name,
           "--run-id", options.run_id, "--pr-number", str(target["number"]),
           "--head-sha", target["head"], "--base-sha", target["base"], "--model", model,
           "--reasoning-effort", options.effort, "--environment", options.environment,
           "--gzip", "--max-payload-bytes", str(options.telemetry_max_bytes),
           "--min-observations", "1" if superseded else "4",
           "--min-step-observations", "0" if superseded else "2",
           env=self.env, timeout=options.telemetry_timeout)
