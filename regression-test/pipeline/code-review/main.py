#!/usr/bin/env python3
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

"""Forward a GitHub event to TeamCity, or run the review or status worker for one event."""

import argparse
import base64
import configparser
import json
import logging
import os
import re
import signal
import sys
import tempfile
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "lib"))

from process import Workspace, boolean, log_failure, sh, step
from review_github_api import GitHub, request_json
from review_runtime import AuthPool, ObjectStore, Runtime
from review_workflow import ReviewWorkflow
from status_workflow import BEGIN as LOCAL_REVIEW_MARKER
from status_workflow import StatusWorkflow

PR_EVENTS = {"opened", "synchronize", "reopened", "ready_for_review", "edited", "closed"}
REVIEW_ASSOCIATIONS = {"MEMBER", "OWNER", "COLLABORATOR"}
REVIEW_COMMAND = re.compile(r"/review(?=\s|$)", re.IGNORECASE)
MAX_EVENT_PARTS = 128
# Deployment configuration. TeamCity passes none of it, so it changes only through a PR here.
REPOSITORY = "apache/doris"
OSS = "oss://doris-community-ci"
REVIEW_DEFAULTS = {
    "repository-url": f"https://github.com/{REPOSITORY}.git",
    "model": "gpt-6.1-sol", "fallback-model": "gpt-6-sol", "effort": "xhigh",
    "oss-endpoint": "https://oss-cn-hongkong.aliyuncs.com",
    "auth-prefix": f"{OSS}/codex/auth.json.",
    "canary-auth-object": f"{OSS}/codex/auth.json.4",
    "codex-package": f"{OSS}/codex/releases/codex-exec-goal-0.162.1-3547e9086675-x86_64-unknown-linux-gnu.tar.gz",
    "codex-checksum": "51304e4f9c343ae84e00a304344df41c2fd32821c83bdbf5be68b0f0c25ddae1",
    "codex-version": "0.162.1",
    "codex-binary-checksum": "a0d5ec053074d66570aa967129d350541f344f76671a199b5a7bc0d45366cdf7",
    "memories-object": f"{OSS}/memories.tar.gz",
    "sessions-prefix": f"{OSS}/session",
    "telemetry-url": "https://litefuse.cloud",
    # Empty review-author means the login that owns the GitHub token.
    "review-author": "", "trusted-revision": "", "ossutil": "ossutil", "environment": "teamcity",
    "trace-name": "doris-ai-review", "subagent-trace-name": "doris-ai-review-subagent",
    "workflow-name": "Code Review Runner",
}
GITHUB_ENV = {"GH_TOKEN", "LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "REVIEW_GITHUB_DIAGNOSTICS_DIR",
              "GITHUB_RUN_ID", "GITHUB_JOB", "REVIEW_GH_VERSION"}


@dataclass(frozen=True)
class Event:
    name: str
    data: dict

    @property
    def inputs(self):
        return self.data.get("inputs", {})

    @property
    def comment(self):
        return self.data.get("comment", {})

    @property
    def body(self):
        return self.comment.get("body") or ""

    @property
    def is_pr_comment(self):
        return (self.name == "issue_comment" and self.data.get("action") == "created"
                and bool(self.data.get("issue", {}).get("pull_request")))

    @property
    def canary(self):
        return self.name == "workflow_dispatch" and boolean(self.inputs.get("runtime_canary", False))

    @property
    def review(self):
        if self.canary:
            return False
        if self.name == "workflow_dispatch":
            return bool(self.inputs.get("pr_number"))
        return (self.is_pr_comment and REVIEW_COMMAND.match(self.body) is not None
                and self.comment.get("author_association", "").upper() in REVIEW_ASSOCIATIONS)

    @property
    def focus(self):
        if self.name == "workflow_dispatch":
            return self.inputs.get("review_focus", "")
        return self.body[len("/review"):].strip()

    @property
    def pr_number(self):
        if self.name == "workflow_dispatch":
            return int(self.inputs["pr_number"])
        if self.name == "pull_request_target":
            return int(self.data["pull_request"]["number"])
        return int(self.data["issue"]["number"])

    @property
    def local_pass(self):
        return self.is_pr_comment and LOCAL_REVIEW_MARKER in self.body

    @property
    def skip(self):
        return self.is_pr_comment and not REVIEW_COMMAND.match(self.body) and "skip buildall" in self.body.lower()

    @property
    def status_heads(self):
        if self.name != "pull_request_target" or self.data.get("action") not in PR_EVENTS:
            return []
        head = self.data["pull_request"]["head"]["sha"]
        before = self.data.get("before")
        return [head, before] if self.data["action"] == "synchronize" and before and before != head else [head]

    def wanted(self, mode):
        """Whether the review or the sync worker acts on this event."""
        if mode == "review":
            return self.review or self.canary
        return self.local_pass or self.skip or bool(self.status_heads)


def event_snapshot(event):
    """Keep exactly the original fields consumed by the workflows.

    In particular, comment bodies are creation-event snapshots, not a later
    GitHub API read. Drop unused issue/PR bodies to bound the request size.
    """
    result = {"action": event.get("action"), "before": event.get("before"),
              "inputs": event.get("inputs", {}),
              "repository": {"full_name": event["repository"]["full_name"]},
              "sender": {"login": event.get("sender", {}).get("login")}}
    if "issue" in event:
        issue = event["issue"]
        result["issue"] = {"number": issue["number"], "pull_request": bool(issue.get("pull_request"))}
    if "comment" in event:
        comment = event["comment"]
        result["comment"] = {key: comment.get(key) for key in ("id", "body", "html_url", "author_association")}
        result["comment"]["user"] = {key: comment["user"][key] for key in ("id", "login")}
    if "pull_request" in event:
        pr = event["pull_request"]
        result["pull_request"] = {"number": pr["number"], "head": {"sha": pr["head"]["sha"]}}
    return result


def build_request(event, *, event_name, build_type, request_id, chunk_size):
    encoded = base64.b64encode(json.dumps(event_snapshot(event), ensure_ascii=False).encode()).decode("ascii")
    chunks = [encoded[index:index + chunk_size] for index in range(0, len(encoded), chunk_size)]
    if len(chunks) > MAX_EVENT_PARTS:
        raise ValueError(f"Event needs {len(chunks)} parameter chunks; the worker accepts {MAX_EVENT_PARTS}")
    properties = {
        "env.REVIEW_EVENT_NAME": event_name,
        "env.REVIEW_REQUEST_ID": request_id,
        "env.REVIEW_EVENT_PARTS": str(len(chunks)),
        **{f"env.REVIEW_EVENT_{index:04d}": chunk for index, chunk in enumerate(chunks)},
    }
    # No PR branch, revision, executable path or trusted-source override is sent.
    return {"buildType": {"id": build_type}, "properties": {
        "property": [{"name": name, "value": value} for name, value in properties.items()]
    }}


def enqueue(server, token, payload, *, timeout):
    request = urllib.request.Request(server.rstrip("/") + "/app/rest/buildQueue", data=json.dumps(payload).encode(),
                                     headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                                              "Accept": "application/json"}, method="POST")
    # Send once: a failed response does not mean TeamCity rejected the build.
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            build = json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"TeamCity enqueue failed with HTTP {error.code}; inspect its queue") from None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        raise RuntimeError("TeamCity acceptance could not be confirmed; inspect its queue") from None
    logging.info("TeamCity accepted build %s: %s", build.get("id"), build.get("webUrl", ""))


def forward(options):
    event = json.loads(options.event_file.read_text())
    # Filtering here keeps comments that the target build ignores off its agents.
    if not Event(options.event_name, event).wanted(options.mode):
        logging.info("Event needs no %s work; nothing to enqueue", options.mode)
        return 0
    payload = build_request(event, event_name=options.event_name, build_type=options.teamcity_build_type,
                            request_id=options.request_id, chunk_size=options.event_chunk_size)
    # The token comes from the environment so that it never appears in argv.
    token = secret_text(os.environ.pop("TEAMCITY_TOKEN", ""), "TEAMCITY_TOKEN")
    enqueue(options.teamcity_url, token, payload, timeout=options.http_timeout)
    return 0


def positive(value):
    result = int(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("Must be positive")
    return result


def secret_text(value, name):
    value = value.rstrip("\r\n")
    if not value or "\n" in value or "\r" in value:
        raise ValueError(f"Credential {name} must be one nonempty line of text")
    return value


def read_secret(path):
    return secret_text(Path(path).read_text(), Path(path).name)


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    forward_command = commands.add_parser("forward", help="Enqueue an event in TeamCity (token: $TEAMCITY_TOKEN)")
    common = argparse.ArgumentParser(add_help=False)

    def add(target, names, **config):
        """Register each whitespace-separated --name with the same configuration."""
        for name in names.split():
            target.add_argument("--" + name, **config)

    add(forward_command, "event-file", type=Path, required=True)
    add(forward_command, "event-name request-id teamcity-url teamcity-build-type", required=True)
    forward_command.add_argument("--mode", choices=("review", "sync"), required=True,
                                 help="Worker of the target build type")
    add(forward_command, "http-timeout", type=positive, default=30)
    add(forward_command, "event-chunk-size", type=positive, default=16000)
    add(common, "event-file", type=Path, required=True)
    add(common, "event-name request-id run-url run-id", required=True)
    add(common, "repository", default=REPOSITORY)
    add(common, "artifacts-dir", type=Path, default=Path("review-artifacts"))
    add(common, "github-token-file temp-dir", type=Path)
    add(common, "skip-policy", type=Path, default=ROOT / "skip-policy.json")
    add(common, "api-timeout", type=positive, default=60)
    add(common, "sync-timeout", type=positive, default=1200)
    commands.add_parser("sync", parents=[common], help="Validate local/skip events and aggregate status")
    review = commands.add_parser("review", parents=[common], help="Run review or runtime canary")
    add(review, "oss-access-key-file oss-secret-key-file", type=Path, required=True)
    add(review, "telemetry-public-key-file telemetry-secret-key-file", type=Path)
    add(review, "command-timeout oss-timeout", type=positive)
    for name, default in REVIEW_DEFAULTS.items():
        add(review, name, default=default)
    add(review, "templates", type=Path, default=ROOT / "prompts")
    limits = {"review-timeout": 7200, "cleanup-reserve": 120, "usage-limit-backoff": 1800,
              "context-threads": 30, "context-body-chars": 1200, "telemetry-max-bytes": 4000000,
              "canary-timeout": 180, "canary-step-timeout": 1080, "canary-job-timeout": 1500}
    # Step budgets in seconds; settings.kts must give the review build more than their sum.
    limits.update({name + "-timeout": seconds for name, seconds in {
        "resolve": 120, "status": 300, "checkout": 600, "install": 600, "verify": 120, "auth": 300,
        "memories": 300, "threads": 300, "context": 600, "diagnostics": 120, "record": 300,
        "telemetry": 300, "sessions": 300, "auth-sync": 480,
    }.items()})
    for name, default in limits.items():
        add(review, name, type=positive, default=default)
    return result


def configure_environment(options):
    env = dict(os.environ)
    if options.github_token_file:
        env["GH_TOKEN"] = read_secret(options.github_token_file)
    env["REVIEW_GH_VERSION"] = sh("gh", "--version", capture=True, timeout=options.api_timeout).stdout.splitlines()[0]
    # The diagnostics helper and Codex subprocesses share this explicit adapter.
    env.update(REVIEW_GITHUB_DIAGNOSTICS_DIR=str(options.artifacts_dir / "github-api"),
               GITHUB_RUN_ID=options.run_id, GITHUB_JOB=options.command)
    for flag, variable in (("telemetry_public_key_file", "LANGFUSE_PUBLIC_KEY"),
                           ("telemetry_secret_key_file", "LANGFUSE_SECRET_KEY")):
        path = getattr(options, flag, None)
        if path:
            env[variable] = read_secret(path)
    # In-process helpers read these from os.environ; redact() also learns the secrets from it.
    os.environ.update({key: value for key, value in env.items() if key in GITHUB_ENV})
    return env


@contextmanager
def object_store(options):
    with tempfile.TemporaryDirectory(prefix="review-secrets-", dir=options.temp_dir) as temporary:
        config_path = Path(temporary) / "ossutil.ini"
        config = configparser.ConfigParser(interpolation=None)
        config.optionxform = str
        config["Credentials"] = {"endpoint": options.oss_endpoint,
                                 "accessKeyID": read_secret(options.oss_access_key_file),
                                 "accessKeySecret": read_secret(options.oss_secret_key_file)}
        with config_path.open("w") as output:
            config.write(output)
        config_path.chmod(0o600)
        yield ObjectStore(options.ossutil, config_file=config_path, timeout=options.oss_timeout)


def validate(options, event):
    """Reject an unusable configuration before any credential or workspace is touched."""
    if event.data["repository"]["full_name"] != options.repository:
        raise ValueError("Event repository does not match the configured repository")
    if options.command != "review" or not event.wanted("review"):
        return
    if options.review_timeout <= options.cleanup_reserve:
        raise ValueError("Review timeout must exceed the cleanup reserve")
    if event.canary and not options.canary_auth_object:
        raise ValueError("Canary requires --canary-auth-object")
    if not event.canary and not options.trusted_revision:
        raise ValueError("Review requires --trusted-revision")


def run_worker(options):
    event = Event(options.event_name, json.loads(options.event_file.read_text()))
    validate(options, event)
    if not event.wanted(options.command):
        logging.info("Event needs no %s work", options.command)
        return 0
    options.artifacts_dir = options.artifacts_dir.resolve()
    options.artifacts_dir.mkdir(parents=True, exist_ok=True)
    if options.command == "review" and event.canary:
        # The canary uses OSS only; it receives no GitHub or telemetry credentials.
        with object_store(options) as store, Workspace(options.temp_dir) as workspace:
            return Runtime(options, store, AuthPool(store, options.auth_prefix), dict(os.environ)).canary(workspace)
    env = configure_environment(options)
    github = GitHub(options.repository, env=env, timeout=options.api_timeout)
    statuses = StatusWorkflow(github, run_url=options.run_url,
                              skip_policy=json.loads(options.skip_policy.read_text()))
    if options.command == "sync":
        with step("Synchronize review status", options.sync_timeout):
            statuses.synchronize(event)
        return 0
    if not options.review_author:
        options.review_author = request_json("user", env=env, timeout=options.api_timeout)["login"]
        logging.info("Reviewing as %s, the owner of the GitHub token", options.review_author)
    with object_store(options) as store, Workspace(options.temp_dir) as workspace:
        runtime = Runtime(options, store, AuthPool(store, options.auth_prefix), env)
        return ReviewWorkflow(options, github, statuses, runtime).run(event, workspace)


def cancel(_signum, _frame):
    raise KeyboardInterrupt


def main(argv=None):
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    options = parser().parse_args(argv)
    signal.signal(signal.SIGTERM, cancel)
    try:
        return forward(options) if options.command == "forward" else run_worker(options)
    except KeyboardInterrupt:
        logging.error("Build cancelled")
        return 130
    except Exception as error:
        log_failure(options.command, error)
        return 1


if __name__ == "__main__":
    sys.exit(main())
