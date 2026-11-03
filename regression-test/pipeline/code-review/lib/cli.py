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

"""Explicit command-line configuration for CI-independent workflows."""

import argparse
import configparser
import json
import logging
import os
import signal
import tempfile
from contextlib import ExitStack, contextmanager
from pathlib import Path

from auth_pool import AuthPool
from events import Event
from forward import build_request, enqueue
from github_client import GitHub
from lifecycle import Workspace
from locking import Locks
from object_store import ObjectStore
from process import sh, step
from review_runtime import Runtime
from review_workflow import ReviewWorkflow
from review_github_api import redact
from status_workflow import StatusWorkflow


ROOT = Path(__file__).resolve().parents[1]


def positive(value):
    result = int(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("Must be positive")
    return result


def read_secret(path):
    value = Path(path).read_text().rstrip("\r\n")
    if not value or "\n" in value or "\r" in value:
        raise ValueError("Credential file must contain one nonempty line of text")
    return value


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    forwarding = commands.add_parser("forward", help="Only enqueue an event in TeamCity")
    forwarding.add_argument("--event-file", type=Path, required=True)
    forwarding.add_argument("--event-name", required=True)
    forwarding.add_argument("--request-id", required=True)
    forwarding.add_argument("--origin-url", required=True)
    forwarding.add_argument("--teamcity-url", required=True)
    forwarding.add_argument("--teamcity-build-type", required=True)
    forwarding.add_argument("--teamcity-token-file", type=Path, required=True)
    forwarding.add_argument("--http-timeout", type=positive, default=30)
    forwarding.add_argument("--event-chunk-size", type=positive, default=16000)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--event-file", type=Path, required=True)
    common.add_argument("--event-name", required=True)
    common.add_argument("--repository", required=True)
    common.add_argument("--github-token-file", type=Path,
                        help="Token text file; otherwise use the existing gh login")
    common.add_argument("--dry-run", action="store_true",
                        help="Read live services but simulate GitHub/OSS writes locally; never upload telemetry")
    common.add_argument("--request-id", required=True)
    common.add_argument("--run-url", required=True)
    common.add_argument("--run-id", required=True)
    common.add_argument("--state-root", type=Path, required=True,
                        help="Shared writable host directory, mounted identically into all agents")
    common.add_argument("--artifacts-dir", type=Path, required=True)
    common.add_argument("--skip-policy", type=Path, default=ROOT / "skip-policy.json")
    common.add_argument("--api-timeout", type=positive,
                        help="Optional per-call limit; workflow steps enforce their original overall budgets")
    common.add_argument("--sync-timeout", type=positive, default=21600)
    common.add_argument("--lock-timeout", type=positive, default=14400)
    common.add_argument("--temp-dir", type=Path, help="Build-private directory managed/cleaned by the CI agent")
    commands.add_parser("sync", parents=[common], help="Validate local/skip events and aggregate status")
    review = commands.add_parser("review", parents=[common], help="Execute automated review or runtime canary")
    review.add_argument("--repository-url", required=True)
    review.add_argument("--trusted-revision", default="")
    review.add_argument("--review-author", default="")
    review.add_argument("--model", default="gpt-6.1-sol")
    review.add_argument("--fallback-model", default="gpt-6-sol")
    review.add_argument("--effort", default="xhigh")
    review.add_argument("--review-timeout", type=positive, default=7200)
    review.add_argument("--cleanup-reserve", type=positive, default=120)
    review.add_argument("--command-timeout", type=positive,
                        help="Optional per-command limit in addition to the workflow step budget")
    for name, seconds in {
        "resolve": 120, "status": 120, "checkout": 600, "install": 600, "verify": 120,
        "auth": 300, "memories": 300, "threads": 300, "focus": 120, "context": 600,
        "prompt": 300, "diagnostics": 120, "record": 300, "sessions": 300, "auth-sync": 480,
    }.items():
        review.add_argument(f"--{name}-timeout", type=positive, default=seconds)
    review.add_argument("--usage-limit-backoff", type=positive, default=1800)
    review.add_argument("--context-threads", type=positive, default=30)
    review.add_argument("--context-body-chars", type=positive, default=1200)
    review.add_argument("--templates", type=Path, default=ROOT / "prompts")
    review.add_argument("--ossutil", default="ossutil")
    review.add_argument("--oss-endpoint")
    review.add_argument("--oss-access-key-file", type=Path)
    review.add_argument("--oss-secret-key-file", type=Path)
    review.add_argument("--rclone", default="rclone", help="Read-only OSS transport for --dry-run")
    review.add_argument("--rclone-remote", default="oss:")
    review.add_argument("--rclone-endpoint", help="Optional S3 endpoint override for local reads")
    review.add_argument("--local-codex-loader", type=Path,
                        help="Optional isolated ELF loader for --dry-run on older Linux hosts")
    review.add_argument("--local-codex-library-path", type=Path)
    review.add_argument("--oss-timeout", type=positive, help="Optional per-command limit")
    review.add_argument("--auth-prefix", required=True)
    review.add_argument("--codex-package", required=True)
    review.add_argument("--codex-checksum", required=True)
    review.add_argument("--codex-binary-checksum", default="a0d5ec053074d66570aa967129d350541f344f76671a199b5a7bc0d45366cdf7")
    review.add_argument("--codex-version", required=True)
    review.add_argument("--memories-object", default="")
    review.add_argument("--sessions-prefix", default="")
    review.add_argument("--telemetry-url", default="")
    review.add_argument("--telemetry-public-key-file", type=Path)
    review.add_argument("--telemetry-secret-key-file", type=Path)
    review.add_argument("--telemetry-timeout", type=positive, default=300)
    review.add_argument("--telemetry-max-bytes", type=positive, default=4000000)
    review.add_argument("--trace-name", default="doris-ai-review")
    review.add_argument("--subagent-trace-name", default="doris-ai-review-subagent")
    review.add_argument("--environment", default="teamcity")
    review.add_argument("--workflow-name", default="Code Review Runner")
    review.add_argument("--canary-auth-object", default="")
    review.add_argument("--canary-case", action="append",
                        help="Ordered LABEL:MODEL:EFFORT:plain|goal; every case must pass")
    review.add_argument("--canary-timeout", type=positive, default=180)
    review.add_argument("--canary-step-timeout", type=positive, default=1080)
    review.add_argument("--canary-job-timeout", type=positive, default=1500)
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
    os.environ.update({key: value for key, value in env.items() if key in {
        "GH_TOKEN", "LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "REVIEW_GITHUB_DIAGNOSTICS_DIR",
        "GITHUB_RUN_ID", "GITHUB_JOB", "REVIEW_GH_VERSION",
    }})
    return env


@contextmanager
def object_store(options):
    if options.dry_run:
        from local_services import ReadOnlyObjectStore
        yield ReadOnlyObjectStore(options)
        return
    if not all((options.oss_endpoint, options.oss_access_key_file, options.oss_secret_key_file)):
        raise ValueError("Live review requires --oss-endpoint, --oss-access-key-file and --oss-secret-key-file")
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


def run_worker(options):
    with ExitStack() as stack:
        return _run_worker(options, stack)


def _run_worker(options, stack):
    event = Event(options.event_name, json.loads(options.event_file.read_text()))
    if event.data["repository"]["full_name"] != options.repository:
        raise ValueError("Event repository does not match the configured repository")
    if options.command == "review" and not (event.review or event.canary):
        logging.info("Event does not request an authorized automated review")
        return 0
    if not options.state_root.is_absolute():
        raise ValueError("--state-root must be the shared absolute host path")
    options.state_root = options.state_root.resolve()
    if options.dry_run:
        options.state_root /= "dry-run"
    options.artifacts_dir = options.artifacts_dir.resolve()
    options.artifacts_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ) if event.canary else configure_environment(options)
    if options.dry_run:
        from local_services import LocalGitHub
        local = stack.enter_context(LocalGitHub(options, env))
        env = local.environment(env)
        options.local_gateway = local
    github = GitHub(options.repository, env=env, timeout=options.api_timeout)
    locks = Locks(options.state_root / "locks", timeout=options.lock_timeout)
    statuses = StatusWorkflow(github, locks, run_url=options.run_url,
                              skip_policy=json.loads(options.skip_policy.read_text()))
    if options.command == "sync":
        with step("Synchronize review status", options.sync_timeout):
            statuses.synchronize(event)
        return 0
    if options.review_timeout <= options.cleanup_reserve:
        raise ValueError("Review timeout must exceed the cleanup reserve")
    with object_store(options) as store:
        auth = AuthPool(store, options.auth_prefix)
        runtime = Runtime(options, store, auth, env)
        with Workspace(options.temp_dir) as workspace:
            if event.canary:
                if not options.canary_auth_object:
                    raise ValueError("Canary requires --canary-auth-object")
                if options.canary_case is None:
                    options.canary_case = ["sol:gpt-6-sol:low:plain", "prior-sol:gpt-5.6-sol:low:plain",
                                           "sol-goal:gpt-6-sol:low:goal", "sol61:gpt-6.1-sol:xhigh:plain",
                                           "sol61-goal:gpt-6.1-sol:xhigh:goal"]
                from canary import run_canary
                return run_canary(options, runtime, workspace)
            if not options.review_author or not options.trusted_revision:
                raise ValueError("Review requires --review-author and --trusted-revision")
            with locks.hold("pull-requests", f"{options.repository}:{event.pr_number}"):
                return ReviewWorkflow(options, github, statuses, runtime).run(event, workspace)


def main(argv=None):
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    options = parser().parse_args(argv)

    def cancelled(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, cancelled)
    try:
        if options.command == "forward":
            payload = build_request(json.loads(options.event_file.read_text()), event_name=options.event_name,
                                    build_type=options.teamcity_build_type, request_id=options.request_id,
                                    origin_url=options.origin_url, chunk_size=options.event_chunk_size)
            enqueue(options.teamcity_url, read_secret(options.teamcity_token_file), payload,
                    timeout=options.http_timeout)
            return 0
        return run_worker(options)
    except KeyboardInterrupt:
        logging.error("Build cancelled")
        return 130
    except Exception as error:
        # Never stringify subprocess argv or a credential parsing exception.
        logging.error("%s failed (%s): %s", options.command, type(error).__name__, redact(str(error)))
        return 1
