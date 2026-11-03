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

"""Review execution, recovery, verdict handling and finalization."""

import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from process import boolean, environment, require, require_full_sha, step, write_json
from review_context import checkout, prepare, render_prompt
from review_github_api import redact, request_json
from submit_review import RESULT_FILE, RUN_FILE, SUBMISSION_FILE, verify_completion

CAPACITY_MESSAGE = 'Selected model is at capacity. Please try a different model.'
SUPERSEDED_EXIT_CODE = 75


class ReviewSuperseded(Exception):
    def __init__(self, head_sha):
        self.head_sha = head_sha
        super().__init__(f'PR head changed to {head_sha}; stopping superseded review')


def check_head(pr, expected):
    head = pr['head']['sha']
    require_full_sha('PR head', head)
    if head != expected:
        raise ReviewSuperseded(head)


class HeadWatchdog:
    def __init__(self, args, remaining):
        self.args, self.remaining, self.next_check = args, remaining, 0

    def check(self, *, force=False):
        if not force and time.monotonic() < self.next_check:
            return
        self.next_check = time.monotonic() + 60
        try:
            pr = request_json(f'repos/{self.args.repository}/pulls/{self.args.pr_number}',
                              timeout=min(10, self.remaining()))
            check_head(pr, self.args.head_sha)
        except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
            # An unavailable API is not evidence of a new head. Submission still checks strictly.
            logging.warning('PR head check unavailable (%s); keeping current review', type(error).__name__)

    def wait(self, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.check()
            delay = min(deadline - time.monotonic(), self.remaining(), self.next_check - time.monotonic())
            time.sleep(max(0, delay))


def read_events(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def append_event(path, value):
    with path.open('a') as handle:
        handle.write(json.dumps(value) + '\n')


def attempt_result(events, status, stderr):
    terminal = next((e for e in reversed(events)
                     if e['type'] in {'turn.started', 'turn.completed', 'turn.failed', 'error'}), {})
    kind = terminal.get('type', 'missing')
    if kind == 'turn.completed':
        return None if status == 0 else f'Codex exited with status {status} after turn.completed'
    if kind in {'turn.failed', 'error'}:
        return (terminal.get('error') or terminal).get('message') or f'Codex reported {kind} (exit status {status})'
    if status == 0:
        return 'Codex exited with status 0 without a terminal turn event; review is incomplete'
    return next((line for line in reversed(stderr.read_text().splitlines()) if line.strip()),
                f'Codex exited with status {status}')


def session_id(events):
    ids = [event['thread_id'] for event in events if event['type'] == 'thread.started']
    require(len(ids) == 1, 'Expected exactly one main thread.started event')
    require(str(uuid.UUID(ids[0])) == ids[0], 'Main session ID is not a canonical UUID')
    return ids[0]


def require_rollout(home, thread, cwd):
    for path in (home / 'sessions').rglob(f'*{thread}.jsonl'):
        with path.open() as handle:
            meta = json.loads(handle.readline())
        payload = meta['payload']
        if meta['type'] == 'session_meta' and payload['id'] == thread and Path(payload['cwd']).resolve() == cwd.resolve():
            return
    raise ValueError('Main session rollout is missing; refusing to start a new review')


def run_attempt(command, events_path, stderr_path, timeout, *, reaper, watchdog=None):
    # A file-backed stderr stream avoids a copier thread and its cancellation/join races.
    with events_path.open('w') as stdout, stderr_path.open('w') as stderr, stderr_path.open(errors="replace") as reader:
        process = None
        try:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
            deadline = time.monotonic() + timeout if timeout is not None else float('inf')
            while True:
                if watchdog:
                    watchdog.check()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                try:
                    return process.wait(timeout=min(1, remaining))
                except subprocess.TimeoutExpired:
                    sys.stderr.write(reader.read())
                    sys.stderr.flush()
        finally:
            # Defer cancellation until Codex and adopted descendants have been reaped.
            previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
            try:
                try:
                    if process is not None:
                        try:
                            process.send_signal(signal.SIGINT)
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            pass
                        finally:
                            process.kill()
                            process.wait()
                finally:
                    reaper.reap()
                    sys.stderr.write(reader.read())
                    sys.stderr.flush()
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def check_resume_target(args, started, remaining):
    root = f'repos/{args.repository}/pulls/{args.pr_number}'
    pr = request_json(root, timeout=min(30, remaining()))
    check_head(pr, args.head_sha)
    require(pr['state'] == 'open' and pr['base']['sha'] == args.base_sha, 'PR changed; refusing stale resume')
    reviews = request_json(root + '/reviews', pages=True, timeout=min(30, remaining()))
    require(not any(r.get('user', {}).get('login') == args.review_author and r.get('commit_id') == args.head_sha
                    and (r.get('submitted_at') or '') >= started for r in reviews),
            'A bot review was already submitted during this run; refusing duplicate resume')


def preserve_attempt(events, stderr, output, context):
    if events.exists():
        for line in events.read_text().splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue  # Cancellation can leave a partial last line; the raw attempt is retained.
            append_event(context / 'codex-events.jsonl', event)
    if stderr.exists():
        with (context / 'codex-stderr.log').open('a') as handle:
            handle.write(stderr.read_text(errors='replace') + '\n')
    if output.exists():
        shutil.copyfile(output, context / 'codex-final-message.txt')


def run_review(args, reaper):
    context = args.context_dir
    aggregate, final = context / 'codex-events.jsonl', context / 'codex-final-message.txt'
    attempts = context / 'codex-attempts'
    attempts.mkdir()
    aggregate.touch()
    (context / 'codex-stderr.log').touch()
    prompt = (context / 'codex_goal_prompt.txt').read_text()
    deadline = time.monotonic() + args.budget_seconds
    run = dict(repository=args.repository, pr_number=args.pr_number, head_sha=args.head_sha, base_sha=args.base_sha,
               started_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), token=str(uuid.uuid4()),
               deadline=deadline, review_author=args.review_author)
    write_json(context / RUN_FILE, run)
    thread, model, retries, attempt = None, args.model, 0, 0

    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise TimeoutError('Review shared time budget exhausted')
        return seconds

    def fail(message):
        logging.error('%s', message)
        append_event(aggregate, {'type': 'turn.failed', 'source': 'review-resume-runner', 'error': {'message': message}})
        return 1, {}

    watchdog = HeadWatchdog(args, remaining)
    try:
        while True:
            (context / 'codex-review-model.txt').write_text(model + '\n')
            watchdog.check(force=True)
            attempt += 1
            events, stderr, output = (attempts / f'{attempt}{suffix}' for suffix in ('.jsonl', '.stderr.log', '.final.txt'))
            final.write_text('')
            command = ['codex', 'exec', '--goal', '--cd', str(args.cwd), '--model', model, '--config',
                       f'model_reasoning_effort={args.effort}', '--sandbox', 'danger-full-access', '--color', 'never',
                       '--json', '--output-last-message', str(output)]
            command += ['resume', thread, resume_prompt(prompt)] if thread else [prompt]
            logging.info('Review attempt %s: model=%s, session=%s, remaining=%.0fs', attempt, model, thread, remaining())
            try:
                status = run_attempt(command, events, stderr, remaining(), reaper=reaper, watchdog=watchdog)
            finally:
                preserve_attempt(events, stderr, output, context)
            watchdog.check(force=True)
            events = read_events(events)
            if status < 0 or status in (124, 130, 137, 143):
                return fail(f'Codex was interrupted or timed out (status {status}); not resuming')
            message = attempt_result(events, status, stderr)
            logging.info('Review attempt %s exited %s: %s', attempt, status, message or 'completed')
            unsupported = f"The '{model}' model is not supported when using Codex with a ChatGPT account."
            began = any(e['type'] == 'turn.completed' or e['type'].startswith('item.') for e in events)
            if args.fallback_model and args.fallback_model != model and thread is None and not began and unsupported in (message or ''):
                check_resume_target(args, run['started_at'], remaining)
                model = args.fallback_model
                continue
            if message not in (None, CAPACITY_MESSAGE):
                return fail(message)
            current = session_id(events)
            require(thread is None or thread == current, 'Codex resumed a different session')
            thread = current
            if message is None or (context / SUBMISSION_FILE).exists():
                try:
                    result = verify_completion(context, run, remaining)
                except (ValueError, subprocess.SubprocessError):
                    watchdog.check(force=True)
                    raise
                result['recovered_after_capacity'] = message == CAPACITY_MESSAGE
                write_json(context / RESULT_FILE, result)
                append_event(aggregate, {'type': 'review.completed', **result})
                logging.info('Verified final review: %s', result)
                return 0, result
            if retries == 6:
                return fail(message)
            require_rollout(Path(os.environ['CODEX_HOME']), thread, args.cwd)
            # Runtime installation already checked resume support before the first model invocation.
            require(remaining() > 300, 'Insufficient shared review budget for capacity backoff')
            logging.info('Capacity unavailable; waiting 300s before resuming %s', thread)
            append_event(aggregate, dict(type='review.capacity_retry', thread_id=thread, next_attempt=attempt + 1,
                                        delay_seconds=300))
            watchdog.wait(300)
            check_resume_target(args, run['started_at'], remaining)
            retries += 1
    except ReviewSuperseded as error:
        result = dict(state='superseded', repository=args.repository, pr_number=args.pr_number, head_sha=args.head_sha,
                      superseding_head_sha=error.head_sha, message=str(error))
        write_json(context / RESULT_FILE, result)
        append_event(aggregate, {'type': 'review.superseded', **result})
        final.write_text(str(error) + '\n')
        logging.info('%s', error)
        return SUPERSEDED_EXIT_CODE, result
    except KeyboardInterrupt:
        fail('Review cancelled; not resuming')
        return 130, {}
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        return fail(f'Review recovery stopped: {error}')


def resume_prompt(prompt):
    return prompt + "\n\n" + (
        "Recover from a capacity error in this SAME review session. Continue unfinished work using the existing "
        "conversation and subagent ledger; preserve completed findings and the three-round limit. "
        "The previous process exited, so recover child work by recorded IDs and ledger sections; replace only "
        "unrecoverable work. Before any GitHub write, refetch reviews/comments, verify submitted work and never "
        "submit it twice. Complete the goal only after the original review completion criteria are satisfied.")


AUTH_FAILURES = {
    "refresh_token_reused": "Your access token could not be refreshed because your refresh token was already used.",
    "refresh_token_invalidated": "Your session has ended. Please log in again.",
}


@dataclass(frozen=True)
class Failure:
    message: str
    invalid_auth: str = ""
    retry_after: int | None = None


def interpret(events, stderr, exit_code, *, now, usage_limit_backoff):
    terminal = [event for event in events if event.get("type") in {"turn.failed", "error"}]
    failed = [event for event in terminal if event["type"] == "turn.failed"]

    def last_line(messages):
        # Match jq -r ... | tail -n 1, including a final empty message.
        output = "".join(message + "\n" for message in messages if message is not None)
        return output.split("\n")[-2] if output else ""

    reason = last_line((event.get("error") or {}).get("message") for event in failed)
    if not reason:
        reason = last_line(event["message"] if event.get("message") is not None
                           else (event.get("error") or {}).get("message")
                           for event in terminal if event["type"] == "error")
    lines = [line for line in stderr.splitlines() if line.strip()]
    reason = reason or (lines[-1] if lines else f"Codex exited with status {exit_code}")
    codes = {(event.get("error") or {}).get("code") or event.get("code") for event in terminal}
    invalid = ""
    for code, text in AUTH_FAILURES.items():
        stderr_code = re.search(r'"code"\s*:\s*"' + re.escape(code) + r'"', stderr)
        refresh_log = re.search(r'ERROR codex_login::auth(?:::manager)?: Failed to refresh token '
                                r'.*error_code: Some\("' + re.escape(code) + r'"\)', stderr)
        if text.casefold() in reason.casefold() or reason == code or code in codes or stderr_code or refresh_log:
            invalid = code
            break
    retry_after = None
    if "you've hit your usage limit" in reason.casefold():
        match = re.search(r"[Tt]ry again at ((?:[A-Za-z]{3} \d{1,2}(?:st|nd|rd|th)?, \d{4} )?"
                          r"\d{1,2}:\d{2} (?:AM|PM))", reason)
        if match:
            value = re.sub(r"(\d)(?:st|nd|rd|th),", r"\1,", match[1])
            try:
                if "," in value:
                    parsed = datetime.strptime(value, "%b %d, %Y %I:%M %p").replace(tzinfo=timezone.utc)
                else:
                    parsed_time = datetime.strptime(value, "%I:%M %p")
                    parsed = datetime.fromtimestamp(now, timezone.utc).replace(
                        hour=parsed_time.hour, minute=parsed_time.minute, second=0, microsecond=0)
                retry_after = int(parsed.timestamp())
            except ValueError:
                pass
        if retry_after is None or retry_after <= now:
            retry_after = int(now + usage_limit_backoff)
    return Failure(reason, invalid, retry_after)


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
        self.options, self.github, self.statuses, self.runtime = options, github, statuses, runtime

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
                except Exception as error:
                    auth_failure = redact(str(error))
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
                code, result = execute_review(self.options, target, context, pr_dir, env, workspace)
                if code == SUPERSEDED_EXIT_CODE:
                    superseded, exit_code = True, 0
                    logging.info("%s", result["message"])
                elif code == 0:
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
            if context_ready and failure:
                finalize("Preserve review diagnostics", lambda: self.runtime.diagnostics(context),
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

    def report_failure(self, target, failure, *, invalid_recorded, cooldown_recorded, auth_failure, context_ready):
        error = auth_failure or failure.message
        recovery = "Inspect the workflow logs, fix the underlying issue, then trigger /review again."
        if not auth_failure:
            if failure.invalid_auth:
                recovery = ("This credential version is excluded. Replace its refresh token; another configured "
                            "account may be selected by /review." if invalid_recorded else
                            "Could not record the invalid credential. Inspect the recording step before retrying.")
            elif failure.retry_after is not None:
                if cooldown_recorded:
                    retry_at = datetime.fromtimestamp(failure.retry_after, timezone.utc).isoformat()
                    recovery = f"Account excluded until {retry_at}. Trigger /review to try another eligible account."
                else:
                    error = "Codex reached its usage limit, but recording the account cooldown failed."
            elif not context_ready:
                error = "Review context preparation failed before Codex ran; inspect the context preparation step."
        self.github.comment(target["number"], "Codex automated review failed and did not complete.\n\n"
                            f"Error: {error}\nWorkflow run: {self.options.run_url}\n\n{recovery}")
