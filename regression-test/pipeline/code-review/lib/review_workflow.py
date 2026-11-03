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

import itertools
import json
import logging
import re
import shutil
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from process import RECOVERABLE, append_jsonl, log_failure, read_jsonl, redact, require, step, supervise, write_json
from review_context import ReviewContext, Target
from review_github_api import GitHub, ReviewSuperseded
from submit_review import RESULT_FILE, RUN_FILE, SUBMISSION_FILE, Delivery

CAPACITY_MESSAGE = 'Selected model is at capacity. Please try a different model.'
CAPACITY_RETRIES = 6
CAPACITY_BACKOFF_SECONDS = 300
HEAD_CHECK_SECONDS = 60
GITHUB_TIMEOUT = 30
# Exit statuses of a killed or timed-out child: timeout(1), SIGINT, SIGKILL and SIGTERM.
INTERRUPTED_STATUSES = {124, 130, 137, 143}
TERMINAL_EVENTS = {'turn.started', 'turn.completed', 'turn.failed', 'error'}
AUTH_FAILURES = {
    'refresh_token_reused': 'Your access token could not be refreshed because your refresh token was already used.',
    'refresh_token_invalidated': 'Your session has ended. Please log in again.',
}
# Codex renders the reset time in the worker's local time zone, adding the date when it is not today.
USAGE_LIMIT_RETRY = re.compile(
    r'[Tt]ry again at ((?:[A-Za-z]{3} \d{1,2}(?:st|nd|rd|th)?, \d{4} )?\d{1,2}:\d{2} (?:AM|PM))')
RESUME_INSTRUCTIONS = (
    "\n\nRecover from a capacity error in this SAME review session. Continue unfinished work using the existing "
    "conversation and subagent ledger; preserve completed findings and the three-round limit. "
    "The previous process exited, so recover child work by recorded IDs and ledger sections; replace only "
    "unrecoverable work. Before any GitHub write, refetch reviews/comments, verify submitted work and never "
    "submit it twice. Complete the goal only after the original review completion criteria are satisfied.")


@dataclass(frozen=True)
class Failure:
    message: str
    invalid_auth: str = ''
    retry_after: int | None = None


def retry_after(reason, now, backoff):
    """The epoch after which a usage-limited account may be used again."""
    match = USAGE_LIMIT_RETRY.search(reason)
    if match:
        value = re.sub(r'(\d)(?:st|nd|rd|th),', r'\1,', match[1])
        try:
            if ',' in value:
                parsed = datetime.strptime(value, '%b %d, %Y %I:%M %p').astimezone()
            else:
                clock = datetime.strptime(value, '%I:%M %p')
                parsed = datetime.fromtimestamp(now).astimezone().replace(
                    hour=clock.hour, minute=clock.minute, second=0, microsecond=0)
            if parsed.timestamp() > now:
                return int(parsed.timestamp())
        except ValueError:
            pass
    return int(now + backoff)


def invalid_auth(reason, events, stderr):
    codes = {(event.get('error') or {}).get('code') or event.get('code')
             for event in events if event['type'] in {'turn.failed', 'error'}}
    for code, message in AUTH_FAILURES.items():
        if (message.casefold() in reason.casefold() or reason == code or code in codes
                or re.search(r'"code"\s*:\s*"' + re.escape(code) + r'"', stderr)
                or re.search(r'ERROR codex_login::auth(?:::manager)?: Failed to refresh token '
                             r'.*error_code: Some\("' + re.escape(code) + r'"\)', stderr)):
            return code
    return ''


def interpret(events, stderr, status, *, now, usage_limit_backoff):
    """None when the attempt completed its turn, else the Failure that ended it."""
    terminal = next((event for event in reversed(events) if event['type'] in TERMINAL_EVENTS), {})
    kind = terminal.get('type')
    if kind == 'turn.completed':
        if status == 0:
            return None
        reason = f'Codex exited with status {status} after turn.completed'
    elif kind in {'turn.failed', 'error'}:
        reason = (terminal.get('error') or terminal).get('message') or f'Codex reported {kind} (exit status {status})'
    elif status == 0:
        reason = 'Codex exited with status 0 without a terminal turn event; review is incomplete'
    else:
        reason = next((line for line in reversed(stderr.splitlines()) if line.strip()),
                      f'Codex exited with status {status}')
    limited = "you've hit your usage limit" in reason.casefold()
    return Failure(reason, invalid_auth(reason, events, stderr),
                   retry_after(reason, now, usage_limit_backoff) if limited else None)


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
        if (meta['type'] == 'session_meta' and payload['id'] == thread
                and Path(payload['cwd']).resolve() == cwd.resolve()):
            return
    raise ValueError('Main session rollout is missing; refusing to start a new review')


class ReviewRun:
    """One Codex goal session: run it, resume it after capacity errors, and verify the delivered review."""

    def __init__(self, options, target, context, env, reaper):
        self.options, self.target, self.context, self.env, self.reaper = options, target, context, env, reaper
        self.dir, self.events = context.dir, context.dir / 'codex-events.jsonl'
        self.deadline = time.monotonic() + options.review_timeout - options.cleanup_reserve
        self.github = GitHub(options.repository, env=env, timeout=GITHUB_TIMEOUT, deadline=self.deadline)
        self.run = dict(repository=options.repository, pr_number=str(target.number), head_sha=target.head,
                        base_sha=target.base, started_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                        token=str(uuid.uuid4()), deadline=self.deadline, review_author=options.review_author)
        self.delivery = Delivery(self.dir, self.run, self.github)
        self.next_head_check = 0

    def remaining(self):
        seconds = self.deadline - time.monotonic()
        if seconds <= 0:
            raise TimeoutError('Review shared time budget exhausted')
        return seconds

    def log_event(self, event):
        append_jsonl(self.events, {**event, '_received_ns': time.time_ns()})

    def receive(self, line):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return  # A cancelled attempt can end mid-line; its raw attempt file keeps the text.
        if isinstance(event, dict):
            self.log_event(event)

    def fail(self, failure):
        logging.error('%s', failure.message)
        self.log_event({'type': 'turn.failed', 'source': 'review-resume-runner', 'error': {'message': failure.message}})
        return None, failure

    def check_head(self, *, force=False):
        """Stop early when the PR closed or moved; an unavailable API is not evidence of either."""
        if not force and time.monotonic() < self.next_head_check:
            return
        self.next_head_check = time.monotonic() + HEAD_CHECK_SECONDS
        try:
            self.github.require_target(self.target.number, self.target.head)
        except RECOVERABLE as error:
            logging.warning('PR head check unavailable (%s); keeping current review', type(error).__name__)

    def wait(self, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.check_head()
            now = time.monotonic()
            time.sleep(max(0, min(deadline - now, self.remaining(), self.next_head_check - now)))

    def require_resumable(self):
        """Before a new Codex invocation, refuse a moved PR or a head another run already reviewed."""
        self.delivery.require_target()
        if any(self.delivery.owned(review) for review in self.delivery.reviews()):
            raise ReviewSuperseded('Another review run submitted a review for this head; refusing to resume')

    def attempt(self, number, model, thread):
        """Run one Codex invocation; return its exit status, its events and its Failure (None on success)."""
        attempts = self.dir / 'codex-attempts'
        attempts.mkdir(exist_ok=True)
        events, stderr, output = (attempts / f'{number}{suffix}' for suffix in ('.jsonl', '.stderr.log', '.final.txt'))
        final = self.dir / 'codex-final-message.txt'
        final.write_text('')
        prompt = (self.dir / 'codex_goal_prompt.txt').read_text()
        command = ['codex', 'exec', '--goal', '--cd', str(self.context.root), '--model', model, '--config',
                   f'model_reasoning_effort={self.options.effort}', '--sandbox', 'danger-full-access',
                   '--color', 'never', '--json', '--output-last-message', str(output)]
        command += ['resume', thread, prompt + RESUME_INSTRUCTIONS] if thread else [prompt]
        logging.info('Review attempt %s: model=%s, session=%s, remaining=%.0fs',
                     number, model, thread, self.remaining())
        try:
            status = supervise(command, events, stderr, self.remaining(), reaper=self.reaper, env=self.env,
                               poll=self.check_head, on_line=self.receive)
        finally:
            with (self.dir / 'codex-stderr.log').open('a') as handle:
                handle.write(stderr.read_text(errors='replace') + '\n')
            if output.exists():
                shutil.copyfile(output, final)
        records = read_jsonl(events)
        failure = interpret(records, stderr.read_text(errors='replace'), status, now=time.time(),
                            usage_limit_backoff=self.options.usage_limit_backoff)
        logging.info('Review attempt %s exited %s: %s', number, status, failure.message if failure else 'completed')
        return status, records, failure

    def falls_back(self, model, thread, events, failure):
        """Switch to the fallback model only when the first invocation rejected the model outright."""
        fallback = self.options.fallback_model
        unsupported = f"The '{model}' model is not supported when using Codex with a ChatGPT account."
        began = any(e['type'] == 'turn.completed' or e['type'].startswith('item.') for e in events)
        return bool(fallback) and fallback != model and thread is None and not began and unsupported in failure.message

    def attempts(self):
        model, thread, retries = self.options.model, None, 0
        for number in itertools.count(1):
            (self.dir / 'codex-review-model.txt').write_text(model + '\n')
            self.check_head(force=True)
            status, events, failure = self.attempt(number, model, thread)
            self.check_head(force=True)
            if status < 0 or status in INTERRUPTED_STATUSES:
                return self.fail(Failure(f'Codex was interrupted or timed out (status {status}); not resuming'))
            if failure and self.falls_back(model, thread, events, failure):
                self.require_resumable()
                model = self.options.fallback_model
                continue
            if failure and failure.message != CAPACITY_MESSAGE:
                return self.fail(failure)
            current = session_id(events)
            require(thread in (None, current), 'Codex resumed a different session')
            thread = current
            if failure is None or (self.dir / SUBMISSION_FILE).exists():
                result = {**self.delivery.verify(), 'recovered_after_capacity': failure is not None}
                write_json(self.dir / RESULT_FILE, result)
                self.log_event({'type': 'review.completed', **result})
                logging.info('Verified final review: %s', result)
                return result, None
            if retries == CAPACITY_RETRIES:
                return self.fail(failure)
            require_rollout(Path(self.env['CODEX_HOME']), thread, self.context.root)
            require(self.remaining() > CAPACITY_BACKOFF_SECONDS,
                    'Insufficient shared review budget for capacity backoff')
            logging.info('Capacity unavailable; waiting %ss before resuming %s', CAPACITY_BACKOFF_SECONDS, thread)
            self.log_event(dict(type='review.capacity_retry', thread_id=thread, next_attempt=number + 1,
                                delay_seconds=CAPACITY_BACKOFF_SECONDS))
            self.wait(CAPACITY_BACKOFF_SECONDS)
            self.require_resumable()
            retries += 1

    def execute(self):
        """Return (verified result, None) or (None, Failure); raise ReviewSuperseded or KeyboardInterrupt."""
        write_json(self.dir / RUN_FILE, self.run)
        (self.dir / 'codex-stderr.log').touch()
        self.events.touch()
        try:
            try:
                return self.attempts()
            except RECOVERABLE as error:
                self.check_head(force=True)  # A moved PR explains a late failure as superseded.
                return self.fail(Failure(f'Review recovery stopped: {redact(str(error))}'))
        except ReviewSuperseded as error:
            result = dict(state='superseded', repository=self.options.repository, pr_number=str(self.target.number),
                          head_sha=self.target.head, message=str(error))
            write_json(self.dir / RESULT_FILE, result)
            self.log_event({'type': 'review.superseded', **result})
            (self.dir / 'codex-final-message.txt').write_text(str(error) + '\n')
            raise
        except KeyboardInterrupt:
            self.fail(Failure('Review cancelled; not resuming'))
            raise


class ReviewWorkflow:
    """One review build: prepare, run Codex, then run every finalizer whatever happened."""

    def __init__(self, options, github, statuses, runtime):
        self.options, self.github, self.statuses, self.runtime = options, github, statuses, runtime

    def run(self, event, workspace):
        with step('Resolve review inputs', self.options.resolve_timeout):
            self.target = Target.resolve(event, self.github)
        self.workspace, self.context, self.auth = workspace, None, None
        self.result, self.failure, self.superseded, self.finalization_failed = {}, None, False, False
        try:
            exit_code = self.execute()
        except ReviewSuperseded as error:
            logging.info('%s', error)
            self.superseded, exit_code = True, 0
        except KeyboardInterrupt as error:
            self.failure = Failure(f'Review was cancelled during "{getattr(error, "step_label", "setup")}".')
            exit_code = 130
        except Exception as error:
            label = getattr(error, 'step_label', 'setup')
            log_failure(label, error)
            # Name only the step and type: exception text can carry command lines.
            self.failure = self.failure or Failure(f'Review failed during "{label}" ({type(error).__name__}).')
            exit_code = 1
        self.finish(exit_code)
        return exit_code or int(self.finalization_failed)

    def execute(self):
        options, target, workspace = self.options, self.target, self.workspace
        if target.manage_status:
            with step('Mark Code Review status as pending', options.status_timeout):
                self.statuses.begin_review(target.number, target.head, target.base)
        context = ReviewContext(options, self.github, target, workspace)
        with step('Checkout repository', options.checkout_timeout):
            context.checkout()
        env = self.runtime.install(workspace)
        with step('Configure Codex auth', options.auth_timeout):
            try:
                self.auth = self.runtime.auth.acquire(workspace)
            except RuntimeError as error:
                self.failure = Failure(redact(str(error)))  # The pool explains which credentials to fix.
                raise
            self.runtime.configure(workspace)
        with step('Sync Codex memories from OSS', options.memories_timeout):
            self.runtime.memories(workspace)
        context.prepare()
        self.context = context.dir
        with step('Run automated code review', options.review_timeout):
            self.result, self.failure = ReviewRun(options, target, context, env, workspace.reaper).execute()
        return 0 if self.failure is None else 1

    def finalize(self, label, operation, seconds, *, critical=True):
        try:
            with step(label, seconds):
                operation()
            return True
        except (Exception, KeyboardInterrupt) as error:
            log_failure(label, error)
            self.finalization_failed |= critical
            return False

    def finish(self, exit_code):
        options, target, failure, home = self.options, self.target, self.failure, self.workspace.path / 'codex-home'
        if failure and self.context:
            self.finalize('Preserve review diagnostics', lambda: self.runtime.diagnostics(self.context),
                          options.diagnostics_timeout, critical=False)
        invalid_recorded = cooldown_recorded = False
        if failure and self.auth and failure.invalid_auth:
            invalid_recorded = self.finalize('Record invalid Codex auth', lambda: self.auth.record_invalid(
                failure.invalid_auth), options.record_timeout)
        if failure and self.auth and failure.retry_after is not None:
            cooldown_recorded = self.finalize('Record Codex usage limit', lambda: self.auth.record_cooldown(
                failure.retry_after), options.record_timeout)
        if failure:
            self.finalize('Publish execution failure', lambda: self.report_failure(invalid_recorded, cooldown_recorded),
                          options.status_timeout)
        # A superseded run leaves its source status to the run or head that replaced it.
        if target.manage_status and not self.superseded:
            self.finalize('Publish automated source', lambda: self.statuses.finish_review(
                target.number, target.head, target.base, result=self.result,
                execution_succeeded=exit_code == 0 and not self.finalization_failed), options.status_timeout)
        if self.context:
            self.finalize('Record review telemetry', lambda: self.runtime.telemetry(self.context, home, target),
                          options.telemetry_timeout, critical=False)
        self.finalize('Archive Codex sessions', lambda: self.runtime.sessions(home), options.sessions_timeout,
                      critical=False)
        if self.auth:
            self.finalize('Persist refreshed credentials', self.auth.sync, options.auth_sync_timeout)
        if target.manage_status:
            self.finalize('Aggregate Code Review status', lambda: self.statuses.aggregate(target.head),
                          options.status_timeout)

    def report_failure(self, invalid_recorded, cooldown_recorded):
        failure, error = self.failure, self.failure.message
        recovery = 'Inspect the workflow logs, fix the underlying issue, then trigger /review again.'
        if failure.invalid_auth:
            recovery = ('This credential version is excluded. Replace its refresh token; another configured '
                        'account may be selected by /review.' if invalid_recorded else
                        'Could not record the invalid credential. Inspect the recording step before retrying.')
        elif failure.retry_after is not None:
            if cooldown_recorded:
                retry_at = datetime.fromtimestamp(failure.retry_after, timezone.utc).isoformat()
                recovery = f'Account excluded until {retry_at}. Trigger /review to try another eligible account.'
            else:
                error = 'Codex reached its usage limit, but recording the account cooldown failed.'
        self.github.comment(self.target.number, 'Codex automated review failed and did not complete.\n\n'
                            f'Error: {error}\nWorkflow run: {self.options.run_url}\n\n{recovery}')
