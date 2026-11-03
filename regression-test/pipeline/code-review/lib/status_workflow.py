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

"""Validate review sources and aggregate the status of every open PR on a SHA."""

import fnmatch
import logging
import re
from datetime import datetime, timedelta

from process import RECOVERABLE, log_failure, require, require_full_sha

FIELDS = 'schema status pr commit base reviewed_at reviewer model effort findings rounds converged'.split()
BEGIN, END = '<!-- doris-repo-review:v1:begin -->', '<!-- doris-repo-review:v1:end -->'
EFFORTS = {
    **{model + suffix: {'xhigh', 'max'} for model in ('claude-opus-5-5', 'claude-fable-5', 'claude-fable-5-1')
       for suffix in ('', '[1m]')},
    **{model: {'xhigh', 'max', 'ultra'} for model in ('gpt-6.1-sol', 'gpt-6-sol', 'gpt-6-astra')},
}
SOURCE = re.compile(r'code-review/source/(automated|local|skip)/pr-(\d+)/base-([0-9a-fA-F]{40})')
MAX_BASE_LAG = timedelta(hours=48)
# Concurrent workers may interleave their aggregate writes; see StatusWorkflow.aggregate.
AGGREGATE_ROUNDS = 3


def parse_comment(comment):
    require(comment.count(BEGIN) == comment.count(END) == 1, 'Expected one review marker pair')
    require(comment.index(BEGIN) < comment.index(END), 'Review markers are out of order')
    blocks = re.findall(r'```yaml\n(.*?)\n```', comment.split(BEGIN)[1].split(END)[0], flags=re.DOTALL)
    require(len(blocks) == 1, 'Expected one fenced yaml block')
    rows = [line.partition(':') for line in blocks[0].splitlines()]
    require(all(separator for _, separator, _ in rows), 'Every yaml line must be "key: value"')
    require([key.strip() for key, _, _ in rows] == FIELDS, 'Comment fields do not match the v1 schema')
    fields = {key.strip(): value.strip() for key, _, value in rows}
    findings = re.fullmatch(r'\{blocker: (\d+), major: (\d+), minor: (\d+), nit: (\d+)\}', fields['findings'])
    require(findings is not None, 'Findings must use the v1 inline-map format')
    require(fields['rounds'].isdigit(), 'Rounds must be an integer')
    fields['findings'] = tuple(map(int, findings.groups()))
    fields['rounds'] = int(fields['rounds'])
    return fields


def timestamp(value):
    parsed = datetime.fromisoformat(value)
    require(parsed.utcoffset() is not None, 'Timestamp must include a timezone offset')
    return parsed


def validate_comment(fields, repository, number, head, base, author):
    for name, value in (('commit', fields['commit']), ('base', fields['base']), ('live base', base)):
        require_full_sha(name, value)
    checks = (
        (fields['schema'] == 'doris-repo-review/v1', 'Unsupported review schema'),
        (fields['status'] == 'PASS', 'Review status is not PASS'),
        (fields['pr'].casefold() == f'{repository}#{number}'.casefold(), 'Review targets another PR'),
        (fields['commit'].casefold() == head.casefold(), 'Review targets another head'),
        (fields['reviewer'].casefold() == author.casefold(), 'Reviewer does not match comment creator'),
        (fields['effort'] in EFFORTS.get(fields['model'], set()), 'Model/effort is not allowed'),
        (fields['findings'][:2] == (0, 0), 'Blocker and Major findings must be zero'),
        (fields['converged'] == 'true', 'Review did not converge'),
        (1 <= fields['rounds'] <= 3, 'Rounds must be between 1 and 3'),
    )
    for valid, message in checks:
        require(valid, message)
    timestamp(fields['reviewed_at'])


def resolve_status(pulls, statuses, head):
    require_full_sha('head', head)
    contexts = set()
    for pr in pulls:
        if pr['state'] == 'open' and pr['head']['sha'].casefold() == head.casefold():
            require_full_sha('base', pr['base']['sha'])
            contexts.add((pr['number'], pr['base']['sha'].casefold()))
    if not contexts:
        return 'pending', f'No open pull request currently uses {head[:12]}.'
    latest = {item['context']: item for item in sorted(statuses, key=lambda item: item['id'])}
    approved, blocked, incomplete, automated = set(), set(), set(), {}
    for context, item in latest.items():
        match = SOURCE.fullmatch(context)
        if match is None:
            continue
        kind, number, base = match.groups()
        key = (int(number), base.casefold())
        if kind == 'automated':
            automated[key] = item
        if item['state'] == 'success':
            approved.add(key)
        elif kind == 'automated' and item['state'] == 'failure':
            blocked.add(key)
            if (item.get('description') or '').startswith('Review did not converge after '):
                incomplete.add(key)
    missing = contexts - approved  # Authorized local PASS/skip still overrides an automated failure.
    failures = sorted(missing & blocked)
    if failures:
        number, base = failures[0]
        reason = 'did not converge' if (number, base) in incomplete else 'completed with P0/P1'
        return 'failure', f'Review {reason} for PR #{number} at {base[:12]}.'
    if missing:
        number, base = min(missing)
        suffix = f' (+{len(missing) - 1} more)' if len(missing) > 1 else ''
        source = automated.get((number, base), {})
        description = source.get('description') or f'Awaiting code review for PR #{number} at {base[:12]}'
        return 'pending', description.rstrip('.') + suffix + '.'
    noun = 'context' if len(contexts) == 1 else 'contexts'
    return 'success', f'Code review passed for {len(contexts)} open PR {noun} on {head[:12]}.'


class StatusWorkflow:
    def __init__(self, github, *, run_url, skip_policy):
        self.github, self.run_url, self.skip_policy = github, run_url, skip_policy

    @staticmethod
    def source(kind, number, base):
        return f'code-review/source/{kind}/pr-{number}/base-{base}'

    def publish(self, head, state, description, *, context='code-review', url=None):
        return self.github.status(head, context, state, description, url or self.run_url)

    def aggregate(self, head):
        """Publish the combined status of head, then re-read the sources until they agree with it.

        Every source write is followed by an aggregate from the same worker. Because each
        aggregate re-verifies after its own write, the last write reflects every source
        status written before it, however concurrent workers interleave.
        """
        published = None
        for _ in range(AGGREGATE_ROUNDS):
            current = resolve_status(self.github.api('pulls?state=open&per_page=100', pages=True),
                                     self.github.api(f'commits/{head}/statuses?per_page=100', pages=True), head)
            if current == published:
                return
            self.publish(head, *current)
            published = current

    def begin_review(self, number, head, base):
        self.publish(head, 'pending', f'Automated review is running for PR #{number} at {base[:12]}.',
                     context=self.source('automated', number, base))
        self.aggregate(head)

    def finish_review(self, number, head, base, *, result, execution_succeeded):
        state = 'pending'
        description = f'Automated review did not pass for PR #{number} at {base[:12]}.'
        if execution_succeeded:
            state = result['state']
            require(state in {'success', 'failure'}, 'Missing verified review verdict')
            description = f"Review completed for PR #{number}: P0={result['p0']}, P1={result['p1']}."
            if not result['converged']:
                description = (f"Review did not converge after {result['rounds']} rounds "
                               f"for PR #{number}: P0={result['p0']}, P1={result['p1']}.")
        self.publish(head, state, description, context=self.source('automated', number, base))

    def approve(self, kind, number, head, base, description, url):
        self.publish(head, 'success', description, context=self.source(kind, number, base), url=url)
        self.aggregate(head)

    def accept_local(self, event):
        comment, number = event.comment, event.pr_number
        author = comment['user']['login']
        if author != event.data['sender']['login']:
            logging.info('Ignoring local PASS: comment creator and sender differ')
            return
        if self.github.api(f'collaborators/{author}/permission')['permission'] not in {'write', 'admin'}:
            logging.info('Ignoring local PASS: comment creator needs write permission')
            return
        pr = self.github.pull(number)
        head, base = pr['head']['sha'], pr['base']['sha']
        try:
            require(pr['state'] == 'open', 'PR is not open')
            fields = parse_comment(comment['body'])
            validate_comment(fields, self.github.repository, number, head, base, author)
            self.require_recent_base(fields['base'], base)
        except ValueError as error:
            # The author has write permission, so tell them why their PASS did not count.
            logging.info('Rejecting local PASS: %s', error)
            self.github.comment(number, f"Local review PASS was not accepted for {head[:12]}: {error}.\n\n"
                                        f"Comment: {comment['html_url']}")
            return
        self.approve('local', number, head, base, f'Local review passed for PR #{number} at {base[:12]}.',
                     comment['html_url'])

    def require_recent_base(self, reviewed, base):
        """The reviewed base must be the current base, or an ancestor at most MAX_BASE_LAG older."""
        comparison = self.github.api(f'compare/{reviewed}...{base}')['status']
        if reviewed.casefold() == base.casefold():
            require(comparison == 'identical', 'Equal bases must have compare status identical')
            return
        require(comparison == 'ahead', 'Reviewed base is not an ancestor of the current base')
        old, new = (timestamp(self.github.api(f'commits/{sha}')['commit']['committer']['date'])
                    for sha in (reviewed, base))
        require(timedelta(0) <= new - old <= MAX_BASE_LAG, 'Reviewed base must be within 48 hours of the current base')

    def skip_review(self, event):
        number = event.pr_number
        pr = self.github.pull(number)
        user, branch = str(event.comment['user']['id']), pr['base']['ref']
        allowed = user in self.skip_policy['all_branches'] or any(
            fnmatch.fnmatchcase(branch, pattern) and user in users
            for pattern, users in self.skip_policy['branches'].items())
        if not allowed:
            logging.info('Ignoring skip: user is not allowed for this target branch')
            return
        head, base = pr['head']['sha'], pr['base']['sha']
        self.approve('skip', number, head, base, f'Code review skipped for PR #{number} at {base[:12]}.',
                     self.run_url)

    def synchronize(self, event):
        actions = []
        if event.local_pass:
            actions.append((self.accept_local, event))
        if event.skip:
            actions.append((self.skip_review, event))
        actions.extend((self.aggregate, head) for head in event.status_heads)
        failures = []
        for operation, argument in actions:
            try:
                operation(argument)
            except RECOVERABLE as error:
                log_failure('Status synchronization', error)
                failures.append(error)
        if failures:
            raise RuntimeError(f"{len(failures)} status synchronization operation(s) failed") from failures[0]
