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

"""Source statuses and SHA-wide aggregation are separate workflow operations."""

import fnmatch
import logging
import subprocess

from resolve_code_review_status import resolve_status
from review_github_api import redact
from validate_review_pass_comment import parse_comment, require_full_sha, validate_comment


class StatusWorkflow:
    def __init__(self, github, locks, *, run_url, skip_policy):
        self.github = github
        self.locks = locks
        self.run_url = run_url
        self.skip_policy = skip_policy

    def _lock(self, head):
        return self.locks.hold("status", f"{self.github.repository}:{head.lower()}")

    @staticmethod
    def source(kind, number, base):
        return f"code-review/source/{kind}/pr-{number}/base-{base}"

    def _aggregate(self, head):
        self.github.status(head, "code-review", "pending",
                           f"Recalculating code review for {head[:12]}.", self.run_url)
        pulls = self.github.api("pulls?state=open&per_page=100", pages=True)
        statuses = self.github.api(f"commits/{head}/statuses?per_page=100", pages=True)
        resolution = resolve_status(pulls, statuses, head_sha=head)
        self.github.status(head, "code-review", resolution.state,
                           resolution.description, self.run_url)
        return resolution

    def aggregate(self, head):
        with self._lock(head):
            return self._aggregate(head)

    def begin_review(self, number, head, base):
        self.github.status(head, "code-review", "pending",
                           f"Automated review is running for PR #{number}.", self.run_url)
        self.github.status(head, self.source("automated", number, base), "pending",
                           f"Automated review is running for PR #{number} at {base[:12]}.",
                           self.run_url)

    def finish_review(self, number, head, base, *, result, execution_succeeded):
        state = "pending"
        description = f"Automated review did not pass for PR #{number} at {base[:12]}."
        if execution_succeeded:
            state = result["state"]
            if state not in {"success", "failure"}:
                raise ValueError("Missing verified review verdict")
            description = f"Review completed for PR #{number}: P0={result['p0']}, P1={result['p1']}."
            if not result["converged"]:
                description = (f"Review did not converge after {result['rounds']} rounds "
                               f"for PR #{number}: P0={result['p0']}, P1={result['p1']}.")
        self.github.status(head, self.source("automated", number, base),
                           state, description, self.run_url)

    def _approve(self, kind, number, head, base, description, url):
        self.github.status(head, "code-review", "pending",
                           f"Recalculating code review for PR #{number}.", url)
        self.github.status(head, self.source(kind, number, base), "success", description, url)
        return self.aggregate(head)

    def accept_local(self, event):
        comment = event.comment
        author = comment["user"]["login"]
        if author != event.data["sender"]["login"]:
            logging.info("Ignoring local PASS: comment creator and sender differ")
            return
        try:
            permission = self.github.api(f"collaborators/{author}/permission")["permission"]
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            logging.warning("Ignoring local PASS: cannot verify repository permission (%s)",
                            type(error).__name__)
            return
        if permission not in {"write", "admin"}:
            logging.info("Ignoring local PASS: creator does not have write permission")
            return
        number = event.pr_number
        pr = self.github.pull(number)
        if pr["state"] != "open":
            logging.info("Ignoring local PASS: pull request is %s", pr["state"])
            return
        head, base = pr["head"]["sha"], pr["base"]["sha"]
        try:
            fields = parse_comment(comment["body"])
            reviewed_base = str(fields["base"])
            # validate_comment checks the snapshot's identity, model and convergence.
            require_full_sha("reviewed base", reviewed_base)
            comparison = self.github.api(f"compare/{reviewed_base}...{base}")["status"]
            reviewed_time = live_time = None
            if reviewed_base != base:
                reviewed_time = self.github.api(f"commits/{reviewed_base}")["commit"]["committer"]["date"]
                live_time = self.github.api(f"commits/{base}")["commit"]["committer"]["date"]
            validate_comment(
                comment["body"], repository=self.github.repository, pr_number=number,
                head_sha=head, live_base_sha=base, base_compare_status=comparison,
                reviewed_base_committed_at=reviewed_time, live_base_committed_at=live_time,
                comment_author=author, comment_author_permission=permission,
            )
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            logging.info("Ignoring local PASS: validation failed (%s)", type(error).__name__)
            return
        return self._approve("local", number, head, base,
                             f"Local review passed for PR #{number} at {base[:12]}.",
                             comment["html_url"])

    def skip_review(self, event):
        number = event.pr_number
        pr = self.github.pull(number)
        user = str(event.comment["user"]["id"])
        branch = pr["base"]["ref"]
        allowed = user in self.skip_policy["all_branches"] or any(
            fnmatch.fnmatchcase(branch, pattern) and user in users
            for pattern, users in self.skip_policy["branches"].items()
        )
        if not allowed:
            logging.info("Ignoring skip: user is not allowed for this target branch")
            return
        head, base = pr["head"]["sha"], pr["base"]["sha"]
        return self._approve("skip", number, head, base,
                             f"Code review skipped for PR #{number} at {base[:12]}.", self.run_url)

    def synchronize(self, event):
        # These used to be independent jobs. One failure must not suppress the
        # other valid event handlers, particularly old-head recomputation.
        actions = []
        if event.local_pass:
            actions.append(lambda: self.accept_local(event))
        if event.skip:
            actions.append(lambda: self.skip_review(event))
        for head in event.status_heads:
            actions.append(lambda head=head: self.aggregate(head))
        failures = []
        for action in actions:
            try:
                action()
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                logging.error("Status synchronization failed (%s): %s", type(error).__name__, redact(str(error)))
                failures.append(error)
        if failures:
            raise RuntimeError(f"{len(failures)} status synchronization operation(s) failed") from failures[0]
