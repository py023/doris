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

"""Submit and verify a final review bound to this runner invocation."""

import argparse
import hashlib
import json
import re
import subprocess
from collections import Counter
from pathlib import Path

from process import require, write_json
from review_github_api import GitHub, ReviewSuperseded

SUBMISSION_FILE = "review-submission.json"
REJECTION_FILE = "review-submission-rejected.json"
RUN_FILE = "review-run.json"
RESULT_FILE = "review-result.json"
PRIORITY = re.compile(r"^\[P([0-3])\]\s+\S")
FIELDS = {"body", "comments", "existing_blocking_comment_ids", "converged", "rounds", "incomplete_reason"}
COMMENT_FIELDS = {"path", "line", "side", "body"}
API_TIMEOUT = 30


def priority(body):
    match = PRIORITY.match(body)
    require(match is not None, "Every finding must start with [P0], [P1], [P2] or [P3]")
    return int(match.group(1))


def validate_submission(value):
    require(isinstance(value, dict) and set(value) == FIELDS, f"Final review requires {sorted(FIELDS)}")
    require(type(value["converged"]) is bool, "converged must be a boolean")
    require(type(value["rounds"]) is int and 1 <= value["rounds"] <= 3, "rounds must be an integer from 1 to 3")
    reason = value["incomplete_reason"]
    require(isinstance(reason, str), "incomplete_reason must be text")
    require(not reason.strip() if value["converged"] else value["rounds"] == 3 and bool(reason.strip()),
            "Only a non-converged review after three rounds requires an incomplete_reason")
    require(isinstance(value["body"], str) and value["body"].strip(), "Final review summary is empty")
    require(isinstance(value["comments"], list), "comments must be an array")
    for comment in value["comments"]:
        require(isinstance(comment, dict) and set(comment) == COMMENT_FIELDS,
                "Each finding requires exactly path, line, side and body")
        require(isinstance(comment["path"], str) and comment["path"], "Finding path is empty")
        require(type(comment["line"]) is int and comment["line"] > 0, "Finding line must be a positive integer")
        require(comment["side"] in {"LEFT", "RIGHT"}, "Finding side must be LEFT or RIGHT")
        require(isinstance(comment["body"], str), "Finding body must be text")
        priority(comment["body"])
    ids = value["existing_blocking_comment_ids"]
    require(isinstance(ids, list) and all(type(i) is int and i > 0 for i in ids),
            "Existing blocking comment IDs must be positive integers")
    require(len(set(ids)) == len(ids), "Existing blocking comment IDs must be unique")
    return value


def anchor(comment):
    return comment["path"], comment.get("line"), comment.get("side"), comment["body"]


class Delivery:
    """The final review declared by one runner invocation, verified by exact GitHub readback."""

    def __init__(self, context, run, github=None):
        self.context, self.run = context, run
        # run["deadline"] is CLOCK_MONOTONIC, which Linux shares across processes.
        self.github = github or GitHub(run["repository"], timeout=API_TIMEOUT, deadline=run["deadline"])
        self.pulls = f"pulls/{run['pr_number']}"

    def require_target(self):
        self.github.require_target(self.run["pr_number"], self.run["head_sha"], self.run["base_sha"])

    def reviews(self):
        return self.github.api(f"{self.pulls}/reviews", pages=True)

    def comments(self):
        return self.github.api(f"{self.pulls}/comments", pages=True)

    def owned(self, item):
        """Whether the review bot wrote this review/comment on this head after the invocation started."""
        run = self.run
        return ((item.get("user") or {}).get("login") == run["review_author"]
                and item.get("commit_id") == run["head_sha"]
                and (item.get("submitted_at") or item.get("created_at") or "") >= run["started_at"])

    def payload(self, submission):
        counts = [0, 0, 0, 0]
        for comment in submission["comments"]:
            counts[priority(comment["body"])] += 1
        # Previously reported findings are not posted again. The reviewer must
        # explicitly reconfirm which existing P0/P1 findings still apply to this head.
        ids = submission["existing_blocking_comment_ids"]
        if ids:
            existing = {comment["id"]: comment for comment in self.comments()}
            for comment_id in ids:
                comment = existing.get(comment_id)
                require(comment is not None and comment.get("in_reply_to_id") is None,
                        f"Existing blocking finding {comment_id} is missing or a reply")
                # Older reviews may bold the whole heading or only the priority.
                level = priority(re.sub(r"^\*\*(\[P[0-3]\])(?:\*\*)?", r"\1", comment["body"], count=1))
                require(level <= 1, f"Existing finding {comment_id} is not P0/P1")
                counts[level] += 1
        # The marker binds the entire declared submission to this invocation;
        # a parallel run cannot satisfy it.
        digest = hashlib.sha256(json.dumps(submission, sort_keys=True).encode()).hexdigest()
        marker = f"<!-- code-review-completion:{self.run['token']}:{digest} -->"
        body = submission["body"]
        if submission["converged"]:
            body += f"\n\nReview converged after {submission['rounds']} round(s)."
        else:
            body += ("\n\n**Review did not converge after 3 rounds. This automated review cannot pass the review "
                     f"check.**\n\n{submission['incomplete_reason']}")
        if ids:
            body += "\n\nExisting P0/P1 findings confirmed for this head: " + ", ".join(
                f"https://github.com/{self.run['repository']}/pull/{self.run['pr_number']}#discussion_r{i}"
                for i in ids)
        body += f"\n\n{marker}"
        event = "REQUEST_CHANGES" if counts[0] + counts[1] else "COMMENT"
        return {"commit_id": self.run["head_sha"], "event": event, "body": body,
                "comments": submission["comments"]}, counts, marker

    def post(self, path, submission, payload):
        # Persist the intent before POST: if the response is lost, the review is read
        # back instead of posted twice. Exclusive creation also stops two simultaneous
        # helper calls from both posting after their initial read found no review.
        with path.open("x") as handle:
            json.dump(submission, handle)
        try:
            self.github.api(f"{self.pulls}/reviews", payload=payload)
        except subprocess.CalledProcessError as error:
            if 400 <= (getattr(error, "http_status", None) or 0) < 500:
                path.unlink()  # GitHub rejected it, so nothing was posted; allow a corrected submission.
            raise

    def verify(self, submission=None, *, submit=False):
        """Return the verified verdict; never infer completion from an unowned review or a local file."""
        path = self.context / SUBMISSION_FILE
        if submission is None:
            if not path.exists():
                rejection = self.context / REJECTION_FILE
                if rejection.exists():
                    raise ReviewSuperseded(json.loads(rejection.read_text())["reason"])
                raise ValueError("No final review submission was declared")
            submission = json.loads(path.read_text())
        submission = validate_submission(submission)
        require(not path.exists() or json.loads(path.read_text()) == submission,
                "Final submission already declared; refusing a different review")
        self.require_target()
        payload, counts, marker = self.payload(submission)
        reviews = self.reviews()
        matching = [review for review in reviews if marker in (review.get("body") or "")]
        if not matching and submit:
            if any(self.owned(review) for review in reviews):
                reason = "Another review run submitted a review for this head; refusing a duplicate"
                # A rejected candidate, not a POST intent: completion still requires readback.
                write_json(self.context / REJECTION_FILE, {"reason": reason, "submission": submission})
                raise ReviewSuperseded(reason)
            require(not path.exists(), "Final submission was attempted but cannot be verified; refusing to repost")
            self.post(path, submission, payload)
            matching = [review for review in self.reviews() if marker in (review.get("body") or "")]
        require(len(matching) == 1, "Could not verify exactly one final review from this invocation")
        review = matching[0]
        expected_state = "CHANGES_REQUESTED" if payload["event"] == "REQUEST_CHANGES" else "COMMENTED"
        require(self.owned(review) and review.get("state") == expected_state and review.get("body") == payload["body"],
                "Final review author, head, timestamp, state or summary did not match")
        # Replies may arrive while the model wraps up. They are not part of the
        # declared inline set and must not invalidate an otherwise complete review.
        comments = [comment for comment in self.comments()
                    if comment.get("pull_request_review_id") == review["id"] and comment.get("in_reply_to_id") is None]
        require(Counter(map(anchor, comments)) == Counter(map(anchor, payload["comments"]))
                and all(self.owned(comment) for comment in comments),
                "Final review inline comments were not completely verified")
        # Recheck after the API reads so a moving PR cannot pass an obsolete review.
        self.require_target()
        return {
            "state": "failure" if counts[0] + counts[1] or not submission["converged"] else "success",
            "converged": submission["converged"], "rounds": submission["rounds"],
            "incomplete_reason": submission["incomplete_reason"],
            "p0": counts[0], "p1": counts[1], "review_id": review["id"], "review_url": review["html_url"],
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context-dir", type=Path, required=True)
    parser.add_argument("--input-file", type=Path, required=True)
    args = parser.parse_args()
    run = json.loads((args.context_dir / RUN_FILE).read_text())
    result = Delivery(args.context_dir, run).verify(json.loads(args.input_file.read_text()), submit=True)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
