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
import time
from collections import Counter
from pathlib import Path

from process import require, write_json
from review_github_api import request_json

SUBMISSION_FILE = "review-submission.json"
REJECTION_FILE = "review-submission-rejected.json"
RUN_FILE = "review-run.json"
RESULT_FILE = "review-result.json"
PRIORITY = re.compile(r"^\[P([0-3])\]\s+\S")


def priority(body):
    match = PRIORITY.match(body)
    if match is None:
        raise ValueError("Every finding must start with [P0], [P1], [P2] or [P3]")
    return int(match.group(1))


def validate_submission(value):
    fields = {"body", "comments", "existing_blocking_comment_ids", "converged", "rounds", "incomplete_reason"}
    require(isinstance(value, dict) and set(value) == fields, f"Final review requires {sorted(fields)}")
    require(type(value["converged"]) is bool, "converged must be a boolean")
    require(type(value["rounds"]) is int and 1 <= value["rounds"] <= 3, "rounds must be an integer from 1 to 3")
    reason = value["incomplete_reason"]
    require(isinstance(reason, str), "incomplete_reason must be text")
    require(not reason.strip() if value["converged"] else value["rounds"] == 3 and bool(reason.strip()),
            "Only a non-converged review after three rounds requires an incomplete_reason")
    require(isinstance(value["body"], str) and value["body"].strip(), "Final review summary is empty")
    require(isinstance(value["comments"], list), "comments must be an array")
    for comment in value["comments"]:
        require(isinstance(comment, dict) and set(comment) == {"path", "position", "body"},
                "Each finding requires path, position and body")
        require(isinstance(comment["path"], str) and comment["path"], "Finding path is empty")
        require(type(comment["position"]) is int and comment["position"] > 0, "Finding position must be positive")
        require(isinstance(comment["body"], str), "Finding body must be text")
        priority(comment["body"])
    ids = value["existing_blocking_comment_ids"]
    require(isinstance(ids, list) and all(type(i) is int and i > 0 for i in ids),
            "Existing blocking comment IDs must be positive integers")
    require(len(set(ids)) == len(ids), "Existing blocking comment IDs must be unique")
    return value


def api(path, remaining, *, payload=None, paginated=False):
    return request_json(path, payload=payload, pages=paginated, timeout=min(30, remaining()))


def check_target(run, remaining):
    root = f"repos/{run['repository']}/pulls/{run['pr_number']}"
    pr = api(root, remaining)
    if (pr["state"] != "open" or pr["head"]["sha"] != run["head_sha"]
            or pr["base"]["sha"] != run["base_sha"]):
        raise ValueError("PR base/head or open state changed; final review is stale")
    return root


def review_payload(submission, run, root, remaining):
    counts = [0, 0, 0, 0]
    for comment in submission["comments"]:
        counts[priority(comment["body"])] += 1
    # Previously reported findings are not posted again. The reviewer must
    # explicitly reconfirm which existing P0/P1 findings still apply to this head.
    ids = submission["existing_blocking_comment_ids"]
    if ids:
        comments = {c["id"]: c for c in api(f"{root}/comments", remaining, paginated=True)}
        for comment_id in ids:
            comment = comments.get(comment_id)
            if comment is None or comment.get("in_reply_to_id") is not None:
                raise ValueError(f"Existing blocking finding {comment_id} is missing or a reply")
            # Older reviews may bold the whole heading or only the priority.
            # Normalize existing comments only; new findings keep their strict format.
            body = re.sub(r"^\*\*(\[P[0-3]\])(?:\*\*)?", r"\1", comment["body"], count=1)
            level = priority(body)
            if level > 1:
                raise ValueError(f"Existing finding {comment_id} is not P0/P1")
            counts[level] += 1
    # The marker binds the entire declared final submission to this invocation,
    # including the deduplicated findings. A parallel run cannot satisfy it.
    digest = hashlib.sha256(json.dumps(submission, sort_keys=True).encode()).hexdigest()
    marker = f"<!-- code-review-completion:{run['token']}:{digest} -->"
    body = submission["body"]
    # Render the declared convergence state ourselves and bind it to the same
    # digest/readback as the findings. A delivered review can still be incomplete.
    if submission["converged"]:
        body += f"\n\nReview converged after {submission['rounds']} round(s)."
    else:
        body += (
            "\n\n**Review did not converge after 3 rounds. This automated review cannot pass the review check.**"
            f"\n\n{submission['incomplete_reason']}"
        )
    if ids:
        body += "\n\nExisting P0/P1 findings confirmed for this head: " + ", ".join(
            f"https://github.com/{run['repository']}/pull/{run['pr_number']}#discussion_r{i}"
            for i in ids
        )
    body += f"\n\n{marker}"
    return {
        "commit_id": run["head_sha"],
        "event": "REQUEST_CHANGES" if counts[0] + counts[1] else "COMMENT",
        "body": body,
        "comments": submission["comments"],
    }, counts, marker


def verify_completion(context, run, remaining, *, submit=False, submission=None):
    """Never infer completion from an unowned review or a local result file."""
    path = context / SUBMISSION_FILE
    if submission is None:
        if not path.exists():
            rejection = context / REJECTION_FILE
            if rejection.exists():
                raise ValueError(json.loads(rejection.read_text())["reason"])
            raise ValueError("No final review submission was declared")
        submission = json.loads(path.read_text())
    submission = validate_submission(submission)
    if path.exists() and json.loads(path.read_text()) != submission:
        raise ValueError("Final submission already declared; refusing a different review")
    root = check_target(run, remaining)
    payload, counts, marker = review_payload(submission, run, root, remaining)
    reviews = api(f"{root}/reviews", remaining, paginated=True)
    matching = [r for r in reviews if marker in (r.get("body") or "")]
    if not matching and submit:
        if any(r.get("user", {}).get("login") == run["review_author"]
               and r.get("commit_id") == run["head_sha"]
               and (r.get("submitted_at") or "") >= run["started_at"] for r in reviews):
            reason = "Another bot review was submitted during this run; refusing duplicate submission"
            # This is a rejected candidate, not a POST intent or proof of delivery.
            # Keep it separate so completion still requires exact GitHub readback.
            write_json(context / REJECTION_FILE, {"reason": reason, "submission": submission})
            raise ValueError(reason)
        if path.exists():
            raise ValueError("Final submission was attempted but cannot be verified; refusing to repost")
        # Persist the complete intent before POST: if the response is lost, the
        # runner can read back this exact review without repeating the write.
        # Exclusive creation also prevents two accidental simultaneous helper
        # invocations from both posting after their initial read found no review.
        with path.open("x") as handle:
            json.dump(submission, handle)
        api(f"{root}/reviews", remaining, payload=payload)
        matching = [r for r in api(f"{root}/reviews", remaining, paginated=True)
                    if marker in (r.get("body") or "")]
    if len(matching) != 1:
        raise ValueError("Could not verify exactly one final review from this invocation")
    review = matching[0]
    expected_state = "CHANGES_REQUESTED" if payload["event"] == "REQUEST_CHANGES" else "COMMENTED"
    if (review.get("user", {}).get("login") != run["review_author"]
            or review.get("commit_id") != run["head_sha"]
            or (review.get("submitted_at") or "") < run["started_at"]
            or review.get("state") != expected_state
            or review.get("body") != payload["body"]):
        raise ValueError("Final review author, head, timestamp, state or summary did not match")
    # Replies may arrive while the model wraps up. They are not part of the
    # declared inline set and must not invalidate an otherwise complete review.
    comments = [c for c in api(f"{root}/reviews/{review['id']}/comments", remaining, paginated=True)
                if c.get("in_reply_to_id") is None]
    expected = Counter((c["path"], c["position"], c["body"]) for c in payload["comments"])
    actual = Counter((c["path"], c.get("position"), c["body"]) for c in comments)
    if actual != expected or any(
        c.get("user", {}).get("login") != run["review_author"]
        or c.get("commit_id") != run["head_sha"] for c in comments
    ):
        raise ValueError("Final review inline comments were not completely verified")
    # Recheck after the API reads so a moving PR cannot pass an obsolete review.
    check_target(run, remaining)
    return {
        "state": "failure" if counts[0] + counts[1] or not submission["converged"] else "success",
        "converged": submission["converged"], "rounds": submission["rounds"],
        "incomplete_reason": submission["incomplete_reason"],
        "p0": counts[0], "p1": counts[1], "review_id": review["id"],
        "review_url": review["html_url"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context-dir", type=Path, required=True)
    parser.add_argument("--input-file", type=Path, required=True)
    args = parser.parse_args()
    run = json.loads((args.context_dir / RUN_FILE).read_text())

    def remaining():
        seconds = run["deadline"] - time.monotonic()
        if seconds <= 0:
            raise TimeoutError("Review's shared time budget was exhausted")
        return seconds

    result = verify_completion(
        args.context_dir, run, remaining, submit=True,
        submission=json.loads(args.input_file.read_text()),
    )
    print(json.dumps(result))


if __name__ == "__main__":
    main()
