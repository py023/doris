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

"""Interpret GitHub events without executing commands or making API calls."""

from dataclasses import dataclass


PR_EVENTS = {"opened", "synchronize", "reopened", "ready_for_review", "edited", "closed"}
REVIEW_ASSOCIATIONS = {"MEMBER", "OWNER", "COLLABORATOR"}
LOCAL_REVIEW_MARKER = "<!-- doris-repo-review:v1:begin -->"


def boolean(value):
    if value is True or value == "true":
        return True
    if value is False or value == "false":
        return False
    raise ValueError(f"Expected a boolean, got {value!r}")


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
        # GitHub expressions startsWith/contains/equality ignore string case.
        return (self.is_pr_comment and self.comment.get("body", "").lower().startswith("/review")
                and self.comment.get("author_association", "").upper() in REVIEW_ASSOCIATIONS)

    @property
    def pr_number(self):
        if self.name == "workflow_dispatch":
            return int(self.inputs["pr_number"])
        if self.name == "pull_request_target":
            return int(self.data["pull_request"]["number"])
        return int(self.data["issue"]["number"])

    @property
    def local_pass(self):
        return self.is_pr_comment and LOCAL_REVIEW_MARKER in self.comment.get("body", "").lower()

    @property
    def skip(self):
        body = self.comment.get("body", "").lower()
        return self.is_pr_comment and not body.startswith("/review") and "skip buildall" in body

    @property
    def status_heads(self):
        if self.name != "pull_request_target" or self.data.get("action") not in PR_EVENTS:
            return []
        head = self.data["pull_request"]["head"]["sha"]
        heads = [head]
        before = self.data.get("before")
        if self.data["action"] == "synchronize" and before and before != head:
            heads.append(before)
        return heads
