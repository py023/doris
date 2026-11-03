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

"""The review target, its private checkout, and every review input written for Codex."""

import json
import logging
import re
import shlex
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from process import RECOVERABLE, boolean, redact, require, require_full_sha, sh, step, write_json

SKILL_PATH = ".claude/skills/code-review/SKILL.md"
# Release branches that may predate the review skill; it is then read from the trusted revision.
SKILL_FALLBACK_BRANCHES = {"branch-4.2", "branch-4.1", "branch-4.0"}
GUIDE_REFERENCE = re.compile(r"`([^`\n]+/AGENTS\.md)`")
READ_SKILL = "Before reviewing code, read and follow `{path}`. Pass this exact path to every review subagent.\n"
FALLBACK_NOTE = (
    "The workflow supplied missing guidance from {revision}. Existing checkout guides and branch code take "
    "precedence. Use fallback guides as checklists; verify rules against this branch and do not assume newer "
    "layouts or features exist. Source-code paths are relative to the repository root.\n")


@dataclass(frozen=True)
class Target:
    number: int
    head: str
    base: str
    focus: str = ""
    manage_status: bool = True

    @classmethod
    def resolve(cls, event, github):
        """A dispatch names its head/base; a /review comment reviews the live PR."""
        live = github.pull(event.pr_number)
        if event.name == "workflow_dispatch":
            head, base = event.inputs["head_sha"], event.inputs["base_sha"]
            manage_status = boolean(event.inputs.get("manage_status", True))
        else:
            head, base, manage_status = live["head"]["sha"], live["base"]["sha"], True
        require_full_sha("head", head)
        require_full_sha("base", base)
        require(not manage_status or (head, base) == (live["head"]["sha"], live["base"]["sha"]),
                "Refusing to update status for a PR/head/base mismatch")
        return cls(event.pr_number, head, base, event.focus, manage_status)


def required_agents(root, changed):
    """AGENTS.md files on the path from the repository root to every changed file, root first."""
    candidates = {"AGENTS.md": None}
    for name in changed:
        for parent in reversed(PurePosixPath(name).parents):
            if str(parent) != ".":
                candidates[f"{parent}/AGENTS.md"] = None
    return [name for name in candidates if (root / name).is_file()]


class ReviewContext:
    """The private PR checkout and the context directory that Codex reads inside it."""

    def __init__(self, options, github, target, workspace):
        self.options, self.github, self.target = options, github, target
        self.root = workspace.path / "pr"
        self.dir = None

    def git(self, *args, capture=True):
        return sh("git", *args, cwd=self.root, timeout=self.options.command_timeout, capture=capture).stdout

    def write(self, name, text):
        (self.dir / name).write_text(text)

    def checkout(self):
        sh("git", "clone", "--filter=blob:none", "--no-checkout", "--no-tags", "--",
           self.options.repository_url, str(self.root), timeout=self.options.command_timeout)
        self.git("fetch", "--no-tags", "origin", self.target.head, self.target.base, capture=False)
        self.git("checkout", "--detach", self.target.head, capture=False)

    def prepare(self):
        self.dir = Path(tempfile.mkdtemp(prefix=".code-review.", dir=self.root))
        with step("Fetch existing PR review threads", self.options.threads_timeout):
            self.write_threads()
        with step("Prepare authoritative PR context and review prompt", self.options.context_timeout):
            self.write("review_focus.txt", self.target.focus + "\n" if self.target.focus.strip()
                       else "No additional user-provided review focus.\n")
            branch, guides = self.write_diff()
            self.write_prompt(guides, self.review_skill(branch))

    def write_threads(self):
        """Existing inline threads are auxiliary context: a failure to load them is reported, not fatal."""
        try:
            comments = self.github.api(f"pulls/{self.target.number}/comments?per_page=100", pages=True)
            comments.sort(key=lambda item: (item.get("in_reply_to_id") or item["id"], item["id"]))
            self.write("pr_review_comments.json", json.dumps(comments))
            threads = {}
            for comment in comments:
                threads.setdefault(comment.get("in_reply_to_id") or comment["id"], []).append(comment)
            limit, sections = self.options.context_body_chars, []
            for thread in sorted(threads.values(), key=lambda items: items[0].get("created_at", ""),
                                 reverse=True)[:self.options.context_threads]:
                root = thread[0]
                line = root.get("line") or root.get("original_line") or "n/a"
                lines = [f"### {root.get('path', '(unknown path)')}:{line}", f"URL: {root.get('html_url', '')}",
                         "Comments:"]
                for comment in thread:
                    body = comment.get("body") or ""
                    body = body[:limit] + "...(truncated)" if len(body) > limit else body
                    kind = "reply" if comment.get("in_reply_to_id") else "original comment"
                    lines.append(f"- {(comment.get('user') or {}).get('login', 'unknown')} "
                                 f"at {comment.get('created_at', '')} ({kind}):")
                    lines.extend("    " + line for line in body.splitlines())
                sections.append("\n".join(lines))
            text = "\n\n".join(sections) or "No existing inline review comments or replies were found for this PR."
        except RECOVERABLE as error:
            logging.warning("Could not load existing review threads (%s)", type(error).__name__)
            details = redact(getattr(error, "stderr", None) or str(error))
            self.write("pr_review_comments_error.log", details + "\n")
            text = ("Existing PR review threads could not be fetched or formatted for this run.\n\n"
                    "Proceed with the automated review without this auxiliary context.\n\n\n"
                    "Fetch/format error details:\n" + "\n".join("    " + line for line in details.splitlines()))
        self.write("pr_review_threads.md", text + "\n")

    def write_diff(self):
        """Write the authoritative diff and AGENTS.md list; return the base branch and the guide block."""
        head, base = self.target.head, self.target.base
        require(self.git("rev-parse", "HEAD").strip() == head, "Checkout does not match the requested review head")
        live = self.github.require_target(self.target.number, head, base)
        require(self.git("rev-parse", "--is-shallow-repository").strip() == "false",
                "Full commit history is required for the authoritative PR diff")
        changed = self.git("diff", "--name-only", "--no-ext-diff", f"{base}...{head}")
        self.write("pr_changed_files.txt", changed)
        self.write("pr.diff", self.git("diff", "--no-ext-diff", "--no-color", f"{base}...{head}"))
        agents = required_agents(self.root, changed.splitlines())
        self.write("required_agents.txt", "".join(path + "\n" for path in agents))
        return live["base"]["ref"], "".join(f"- {path}\n" for path in agents) or "- No AGENTS.md files found.\n"

    def review_skill(self, branch):
        """The instruction naming the review skill; old release branches get it from the trusted revision."""
        if branch not in SKILL_FALLBACK_BRANCHES:
            return "Before reviewing code, read and strictly follow the code review skill in this repository.\n"
        if (self.root / SKILL_PATH).is_file():
            return READ_SKILL.format(path=SKILL_PATH)
        revision = self.options.trusted_revision
        require_full_sha("trusted revision", revision)
        if sh("git", "cat-file", "-e", f"{revision}^{{commit}}", cwd=self.root, capture=True, check=False).returncode:
            self.git("fetch", "--no-tags", "origin", revision, capture=False)
        bundle, sources = self.dir / "review-guidance", {}

        def trusted(name):
            target = bundle / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(self.git("show", f"{revision}:{name}"))
            return target

        def guide(match):
            name = match[1]
            if "..." in PurePosixPath(name).parts:  # A placeholder such as `.../AGENTS.md`.
                return match[0]
            require(not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts,
                    "Guide path escapes the repository")
            if name not in sources:
                local = self.root / name
                if local.is_file():
                    require(local.resolve().is_relative_to(self.root), "Guide path escapes the repository")
                else:
                    local = trusted(name)
                sources[name] = local.relative_to(self.root).as_posix()
            return f"`{sources[name]}`"

        skill = trusted(SKILL_PATH)
        skill.write_text(GUIDE_REFERENCE.sub(guide, skill.read_text()))
        path = skill.relative_to(self.root).as_posix()
        write_json(self.dir / "review_guidance_sources.json",
                   dict(base_ref=branch, trusted_ref=revision, skill=path, guides=sources))
        return READ_SKILL.format(path=path) + FALLBACK_NOTE.format(revision=revision)

    def write_prompt(self, guides, skill):
        templates, relative = self.options.templates, self.dir.relative_to(self.root).as_posix()
        helper = Path(__file__).with_name("submit_review.py")
        replacements = {
            "PLACEHOLDER_REPO": self.github.repository,
            "PLACEHOLDER_PR_NUMBER": str(self.target.number),
            "PLACEHOLDER_HEAD_SHA": self.target.head,
            "PLACEHOLDER_BASE_SHA": self.target.base,
            "PLACEHOLDER_CONTEXT_DIR": relative,
            "PLACEHOLDER_REQUIRED_AGENTS_BLOCK": guides,
            "PLACEHOLDER_REVIEW_SKILL_BLOCK": skill,
            "PLACEHOLDER_SUBMIT_COMMAND": shlex.join([sys.executable, str(helper)]),
        }
        prompt = (templates / "review.txt").read_text()
        for placeholder, value in replacements.items():
            prompt = prompt.replace(placeholder, value)
        self.write("review_prompt.txt", prompt)
        self.write("subagent_review_findings.md", (templates / "ledger.txt").read_text())
        self.write("codex_goal_prompt.txt",
                   "You are performing automated code review in a CI worker, already in Codex goal mode. "
                   f"Before inspecting any code, read {relative}/review_prompt.txt verbatim as the complete "
                   "instruction set. Follow its review cycles and exit criteria, and reconfirm them at the end of "
                   "each cycle.\n")
