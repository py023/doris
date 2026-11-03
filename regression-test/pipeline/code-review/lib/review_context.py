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

import json
import logging
import re
import shlex
import subprocess
import sys
from pathlib import Path, PurePosixPath

from process import require, require_full_sha, sh, step, write_json
from review_github_api import redact

SKILL_PATH = ".claude/skills/code-review/SKILL.md"


SKILL_FALLBACK_BRANCHES = {"branch-4.2", "branch-4.1", "branch-4.0"}


GUIDE_REFERENCE = re.compile(r"`([^`\n]+/AGENTS\.md)`")


def required_agents(root, changed):
    candidates = dict.fromkeys(["AGENTS.md", *[str(parent / "AGENTS.md")
        for name in changed for parent in reversed(PurePosixPath(name).parents) if str(parent) != "."]])
    return [name for name in candidates if (root / name).is_file()]


def prepare_review_skill(root, branch, revision, context):
    path = SKILL_PATH
    note = ""
    if branch in SKILL_FALLBACK_BRANCHES and not (root / path).is_file():
        require_full_sha("trusted revision", revision)
        context.resolve().relative_to(root)
        available = sh("git", "cat-file", "-e", f"{revision}^{{commit}}", cwd=root, capture=True, check=False)
        if available.returncode:
            sh("git", "fetch", "--no-tags", "origin", revision, cwd=root)

        def read_trusted(name):
            return sh("git", "show", f"{revision}:{name}", cwd=root, capture=True).stdout

        bundle, sources = context / "review-guidance", {}

        def guide(match):
            name = match[1]
            if "..." in PurePosixPath(name).parts:
                return match[0]
            require(not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts,
                    "Guide path escapes the repository")
            if name not in sources:
                target = root / name
                if target.is_file():
                    target.resolve().relative_to(root)
                else:
                    target = bundle / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(read_trusted(name))
                sources[name] = target.relative_to(root).as_posix()
            return f"`{sources[name]}`"

        skill = GUIDE_REFERENCE.sub(guide, read_trusted(path))
        target = bundle / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(skill)
        path = target.relative_to(root).as_posix()
        write_json(context / "review_guidance_sources.json",
                   dict(base_ref=branch, trusted_ref=revision, skill=path, guides=sources))
        note = (f"The workflow supplied missing guidance from {revision}. Existing checkout guides and branch code "
                "take precedence. Use fallback guides as checklists; verify rules against this branch and do not "
                "assume newer layouts or features exist. Source-code paths are relative to the repository root.\n")
    if branch not in SKILL_FALLBACK_BRANCHES:
        return "Before reviewing code, read and strictly follow the code review skill in this repository.\n"
    return f"Before reviewing code, read and follow `{path}`. Pass this exact path to every review subagent.\n" + note


def checkout(repository_url, directory, head, base, *, timeout):
    sh("git", "clone", "--filter=blob:none", "--no-checkout", "--no-tags",
       "--", repository_url, str(directory), timeout=timeout)
    sh("git", "fetch", "--no-tags", "origin", head, base, cwd=directory, timeout=timeout)
    sh("git", "checkout", "--detach", head, cwd=directory, timeout=timeout)


def existing_threads(github, number, context, *, max_threads, max_body_chars):
    try:
        comments = github.api(f"pulls/{number}/comments?per_page=100", pages=True)
        comments.sort(key=lambda item: (item.get("in_reply_to_id") or item["id"], item["id"]))
        (context / "pr_review_comments.json").write_text(json.dumps(comments))
        groups = {}
        for comment in comments:
            groups.setdefault(comment.get("in_reply_to_id") or comment["id"], []).append(comment)
        threads = sorted(groups.values(), key=lambda items: items[0].get("created_at", ""), reverse=True)
        sections = []
        for thread in threads[:max_threads]:
            root = thread[0]
            line = root.get("line") or root.get("original_line") or "n/a"
            lines = [f"### {root.get('path', '(unknown path)')}:{line}",
                     f"URL: {root.get('html_url', '')}", "Comments:"]
            for comment in thread:
                body = comment.get("body") or ""
                if len(body) > max_body_chars:
                    body = body[:max_body_chars] + "...(truncated)"
                kind = "reply" if comment.get("in_reply_to_id") else "original comment"
                lines.append(f"- {comment.get('user', {}).get('login', 'unknown')} "
                             f"at {comment.get('created_at', '')} ({kind}):")
                lines.extend("    " + line for line in body.splitlines())
            sections.append("\n".join(lines))
        body = "\n\n".join(sections) or "No existing inline review comments or replies were found for this PR."
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        # Existing threads remain auxiliary context, as in the original workflow.
        logging.warning("Could not load existing review threads (%s)", type(error).__name__)
        details = redact(getattr(error, "stderr", None) or str(error))
        (context / "pr_review_comments_error.log").write_text(details + "\n")
        body = ("Existing PR review threads could not be fetched or formatted for this run.\n\n"
                "Proceed with the automated review without this auxiliary context.\n\n\n"
                "Fetch/format error details:\n" + "\n".join("    " + line for line in details.splitlines()))
    (context / "pr_review_threads.md").write_text(body + "\n")


def prepare(github, pr_dir, target, *, trusted_revision, focus, timeout,
            max_threads, max_body_chars, context, threads_timeout, focus_timeout):
    number, head, base = target["number"], target["head"], target["base"]
    with step("Fetch existing PR review threads", threads_timeout):
        existing_threads(github, number, context, max_threads=max_threads, max_body_chars=max_body_chars)
    with step("Prepare user review focus", focus_timeout):
        (context / "review_focus.txt").write_text(
            focus + "\n" if focus.strip() else "No additional user-provided review focus.\n")
    with step("Prepare authoritative PR context and required AGENTS guides", timeout):
        actual = sh("git", "rev-parse", "HEAD", cwd=pr_dir, timeout=timeout, capture=True).stdout.strip()
        if actual != head:
            raise ValueError("Checkout does not match the requested review head")
        live = github.pull(number)
        if live["head"]["sha"] != head or live["base"]["sha"] != base:
            raise ValueError("PR changed while preparing review context")
        shallow = sh("git", "rev-parse", "--is-shallow-repository", cwd=pr_dir,
                     timeout=timeout, capture=True).stdout.strip()
        if shallow != "false":
            raise ValueError("Full commit history is required for the authoritative PR diff")
        changed = sh("git", "diff", "--name-only", "--no-ext-diff", f"{base}...{head}",
                     cwd=pr_dir, timeout=timeout, capture=True).stdout
        diff = sh("git", "diff", "--no-ext-diff", "--no-color", f"{base}...{head}",
                  cwd=pr_dir, timeout=timeout, capture=True).stdout
        (context / "pr_changed_files.txt").write_text(changed)
        (context / "pr.diff").write_text(diff)
        agents = required_agents(pr_dir, changed.splitlines())
        guides = "".join(f"- {path}\n" for path in agents) or "- No AGENTS.md files found.\n"
        (context / "required_agents.txt").write_text("".join(path + "\n" for path in agents))
        skill = prepare_review_skill(pr_dir, live["base"]["ref"], trusted_revision, context)
    return context, guides, skill


def render_prompt(github, pr_dir, target, context, guides, skill, templates):
    number, head, base = target["number"], target["head"], target["base"]
    relative = context.relative_to(pr_dir).as_posix()
    submit_command = shlex.join([sys.executable, str(Path(__file__).with_name("submit_review.py"))])
    prompt = (templates / "review.txt").read_text()
    replacements = {
        "PLACEHOLDER_REPO": github.repository,
        "PLACEHOLDER_PR_NUMBER": str(number),
        "PLACEHOLDER_HEAD_SHA": head,
        "PLACEHOLDER_BASE_SHA": base,
        "PLACEHOLDER_CONTEXT_DIR": relative,
        "PLACEHOLDER_REQUIRED_AGENTS_BLOCK": guides,
        "PLACEHOLDER_REVIEW_SKILL_BLOCK": skill,
        "PLACEHOLDER_SUBMIT_COMMAND": submit_command,
    }
    for placeholder, value in replacements.items():
        prompt = prompt.replace(placeholder, value)
    (context / "review_prompt.txt").write_text(prompt)
    (context / "subagent_review_findings.md").write_text((templates / "ledger.txt").read_text())
    (context / "codex_goal_prompt.txt").write_text(
        "You are performing automated code review in a CI worker, already in Codex goal mode. "
        f"Before inspecting any code, read {relative}/review_prompt.txt verbatim as the complete instruction set. "
        "Follow its review cycles and exit criteria, and reconfirm them at the end of each cycle.\n")
