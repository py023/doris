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

"""Process supervision, step budgets, secret redaction and small shared helpers."""

import ctypes
import json
import logging
import math
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import traceback
from contextlib import contextmanager
from pathlib import Path

PROCESS_EXIT_GRACE_SECONDS = 5
# Failures of external commands, APIs and their responses that a caller may report and
# survive. StepTimeout is deliberately absent so that no handler swallows a step budget.
RECOVERABLE = (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError)
SECRET_FIELD = (r"(?:access_token|refresh_token|id_token|token|api_key|secret|"
                r"client_secret|password|authorization|cookie|set-cookie)")


class StepTimeout(Exception):
    """A workflow step exhausted its wall-clock budget."""


def redact(value):
    """Remove credentials from text that may reach logs, artifacts or PR comments."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    value = value or ""
    for name, secret in os.environ.items():
        if re.search(r"(?:TOKEN|SECRET|PASSWORD|(?:^|_)KEY|(?:^|_)AK|(?:^|_)SK)$", name) and secret:
            for encoded in (secret, json.dumps(secret)[1:-1]):
                value = value.replace(encoded, "[REDACTED]")
    value = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+)\b", "[REDACTED]", value)
    value = re.sub(r'(?i)(["\']?' + SECRET_FIELD + r'["\']?\s*[:=]\s*)("(?:\\.|[^"\\])*"|[^\r\n,}]+)',
                   r'\1"[REDACTED]"', value)
    value = re.sub(r"(https?://)[^/\s:@]+:[^/@\s]+@", r"\1[REDACTED]@", value)
    return re.sub(r"(?i)([?&](?:token|access_token|signature|sig|key)=)[^&\s\"']+", r"\1[REDACTED]", value)


def log_failure(label, error):
    """Log the redacted message and code locations, never argv or local variable values."""
    frames = "".join(traceback.format_tb(error.__traceback__)).rstrip()
    logging.error("%s failed (%s): %s\n%s", label, type(error).__name__, redact(str(error)), frames)


@contextmanager
def step(label, seconds):
    """Bound a block by SIGALRM; nested steps share the enclosing deadline.

    A failure escaping a step is tagged with the innermost step label.
    """
    logging.info("%s", label)
    started = time.monotonic()
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)

    def expired(signum, frame):
        if previous_timer[0] and previous_timer[0] <= seconds:
            previous_handler(signum, frame)
        raise StepTimeout(f"{label} timed out after {seconds:g} seconds")

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, min(seconds, previous_timer[0]) if previous_timer[0] else seconds)
    try:
        yield
    except BaseException as error:
        if not hasattr(error, "step_label"):
            error.step_label = label
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0]:
            signal.setitimer(signal.ITIMER_REAL,
                             max(0.000001, previous_timer[0] - (time.monotonic() - started)),
                             previous_timer[1])


def sh(*argv, cwd=None, env=None, timeout=None, capture=False, input=None, check=True):
    """Run argv without shell interpolation; stream output unless requested."""
    logging.info("Running %s", argv[0])
    return subprocess.run(argv, cwd=cwd, env=env, timeout=timeout, input=input,
                          capture_output=capture, check=check, text=True)


def stop(process):
    try:
        process.send_signal(signal.SIGINT)
        process.wait(timeout=PROCESS_EXIT_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    finally:
        process.kill()
        process.wait()


def supervise(command, stdout_path, stderr_path, timeout, *, reaper, env=None, poll=None, on_line=None):
    """Run a long-lived child and return its exit status, always reaping it and its descendants.

    stderr is streamed to this process's stderr; complete stdout lines go to on_line as they
    arrive. poll runs about once per second and may raise to stop the child.
    """
    deadline = time.monotonic() + timeout if timeout is not None else math.inf
    with (stdout_path.open("w") as stdout, stderr_path.open("w") as stderr,
          stdout_path.open(errors="replace") as lines, stderr_path.open(errors="replace") as errors):
        partial = ""

        def pump(final=False):
            nonlocal partial
            sys.stderr.write(errors.read())
            sys.stderr.flush()
            if on_line:
                *complete, partial = (partial + lines.read()).split("\n")
                for line in complete + ([partial] if final and partial else []):
                    on_line(line)

        process = None
        try:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr, env=env, start_new_session=True)
            while True:
                if poll:
                    poll()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    # Name only the executable: the remaining argv can hold a whole prompt.
                    raise subprocess.TimeoutExpired(command[0], timeout)
                try:
                    return process.wait(timeout=min(1, remaining))
                except subprocess.TimeoutExpired:
                    pump()
        finally:
            # Defer cancellation until the child and adopted descendants have been reaped.
            previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
            try:
                try:
                    if process is not None:
                        stop(process)
                finally:
                    reaper.reap()
                    pump(final=True)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)


class ChildReaper:
    """Own orphaned commands in this dedicated worker process."""

    def __init__(self):
        self.children = Path(f"/proc/self/task/{os.getpid()}/children")
        self.children.read_text()
        prctl = ctypes.CDLL(None, use_errno=True).prctl
        prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
        prctl.restype = ctypes.c_int
        # PR_SET_CHILD_SUBREAPER: descendants that outlive Codex are reparented
        # to this process, even if shell/PTY commands created new sessions.
        if prctl(36, 1, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))

    def reap(self):
        # Called only after the supervised child was waited for; this worker runs
        # no other concurrent subprocesses, so every remaining child is an orphan.
        deadline = time.monotonic() + PROCESS_EXIT_GRACE_SECONDS
        while children := self.children.read_text().split():
            if time.monotonic() >= deadline:
                raise OSError("Codex descendant cleanup did not finish; not resuming")
            for child in children:
                try:
                    fd = os.pidfd_open(int(child))
                except ProcessLookupError:
                    continue
                try:
                    # Kernel-verified parenthood plus a stable pidfd prevents
                    # signalling an unrelated process if a PID was recycled.
                    os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                    os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG)
                except (ChildProcessError, ProcessLookupError):
                    pass
                finally:
                    os.close(fd)
            # Killing one orphan can reparent its children to us on the next pass.
            time.sleep(0.01)


class Workspace:
    """Private build directory; credentials and checkouts live only as long as the build."""

    def __init__(self, root=None):
        self.root = root

    def __enter__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="review-", dir=self.root)
        self.path = Path(self.temporary.name).resolve()
        try:
            self.reaper = ChildReaper()
        except BaseException:
            self.temporary.cleanup()
            raise
        return self

    def __exit__(self, *_):
        try:
            self.reaper.reap()
        finally:
            self.temporary.cleanup()


def write_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def read_jsonl(path):
    """JSON objects of a JSONL file; a cancelled writer can leave a partial line, which is skipped."""
    events = []
    for line in path.read_text(errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def append_jsonl(path, value):
    with path.open("a") as handle:
        handle.write(json.dumps(value) + "\n")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def require_full_sha(name, value):
    require(re.fullmatch(r"[0-9a-fA-F]{40}", value) is not None, f"{name} is not a full SHA")


def boolean(value):
    if value is True or value == "true":
        return True
    if value is False or value == "false":
        return False
    raise ValueError(f"Expected a boolean, got {value!r}")
