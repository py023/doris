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

import ctypes
import json
import logging
import os
import re
import signal
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path


class StepTimeout(Exception):
    """A workflow step exhausted its wall-clock budget."""


@contextmanager
def environment(values, *, remove=()):
    """Scope Codex's environment to one invocation in the dedicated worker process."""
    previous = dict(os.environ)
    try:
        os.environ.update(values)
        for key in remove:
            os.environ.pop(key, None)
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


@contextmanager
def step(label, seconds):
    """Nested steps share the enclosing Linux worker deadline."""
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
    return subprocess.run(
        argv, cwd=cwd, env=env, timeout=timeout, input=input,
        capture_output=capture, check=check, text=True,
    )


PROCESS_EXIT_GRACE_SECONDS = 5


class ChildReaper:
    """Own orphaned commands in the standalone Linux helper, not the whole runner."""

    def __init__(self):
        self.children = Path(f"/proc/self/task/{os.getpid()}/children")
        self.children.read_text()
        prctl = ctypes.CDLL(None, use_errno=True).prctl
        prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
        prctl.restype = ctypes.c_int
        # PR_SET_CHILD_SUBREAPER: descendants that outlive Codex are reparented
        # to this helper, even if shell/PTY commands created new sessions.
        if prctl(36, 1, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))

    def reap(self):
        # Called only after Popen.wait() reaps Codex. This dedicated helper has
        # no other concurrent subprocesses; synchronous gh/help calls have returned.
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
    def __init__(self, root=None):
        self.temporary = tempfile.TemporaryDirectory(prefix="review-", dir=root)
        self.path = Path(self.temporary.name)

    def __enter__(self):
        self.reaper = ChildReaper()
        return self

    def __exit__(self, *_):
        # Credentials and checkouts live only as long as this build.
        try:
            self.reaper.reap()
        finally:
            self.temporary.cleanup()


def write_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


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
