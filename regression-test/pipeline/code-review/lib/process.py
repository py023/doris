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

"""External commands. Business decisions stay in the workflow modules."""

import logging
import os
import signal
import subprocess
import time
from contextlib import contextmanager


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
    """Bound a whole step, including all its API calls and file operations.

    Workers run in a dedicated Linux process. A nested step cannot extend its
    enclosing job budget; restoring the timer also accounts for elapsed time.
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
