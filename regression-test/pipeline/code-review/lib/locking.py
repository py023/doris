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

"""Host-local locks shared by every review agent on the same filesystem."""

import fcntl
import hashlib
import os
import time
from pathlib import Path


class LockTimeout(TimeoutError):
    pass


class FileLock:
    def __init__(self, directory, namespace, key, *, timeout):
        digest = hashlib.sha256(key.encode()).hexdigest()
        self.path = Path(directory) / namespace / (digest + ".lock")
        self.timeout = timeout
        self.fd = None

    def acquire(self, *, wait=True):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + self.timeout
        try:
            while True:
                try:
                    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return self
                except BlockingIOError:
                    if not wait:
                        self.release()
                        return None
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise LockTimeout(f"Timed out waiting for {self.path.parent.name} lock")
                    time.sleep(min(0.25, remaining))
        except BaseException:
            self.release()
            raise

    def release(self):
        if self.fd is not None:
            # Never unlink lock files: existing waiters must keep using this inode.
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *_):
        self.release()


class Locks:
    def __init__(self, root, *, timeout):
        self.root = Path(root)
        self.timeout = timeout

    def hold(self, namespace, key):
        return FileLock(self.root, namespace, key, timeout=self.timeout)
