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

"""Download and verify packages separately in each build's workspace."""

import hashlib
import json
import logging
from pathlib import Path

from process import sh


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def extract(archive, destination, *, prefix=None):
    if prefix is not None:
        listing = sh("tar", "-tzf", str(archive), capture=True).stdout.splitlines()
        if any(name not in {prefix, prefix + "/"} and not name.startswith(prefix + "/") for name in listing):
            raise ValueError(f"Archive contains content outside {prefix}")
    sh("tar", "-xzf", str(archive), "-C", str(destination))


def install_codex(store, directory, *, source, checksum, version):
    archive = directory / "codex-package.tar.gz"
    package = directory / "codex-package"
    store.download(source, archive)
    if digest(archive) != checksum:
        raise ValueError("Codex archive SHA256 does not match the configured package")
    package.mkdir()
    extract(archive, package)
    sh("sha256sum", "--check", "SHA256SUMS", cwd=package)
    if json.loads((package / "codex-package.json").read_text())["version"] != version:
        raise ValueError("Codex package version mismatch")
    return package / "bin/codex"


def restore_memories(store, source, home):
    archive = home / "memories.tar.gz"
    try:
        if store.download(source, archive, optional=True) and archive.stat().st_size:
            extract(archive, home, prefix="memories")
        else:
            logging.info("No memories archive available; continuing with empty memories")
    finally:
        archive.unlink(missing_ok=True)
    memories = home / "memories"
    memories.mkdir(mode=0o700, exist_ok=True)
    (memories / "memory_summary.md").touch(exist_ok=True)
    sh("chmod", "-R", "go-rwx", str(memories), check=False)
