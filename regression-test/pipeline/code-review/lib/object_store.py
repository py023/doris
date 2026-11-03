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

"""OSS operations used by package installation, auth and session archival."""

import subprocess

from process import sh


class ObjectStore:
    def __init__(self, executable, *, config_file, timeout=None):
        self.command = (executable, "-c", str(config_file))
        self.timeout = timeout

    def _run(self, *arguments, capture=True, **transport):
        flags = [f"--{key.replace('_', '-')}={value}" for key, value in transport.items()]
        return sh(*self.command, *flags, *arguments, timeout=self.timeout, capture=capture)

    def list(self, prefix):
        lines = self._run("ls", prefix, "-s").stdout.splitlines()
        return [line.strip() for line in lines if line.strip().startswith("oss://")]

    def download(self, source, destination, *, optional=False, **transport):
        try:
            self._run("cp", "-f", source, str(destination), **transport)
            return True
        except subprocess.CalledProcessError:
            if not optional:
                raise
            return False

    def upload(self, source, destination, **transport):
        self._run("cp", "-f", str(source), destination, **transport)

    def exists(self, source):
        return source in self.list(source)

    def session_exists(self, source):
        # The original session step attempted upload whenever stat failed.
        try:
            self._run("stat", source)
            return True
        except subprocess.CalledProcessError:
            return False
