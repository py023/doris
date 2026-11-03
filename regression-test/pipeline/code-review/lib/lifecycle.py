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

"""Build-private temporary workspaces and process cleanup."""

import tempfile
from pathlib import Path

from run_review_with_resume import ChildReaper


class Workspace:
    def __init__(self, root=None):
        self.temporary = tempfile.TemporaryDirectory(prefix="review-", dir=root)
        self.path = Path(self.temporary.name)

    def __enter__(self):
        self.reaper = ChildReaper()
        return self

    def __exit__(self, *_):
        # Auth writeback is attempted by this run's finalizer only. Never retain
        # credentials for another build to recover or upload later.
        try:
            self.reaper.reap()
        finally:
            self.temporary.cleanup()
