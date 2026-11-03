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

"""GitHub transport shared by review execution and status synchronization."""

import json

from review_github_api import decode_json, run_gh


class GitHub:
    def __init__(self, repository, *, env, timeout):
        self.repository = repository
        self.env = env
        self.timeout = timeout

    def api(self, path, *, payload=None, pages=False):
        command = ["gh", "api", f"repos/{self.repository}/{path}"]
        if pages:
            command += ["--paginate", "--slurp"]
        if payload is not None:
            command += ["--method", "POST", "--input", "-"]
        result = run_gh(
            command, env=self.env, timeout=self.timeout, text=True, check=True,
            capture_output=True, input=None if payload is None else json.dumps(payload),
        )
        data = decode_json(result, command)
        return [item for page in data for item in page] if pages else data

    def pull(self, number):
        return self.api(f"pulls/{number}")

    def status(self, head, context, state, description, url):
        return self.api(f"statuses/{head}", payload={
            "context": context, "state": state,
            "description": description, "target_url": url,
        })

    def comment(self, number, body):
        return self.api(f"issues/{number}/comments", payload={"body": body})
