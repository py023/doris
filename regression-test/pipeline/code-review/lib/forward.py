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

"""Transport-only GitHub Actions adapter; event policy runs on TeamCity."""

import base64
import json
import logging
import urllib.error
import urllib.request


def event_snapshot(event):
    """Keep exactly the original fields consumed by the workflows.

    In particular, comment bodies are creation-event snapshots, not a later
    GitHub API read. Drop unused issue/PR bodies to bound the request size.
    """
    result = {"action": event.get("action"), "before": event.get("before"),
              "inputs": event.get("inputs", {}),
              "repository": {"full_name": event["repository"]["full_name"]},
              "sender": {"login": event.get("sender", {}).get("login")}}
    if "issue" in event:
        issue = event["issue"]
        result["issue"] = {"number": issue["number"], "pull_request": bool(issue.get("pull_request"))}
    if "comment" in event:
        comment = event["comment"]
        result["comment"] = {key: comment.get(key) for key in ("id", "body", "html_url", "author_association")}
        result["comment"]["user"] = {key: comment["user"][key] for key in ("id", "login")}
    if "pull_request" in event:
        pr = event["pull_request"]
        result["pull_request"] = {"number": pr["number"], "head": {"sha": pr["head"]["sha"]}}
    return result


def build_request(event, *, event_name, build_type, request_id, origin_url, chunk_size):
    encoded = base64.b64encode(json.dumps(event_snapshot(event), ensure_ascii=False).encode()).decode("ascii")
    chunks = [encoded[index:index + chunk_size] for index in range(0, len(encoded), chunk_size)]
    properties = {
        "env.REVIEW_EVENT_NAME": event_name,
        "env.REVIEW_REQUEST_ID": request_id,
        "env.REVIEW_ORIGIN_URL": origin_url,
        "env.REVIEW_EVENT_PARTS": str(len(chunks)),
        **{f"env.REVIEW_EVENT_{index:04d}": chunk for index, chunk in enumerate(chunks)},
    }
    # No PR branch, revision, executable path or trusted-source override is sent.
    return {"buildType": {"id": build_type}, "properties": {
        "property": [{"name": name, "value": value} for name, value in properties.items()]
    }}


def enqueue(server, token, payload, *, timeout):
    data = json.dumps(payload).encode()
    request = urllib.request.Request(server.rstrip("/") + "/app/rest/buildQueue", data=data, headers={
        "Authorization": "Bearer " + token, "Content-Type": "application/json", "Accept": "application/json",
    }, method="POST")
    # Send once: a failed response does not mean TeamCity rejected the build.
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            build = json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"TeamCity enqueue failed with HTTP {error.code}; inspect its queue") from None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        raise RuntimeError("TeamCity acceptance could not be confirmed; inspect its queue") from None
    logging.info("TeamCity accepted build %s: %s", build["id"], build.get("webUrl", ""))
    return build
