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

"""Local review transports: real reads, recorded writes, isolated Codex process.

GitHub delivery/readback is simulated, not evidence of a real published review.
The host gh credentials stay in the parent process's environment/configuration;
Codex sees only a gateway that forwards GETs and records supported POSTs locally.
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from packages import digest
from process import sh
from review_github_api import redact


def record(path, value):
    with path.open("a") as output:
        output.write(json.dumps(value) + "\n")


class ReadOnlyObjectStore:
    def __init__(self, options):
        self.options = options
        self.journal = options.artifacts_dir / "oss-suppressed-writes.jsonl"
        if not re.fullmatch(r"[\w-]+:", options.rclone_remote):
            raise ValueError("--rclone-remote must be a configured remote name followed by ':'")

    def remote(self, source):
        if not source.startswith("oss://"):
            raise ValueError("Expected an oss:// object")
        return self.options.rclone_remote + source[len("oss://"):]

    def _run(self, *arguments):
        command = [self.options.rclone, *arguments, "--retries", "1", "--low-level-retries", "1"]
        if self.options.rclone_endpoint:
            command += ["--s3-endpoint", self.options.rclone_endpoint]
        return sh(*command, timeout=self.options.oss_timeout, capture=True)

    def list(self, prefix):
        parent, name = prefix.rsplit("/", 1)
        result = self._run("lsf", self.remote(parent), "--max-depth", "1", "--files-only")
        return [parent + "/" + item for item in result.stdout.splitlines() if item.startswith(name)]

    def download(self, source, destination, *, optional=False, **transport):
        destination = Path(destination)
        destination.unlink(missing_ok=True)
        try:
            self._run("copyto", self.remote(source), str(destination))
        except subprocess.CalledProcessError as error:
            # rclone 3/4 mean directory/file not found. Auth/network errors must
            # remain failures, including when reading optional account metadata.
            if optional and error.returncode in (3, 4):
                return False
            raise
        # copyto can report success for a missing source interpreted as an
        # empty directory. Never reuse an earlier candidate in that case.
        if not destination.is_file():
            if optional:
                return False
            raise FileNotFoundError(f"No object downloaded from {source}")
        return True

    def exists(self, source):
        return source in self.list(source)

    def session_exists(self, source):
        return self.exists(source)

    def upload(self, source, destination, **transport):
        entry = {"simulated": True, "operation": "upload", "destination": destination,
                 "size": Path(source).stat().st_size, "sha256": digest(source)}
        if Path(source).name == "auth.json":
            # A refresh can rotate the token even though OSS is read-only.
            # Preserve the new private copy outside artifacts for recovery.
            recovery = self.options.state_root / "auth-recovery" / (entry["sha256"] + ".json")
            recovery.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(source, recovery)
            recovery.chmod(0o600)
            entry["private_recovery_file"] = str(recovery)
        record(self.journal, entry)
        logging.info("Dry run: suppressed OSS upload to %s", destination)


class LocalGitHub:
    def __init__(self, options, env):
        self.options, self.host_env = options, dict(env)
        self.real_gh = shutil.which("gh", path=env.get("PATH"))
        self.writes = []
        self.lock = threading.RLock()
        self.journal = options.artifacts_dir / "github-suppressed-writes.jsonl"

    def read(self, path, *, pages=False):
        # Construct the command ourselves: never forward client argv, input,
        # credentials, host overrides or field flags to authenticated gh.
        command = [self.real_gh, "api", path, "--method", "GET"]
        if pages:
            command += ["--paginate", "--slurp"]
        response = sh(*command, env=self.host_env, timeout=self.options.api_timeout, capture=True)
        value = json.loads(response.stdout)
        return [item for page in value for item in page] if pages else value

    def call(self, argv, body):
        if argv == ["--version"]:
            return self.options.gateway_version + " (local read-only gateway)\n"
        if not argv or argv[0] != "api":
            raise ValueError("Local review supports gh api only; no GitHub write command is forwarded")
        parser = argparse.ArgumentParser(exit_on_error=False, add_help=False)
        parser.add_argument("path")
        parser.add_argument("--method", "-X", default="GET")
        parser.add_argument("--paginate", action="store_true")
        parser.add_argument("--slurp", action="store_true")
        parser.add_argument("--input")
        args, unknown = parser.parse_known_args(argv[1:])
        prefix = "repos/" + self.options.repository + "/"
        if unknown or not args.path.startswith(prefix) or any(c in args.path for c in ("%", "..", "#", "\\")):
            raise ValueError("Unsupported local gh request")
        path = urlsplit(args.path).path
        with self.lock:
            if args.method == "GET":
                if args.input:
                    raise ValueError("GET request must not contain input")
                local_comments = next((entry["comments"] for entry in self.writes
                                       if path == entry.get("comments_path")), None)
                if local_comments is not None:
                    value = local_comments
                else:
                    value = self.read(args.path, pages=args.paginate)
                    additions = [entry["response"] for entry in self.writes
                                 if path == entry["read_path"]]
                    if additions:
                        value = sorted([*value, *additions], key=lambda item: item["id"], reverse=True)
                return json.dumps([value] if args.slurp else value)
            if args.method != "POST" or args.input != "-" or args.paginate or args.slurp:
                raise ValueError("External writes are disabled")
            payload = json.loads(body)
            identifier = 9000000000000000 + len(self.writes)
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            response = {"id": identifier, "simulated": True, "html_url": self.url + f"/local/{identifier}",
                        "user": {"login": getattr(self.options, "review_author", "local-review")}}
            entry = {"simulated": True, "path": path, "payload": payload, "response": response,
                     "read_path": path}
            if re.fullmatch(re.escape(prefix) + r"pulls/\d+/reviews", path):
                if payload["event"] not in {"COMMENT", "REQUEST_CHANGES"}:
                    raise ValueError("Unsupported review event")
                response.update(commit_id=payload["commit_id"], body=payload["body"], submitted_at=timestamp,
                                state="COMMENTED" if payload["event"] == "COMMENT" else "CHANGES_REQUESTED")
                entry["comments_path"] = path + f"/{identifier}/comments"
                entry["comments"] = [dict(comment, id=identifier + index + 1, user=response["user"],
                                          commit_id=payload["commit_id"])
                                     for index, comment in enumerate(payload["comments"])]
            elif re.fullmatch(re.escape(prefix) + r"statuses/[0-9a-f]{40}", path):
                response.update(payload)
                entry["read_path"] = prefix + "commits/" + path.rsplit("/", 1)[1] + "/statuses"
            elif re.fullmatch(re.escape(prefix) + r"issues/\d+/comments", path):
                response.update(body=payload["body"], created_at=timestamp)
            else:
                raise ValueError("External writes are disabled; unsupported simulated endpoint")
            self.writes.append(entry)
            record(self.journal, entry)
            return json.dumps(response)

    def __enter__(self):
        gateway = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                try:
                    request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    response = {"stdout": gateway.call(request["argv"], request["stdin"]), "code": 0}
                except (Exception, SystemExit) as error:
                    response = {"stderr": redact(str(error)), "code": 1}
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())

        self.temporary = tempfile.TemporaryDirectory(prefix="review-local-", dir=self.options.temp_dir
                                                      if hasattr(self.options, "temp_dir") else None)
        self.path = Path(self.temporary.name)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:" + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.options.gateway_version = self.host_env["REVIEW_GH_VERSION"]
        wrapper = self.path / "gh"
        wrapper.write_text(
            f"#!{sys.executable}\nimport json, sys, urllib.request\n"
            "body = sys.stdin.read() if '--input' in sys.argv else ''\n"
            "data = json.dumps({'argv': sys.argv[1:], 'stdin': body}).encode()\n"
            f"request = urllib.request.Request({self.url!r}, data=data)\n"
            "opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))\n"
            f"with opener.open(request, timeout={self.options.api_timeout + 5 if self.options.api_timeout else None}) as response:\n"
            "    result = json.load(response)\n"
            "sys.stdout.write(result.get('stdout', ''))\n"
            "sys.stderr.write(result.get('stderr', ''))\n"
            "sys.exit(result['code'])\n"
        )
        wrapper.chmod(0o700)
        return self

    def environment(self, env):
        return {**env, "PATH": str(self.path) + os.pathsep + env["PATH"]}

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temporary.cleanup()

    def isolate_codex(self, binary, workspace, env):
        """Expose the private checkout/home and tools, excluding host credentials."""
        bwrap = shutil.which("bwrap")
        if bwrap is None:
            raise RuntimeError("--dry-run requires bubblewrap (bwrap) to isolate host credentials")
        tools = workspace.path / "local-bin"
        tools.mkdir()
        shutil.copy2(self.path / "gh", tools / "gh")
        shutil.copy2(shutil.which("rg", path=env["PATH"]), tools / "rg")
        home = workspace.path / "local-home"
        home.mkdir()
        command = [bwrap, "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
                   "--die-with-parent", "--new-session", "--clearenv"]
        for path in ("/usr", "/bin", "/lib", "/lib64", "/etc/ld.so.cache", "/etc/ssl",
                     "/etc/pki/ca-trust/extracted", "/etc/pki/tls/certs", "/etc/pki/tls/openssl.cnf",
                     "/etc/resolv.conf", "/etc/hosts",
                     "/etc/nsswitch.conf", "/etc/passwd", "/etc/group", "/etc/localtime"):
            if Path(path).exists():
                command += ["--ro-bind", path, path]
        controller = str(Path(__file__).resolve().parent)
        command += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                    "--ro-bind", controller, controller, "--ro-bind", str(binary.parent.parent), str(binary.parent.parent),
                    "--bind", str(workspace.path), str(workspace.path)]
        loader = getattr(self.options, "local_codex_loader", None)
        libraries = getattr(self.options, "local_codex_library_path", None)
        if bool(loader) != bool(libraries):
            raise ValueError("Local Codex loader and library path must be specified together")
        if loader:
            loader, libraries = loader.resolve(), libraries.resolve()
            loader.relative_to(libraries)
            # Keep /proc/self/exe pointing at codex itself. Invoking ld.so as
            # the executable breaks Codex's sibling code-mode-host discovery.
            # Mount compatible libc files inside this namespace only; every
            # Codex helper then uses the same runtime without patching the
            # verified package or changing the host's libraries.
            for library in libraries.glob("*.so.*"):
                for directory in ("/lib64", "/usr/lib64", "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu"):
                    target = Path(directory) / library.name
                    if target.is_file():
                        command += ["--ro-bind", str(library), str(target)]
        safe = {"HOME": str(home), "CODEX_HOME": env["CODEX_HOME"], "PATH": str(tools) + ":/usr/local/bin:/usr/bin:/bin",
                "GH_CONFIG_DIR": str(home / ".config/gh"), "GIT_CONFIG_NOSYSTEM": "1", "LANG": "C.UTF-8"}
        for key in ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
            if key in env:
                safe[key] = env[key]
        for key, value in safe.items():
            command += ["--setenv", key, value]
        command += [str(binary)]
        launcher = tools / "codex"
        launcher.write_text(f"#!{sys.executable}\nimport os, sys\ncommand = {command!r}\n"
                            "os.execv(command[0], command + sys.argv[1:])\n")
        launcher.chmod(0o700)
        return {**env, "PATH": str(tools) + os.pathsep + env["PATH"]}
