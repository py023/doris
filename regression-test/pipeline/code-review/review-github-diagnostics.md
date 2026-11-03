# GitHub request diagnostics for code review

The review and status workers import `lib/review_github_api.py` from the
independent trusted master checkout. PR code is checked out into a separate
private workspace. The submission helper and head watchdog use the same
trusted module.

Python helpers use run_gh with captured text output, check=True and their timeout;
use decode_json when decoding its result. Request arguments, normal stdout,
write deduplication, permission decisions and retry policy remain unchanged.

On a failure, the helper prints a short diagnostic and saves one JSON record
under REVIEW_GITHUB_DIAGNOSTICS_DIR. Records include the command exit status or
timeout, the last HTTP method/path/status, GitHub request ID, rate-limit and
retry headers, gh version, and bounded response/stdout/stderr excerpts. A
successful gh exit followed by a Python JSON decode error is also recorded.
A transport failure without a response has status: null; it is not inferred
to be an HTTP error.

The helper captures GH_DEBUG=api in memory because gh can discard a malformed
error body and its HTTP status while parsing it. Outgoing headers, request
bodies and argv are never archived. Response headers use an allowlist.
Credential values and common credential fields are redacted before excerpts
are truncated. The response body is gh's formatted debug excerpt, not exact
wire bytes; gh may itself limit or omit it. Debug format changes may leave
fields unavailable. Hard termination of the helper can prevent recording.

Each failure uses a separate file so later cleanup errors do not overwrite it.
The CLI writes diagnostics under `--artifacts-dir/github-api`, outside the
private workspace, including when an optional operation catches an API failure.
TeamCity's artifact rule publishes `review-artifacts/**` as `review-diagnostics`.
The endpoint identifies the current or previous head. Diagnostic storage
failures do not replace the original request failure.

Submission evidence is retained under `--artifacts-dir/review`. Neither
credential files nor the full CODEX_HOME are published as build artifacts.

Local validation:

~~~sh
cd regression-test/pipeline/code-review
RUN_GH_HTTP_TESTS=1 python3 -m unittest discover -s tests -t .
~~~

The opt-in HTTP test uses real gh only against a loopback server, with fake
tokens and a temporary config; it never sends a request to GitHub. Linux-only
process-supervision tests require a Linux host.
