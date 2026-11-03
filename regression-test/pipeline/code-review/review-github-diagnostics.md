# GitHub request diagnostics

All review workers and submission helpers use `request_json` from the trusted
controller checkout. Failures retain the exit status, HTTP status, request ID,
rate-limit headers and bounded response excerpts in `--artifacts-dir/github-api`.
`GH_DEBUG=api` is captured in memory; request headers/body are discarded, and
response excerpts are redacted before truncation. Each failure has its own file.

Submission intent and rejected candidates are retained under `--artifacts-dir/review`.
TeamCity publishes `review-artifacts/**`; credentials and private workspaces are excluded.
Reads and commit-status writes retry transient failures (transport errors, HTTP 429 and 5xx) up to
three attempts, and every failed attempt has its own record. Comment and review POSTs never retry.
Diagnostic storage failures do not replace the original request failure.
