# Snyk agent-scan: public samples

Source: https://github.com/snyk/agent-scan/blob/69ce32c6e5ae67e5d688efee9e9c45f7de7046c4/docs/json-output.md
Commit: 69ce32c6e5ae67e5d688efee9e9c45f7de7046c4
Retrieved: 2026-10-05
Licence: Apache-2.0 (snyk/agent-scan)
Trimming: none; both are the doc's code blocks verbatim, including the doc's
own placeholder `"metadata": { "...": "..." }` in the v0.5 sample.
Redaction: none (paths are the doc's placeholders under `/Users/me`; the URL is
`.invalid`).

| file | what it is |
|---|---|
| `v06_scan_docs.json` | "`scan --json`" (v0.6 and later): one server risk (score 1000) and one skill risk (score 600) |
| `v05_scan_docs.json` | "JSON structure overview" (v0.5.x): one skill target with issue `E004` |

Result: pass, no change. With `broken_at_score=500` both v0.6 risks read BROKEN;
with 700 the 600-score risk reads COULD NOT LOOK; with no threshold both read
COULD NOT LOOK. The v0.5 `E004` reads BROKEN (`issue_error`). The repo holds no
captured scan output under `tests/`; these doc examples are the only public
samples found.
