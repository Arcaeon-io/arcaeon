# Snyk agent-scan fixtures

Shape from R15, not a live capture.

These files were written by hand from the published Snyk agent-scan (formerly
Invariant mcp-scan) JSON output notes: `docs/json-output.md`,
`models/api/v20260710.py` and `docs/issue-codes.md` in the `snyk/agent-scan`
repository, as summarised in the Batch 200 research note R15. No scanner was run,
no Snyk account was used and nothing was sent anywhere. Every name, path,
message and evidence string is synthetic.

- `v06_clean.json`: v0.6+ `scan_path_responses` shape, one path, two servers and
  one skill, every `risk_indexes` empty, no errors.
- `v06_findings.json`: v0.6+ shape with scored risks (0 to 1000) on a server
  and a skill, a non-numeric score, a server error and a path error.
- `v05_findings.json`: v0.5.x path-keyed shape with E, W, X and an unknown
  issue code, a clean server and a server error. In this shape a server's
  `signature` is its tool catalog, not a cryptographic signature.

What R15 marks unverified, and so what these fixtures cannot settle: whether
agent-scan applies a score threshold of its own (none is documented), whether
change detection now happens server-side, and the exact JSON a current CLI build
prints for a skill-only scan.
