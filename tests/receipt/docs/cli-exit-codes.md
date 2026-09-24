# CLI exit-code matrix

`arcaeon-receipt`'s exit codes are part of its contract: a pre-filing gate,
a CI step, or a trainer script wires its own stop/continue logic straight to
the process exit code, never to parsing stdout. This table is the whole
contract, one row per subcommand (A-009). Source of truth is
`arcaeon_receipt/cli.py`; if this table and the code ever disagree, the code
wins and this file is stale.

| subcommand | exit 0 | exit 1 | exit 2 | exit 3 |
|---|---|---|---|---|
| `cite` | every detected citation came back `found` (no flagged checks) | bad `--path`, transport/token error (`RuntimeError`/`ValueError`/`OSError` from `cite.citation_receipt`, e.g. missing `COURTLISTENER_TOKEN`, oversize text) | -- (not used by `cite`) | at least one check is flagged (`not_found`, `invalid_reporter`, or `not_recognized_by_service`) |
| `ballot` | receipt built and written | bad ballot JSON path/parse, or a `ValueError`/`OSError` from `ballot.ballot_receipt` | -- (not used by `ballot`) | -- (not used: a ballot is an already-graded object with no flagged-check concept) |
| `verify` | `verify_receipt(...)["ok"]` is `True` | bad `--path` (can't load/parse the receipt JSON) | `verify_receipt(...)["ok"]` is `False` (body digest mismatch, broken ledger chain, or a failed OTS check) | -- (not used by `verify`) |
| `exhibit` | exhibit printed | bad `--path` (can't load/parse the receipt JSON) | -- (not used by `exhibit`) | -- (not used by `exhibit`) |

Notes:

- Exit 3 is deliberate and specific to `cite`: a pre-filing gate should stop
  on a flag, not on a clean receipt, and should not have to grep stdout to
  tell the two apart.
- `ballot` never returns 2 or 3 itself; run its output through `verify` (own
  exit codes above) to check tamper, and its own scope
  (`does_not_prove: ["the score is correct", "the sim was not attempted before"]`)
  on the receipt's face for everything else.
- Every subcommand's error path (exit 1) prints `error: <message>` to
  stderr and nothing else useful to stdout; a caller that only checks the
  return code still gets a diagnosable stderr line.
- Covered by test: `tests/test_receipts.py::test_cite_cli_exit_codes` (0/2/3
  via `cli_main()` directly) and
  `tests/test_receipts.py::test_cite_cli_subprocess_exit_3_on_flagged_receipt`
  (3, via a real subprocess -- A-010) for `cite`;
  `tests/test_ballot.py::test_ballot_cli_subprocess_exit_codes` (0/1, real
  subprocess) for `ballot`.
