# Next release: full suite, recorded (K145)

Not a release. Nothing here was pushed, uploaded or published; the version is
still 0.9.1 until the version item picks the next number.

## The run that counts

- Command: `py -m pytest -q -p no:cacheprovider` (no time cap; pytest-timeout
  is not installed), run from a clean detached worktree of branch
  `plugin-2026-09-27`, with `PYTHONPATH` set to that worktree's `src` and
  `ARCAEON_HOME` set to an empty temp directory.
- Tip at collection: `4556331` (K021R: changelog names changed_since_write),
  which includes K108R (`0df880c`, the origin/403 body-read fix). KH8R had not
  landed when the run started.
- Started 2026-09-27 08:45 PT, finished 09:16 PT.
- Last line, exactly:

```text
4631 passed, 35 skipped, 7 xfailed, 324 warnings in 1877.94s (0:31:17)
```

- Counts: 4631 passed, 0 failed, 0 errors, 35 skipped, 7 xfailed. The 9/25
  baseline was 3061 passed.
- Process exit: 1. No test failed; the exit comes from the root conftest's
  real-home guard (below), which sets the session status to 1 when a file
  under the real home changed during the run.

## The real-home guard's verdict: tripped, and the cause is outside this tree

The guard printed:

```text
REAL HOME WRITTEN: the suite changed 2 file(s) under the real home (ARCAEON_REAL_HOME_GUARD=0 skips this check): <home>\.arcaeon\activity.jsonl (10044 -> 10183 bytes); <home>\.mcp_vet\audit.jsonl (42990 -> 43752 bytes)
```

What changed: one `buy` line in the activity journal (08:51 PT) and two
`mcp_vet_scan` lines in the vet audit ledger, each naming a
`test_vet_scan_of_the_planted_fixture` temp directory from two different
pytest base temps (`pytest-2512`, `pytest-2518`). One session has one base
temp, so at least one of those lines came from another suite. During this run
at least two other pytest sessions were running on the same machine (another
worker's full suite and the heavy KH2/KH3/KH5 files), and the guard watches
the real home, not this process.

Attribution check: `tests/connector/test_connector.py` and `tests/test_buy.py`
rerun alone in the same worktree with a known `--basetemp`: 24 passed,
2 skipped, and neither real file changed by a byte (43752 and 10183 before and
after), and no line in the vet ledger names that base temp. So this tree's
tests did not write the real home when run in isolation. The guard's verdict
stays recorded as TRIPPED; a rerun with no other suite on the machine is the
way to see it pass.

## The earlier run, voided

A first full run on tip `f342a80` (08:17 to 08:43 PT) ended:

```text
4604 passed, 35 skipped, 7 xfailed, 324 warnings, 27 errors in 1580.99s (0:26:20)
```

All 27 errors are `FileNotFoundError: [WinError 3]` for the worktree's
`tests\serve` directory, raised in the root conftest's per-test chdir fixture:
another worker checked the shared worktree out to `4556331` mid-run, and the
directory was briefly absent while its files were rewritten. The errored
tests: `tests/serve/test_serve_journal.py` (3:
`test_a_verdict_with_no_reason_word_adds_no_key`,
`test_journal_off_writes_nothing`,
`test_a_journal_failure_never_changes_a_response`) and
`tests/serve/test_server.py` (24, from `test_health_is_200_ok_true` through
`test_the_real_command_serves_health_on_a_random_port`). Every one of them
passed in the run that counts. The same guard tripped on that run too (one
`buy` line, 9905 -> 10044 bytes, 08:34 PT).

## Caveat on the counted run

The shared worktree moved again during the counted run (to `faf4e5e`, the OA
commits). Tests were collected at `4556331`; a few files may have been read
after the move. A run on a worktree no one else touches would remove the
doubt.
