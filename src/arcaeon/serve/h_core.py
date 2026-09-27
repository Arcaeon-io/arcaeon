# SPDX-License-Identifier: MIT
"""Handler core, no HTTP: a request dict in, the CLI's JSON dict plus `exit` out.

Never a second implementation. Each function builds the argv the CLI would
get and runs the CLI's own verb function (arcaeon.cli.HANDLERS), capturing
what it prints. So `h_core.verify({"ledger": p})` and `arcaeon verify p` run
the same code, and tests/serve/test_parity.py holds them key for key.

What comes back:
- the verb's stdout parsed as a JSON object, when it is one (verify,
  reconcile, receipt verify, status --json), plus `exit`;
- `log` prints the new chain value, which comes back as `{"chain": ...}`;
- a verb that prints plain text (audit verify) comes back as `{"output": ...}`;
- when stdout is not a JSON object and the verb wrote to stderr (a usage
  error, a refusal), that text rides along as `error`.

Exit codes are arcaeon.verdict's one table: 0 good, 1 a bad finding, 2 bad
usage, 3 COULD NOT LOOK. A verb that raises is COULD NOT LOOK (3), naming
the exception class only, the same answer the CLI's front door gives.

Capturing stdout swaps sys.stdout for the whole process, so calls run one at
a time under a lock; a threaded server stays correct, just serial here.
The activity journal is not written from here: the server journals each HTTP
call itself (K015), so one call is never counted twice.
"""
from __future__ import annotations

import contextlib
import io
import json
import threading

from arcaeon import verdict as V

_LOCK = threading.Lock()


def _usage(msg: str) -> dict:
    return {"exit": V.EXIT_USAGE, "error": msg}


def run_verb(verb: str, argv: list[str]) -> tuple[int, str, str]:
    """(exit, stdout, stderr) of the CLI verb function, captured."""
    from arcaeon import cli
    out, err = io.StringIO(), io.StringIO()
    with _LOCK, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.HANDLERS[verb](list(argv))
        except KeyboardInterrupt:
            raise
        except Exception as e:  # noqa: BLE001  the CLI front door's own rule
            print(f"arcaeon {verb}: could not finish: {type(e).__name__} [internal_error]",
                  file=err)
            rc = V.EXIT_COULD_NOT_LOOK
    rc = 0 if rc is None else rc
    return (rc if isinstance(rc, int) else V.EXIT_USAGE), out.getvalue(), err.getvalue()


def _result(rc: int, stdout: str, stderr: str) -> dict:
    try:
        parsed = json.loads(stdout) if stdout.strip() else None
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        return {**parsed, "exit": rc}
    res: dict = {"exit": rc}
    if stdout.strip():
        res["output"] = stdout.rstrip("\n")
    if stderr.strip():
        res["error"] = stderr.strip()
    return res


def _str(body: dict, name: str) -> str | None:
    v = body.get(name)
    return v if isinstance(v, str) and v else None


def _need(body, *names) -> dict | None:
    if not isinstance(body, dict):
        return _usage("the request body must be a JSON object")
    for n in names:
        if _str(body, n) is None:
            return _usage(f"missing required field '{n}'")
    return None


# --- the six --------------------------------------------------------------------

def verify(body: dict) -> dict:
    """`arcaeon verify <ledger> [--strict] [--witness PINS [--ns NS]]`."""
    bad = _need(body, "ledger")
    if bad:
        return bad
    argv = [body["ledger"]]
    if body.get("strict"):
        argv.append("--strict")
    if _str(body, "witness"):
        argv += ["--witness", body["witness"]]
    if _str(body, "ns"):
        argv += ["--ns", body["ns"]]
    return _result(*run_verb("verify", argv))


def log(body: dict) -> dict:
    """`arcaeon log <ledger> '<row>'`: `row` and `fields` merge the way the
    CLI merges a JSON row and --field (fields over the row)."""
    bad = _need(body, "ledger")
    if bad:
        return bad
    row, fields = body.get("row"), body.get("fields")
    if row is None and fields is None:
        return _usage("log needs `row` or `fields`")
    if row is not None and not isinstance(row, dict):
        return _usage("`row` must be a JSON object")
    if fields is not None and not isinstance(fields, dict):
        return _usage("`fields` must be a JSON object")
    merged = {**(row or {}), **(fields or {})}
    rc, out, err = run_verb("log", [body["ledger"], json.dumps(merged, ensure_ascii=False)])
    if rc == V.EXIT_GOOD and out.strip() and "\n" not in out.strip():
        return {"chain": out.strip(), "exit": rc}
    return _result(rc, out, err)


def reconcile(body: dict) -> dict:
    """`arcaeon reconcile <tape_a> <tape_b> [--pin PIN]` (kind "tapes")."""
    if isinstance(body, dict) and body.get("kind", "tapes") != "tapes":
        return _usage(f"reconcile kind {body.get('kind')!r} is not handled here")
    bad = _need(body, "tape_a", "tape_b")
    if bad:
        return bad
    argv = [body["tape_a"], body["tape_b"]]
    if _str(body, "pin"):
        argv += ["--pin", body["pin"]]
    return _result(*run_verb("reconcile", argv))


def audit_verify(body: dict) -> dict:
    """`arcaeon audit verify <path>`."""
    bad = _need(body, "path")
    if bad:
        return bad
    return _result(*run_verb("audit", ["verify", body["path"]]))


def receipt_verify(body: dict) -> dict:
    """`arcaeon receipt verify <receipt>`."""
    bad = _need(body, "receipt")
    if bad:
        return bad
    return _result(*run_verb("receipt", ["verify", body["receipt"]]))


def status(body: dict | None = None) -> dict:
    """`arcaeon status --json`."""
    return _result(*run_verb("status", ["--json"]))
