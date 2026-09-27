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

Content-in (K007): every function that takes a path also takes `content`
(the file's text) or `content_b64` (its bytes, base64); reconcile takes
`content_a` / `content_b` and their `_b64` forms. That is for an agent with
no file access. Nothing is written at the named path or under the served
root: the bytes go to a private temporary directory (created owner-only,
outside the root) that is removed before the answer returns, and the CLI's
own verb reads them there, so a content check runs the very same code as a
path check. The temporary path never reaches the answer: wherever the verb
printed it, the answer says `(content)` instead. A path and content for the
same file together is bad usage.

Capturing stdout swaps sys.stdout for the whole process, so calls run one at
a time under a lock; a threaded server stays correct, just serial here.
The activity journal is not written from here: the server journals each HTTP
call itself (K015), so one call is never counted twice.
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import io
import json
import os
import shutil
import tempfile
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


# --- content-in (K007) ---------------------------------------------------------

CONTENT_LABEL = "(content)"


class _Usage(ValueError):
    pass


def _content_bytes(body: dict, text_field: str, b64_field: str) -> bytes | None:
    text, b64 = body.get(text_field), body.get(b64_field)
    if text is not None and b64 is not None:
        raise _Usage(f"send `{text_field}` or `{b64_field}`, not both")
    if text is not None:
        if not isinstance(text, str):
            raise _Usage(f"`{text_field}` must be a string")
        return text.encode("utf-8", "surrogatepass")
    if b64 is not None:
        if not isinstance(b64, str):
            raise _Usage(f"`{b64_field}` must be a base64 string")
        try:
            return base64.b64decode(b64.encode("ascii"), validate=True)
        except (binascii.Error, ValueError, UnicodeEncodeError):
            raise _Usage(f"`{b64_field}` is not base64") from None
    return None


@contextlib.contextmanager
def _inputs(body, specs):
    """Yield ({path_field: path}, tmpdir) for each (path_field, text_field,
    b64_field): the path the request named, or a temporary file holding its
    content. The temporary directory is gone when the block ends."""
    if not isinstance(body, dict):
        raise _Usage("the request body must be a JSON object")
    paths: dict[str, str] = {}
    tmpdir = None
    try:
        for field, text_f, b64_f in specs:
            data = _content_bytes(body, text_f, b64_f)
            if data is None:
                if _str(body, field) is None:
                    raise _Usage(f"missing required field '{field}' "
                                 f"(or `{text_f}` / `{b64_f}`)")
                paths[field] = body[field]
                continue
            if body.get(field) is not None:
                raise _Usage(f"send `{field}` or `{text_f}`, not both")
            if tmpdir is None:
                tmpdir = tempfile.mkdtemp(prefix="arcaeon-content-")
            p = os.path.join(tmpdir, f"{field}.jsonl")
            with open(p, "wb") as fh:
                fh.write(data)
            paths[field] = p
        yield paths, tmpdir
    finally:
        if tmpdir is not None:
            shutil.rmtree(tmpdir, ignore_errors=True)


def _scrub(text: str, tmpdir: str | None, paths: dict) -> str:
    """Put `(content)` wherever a temporary path was printed."""
    if not tmpdir or not text:
        return text
    for p in sorted({*paths.values(), tmpdir}, key=len, reverse=True):
        if not p.startswith(tmpdir):
            continue
        for form in sorted({p, json.dumps(p)[1:-1], p.replace(os.sep, "/")},
                           key=len, reverse=True):
            text = text.replace(form, CONTENT_LABEL)
    return text


def _run_with(verb: str, body, specs, build) -> dict:
    """Materialize content, build the argv from the paths, run the verb."""
    try:
        with _inputs(body, specs) as (paths, tmpdir):
            rc, out, err = run_verb(verb, build(paths))
            return _result(rc, _scrub(out, tmpdir, paths), _scrub(err, tmpdir, paths))
    except _Usage as e:
        return _usage(str(e))


# --- the six --------------------------------------------------------------------

def verify(body: dict) -> dict:
    """`arcaeon verify <ledger> [--strict] [--witness PINS [--ns NS]]`;
    `content` / `content_b64` instead of `ledger` verifies text sent inline."""
    def build(paths):
        argv = [paths["ledger"]]
        if body.get("strict"):
            argv.append("--strict")
        if _str(body, "witness"):
            argv += ["--witness", body["witness"]]
        if _str(body, "ns"):
            argv += ["--ns", body["ns"]]
        return argv
    return _run_with("verify", body, [("ledger", "content", "content_b64")], build)


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

    def build(paths):
        argv = [paths["tape_a"], paths["tape_b"]]
        if _str(body, "pin"):
            argv += ["--pin", body["pin"]]
        return argv
    return _run_with("reconcile", body, [("tape_a", "content_a", "content_a_b64"),
                                         ("tape_b", "content_b", "content_b_b64")], build)


def audit_verify(body: dict) -> dict:
    """`arcaeon audit verify <path>` (or `content` / `content_b64`)."""
    return _run_with("audit", body, [("path", "content", "content_b64")],
                     lambda paths: ["verify", paths["path"]])


def receipt_verify(body: dict) -> dict:
    """`arcaeon receipt verify <receipt>` (or `content` / `content_b64`)."""
    return _run_with("receipt", body, [("receipt", "content", "content_b64")],
                     lambda paths: ["verify", paths["receipt"]])


def status(body: dict | None = None) -> dict:
    """`arcaeon status --json`."""
    return _result(*run_verb("status", ["--json"]))
