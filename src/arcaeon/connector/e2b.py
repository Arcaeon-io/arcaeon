# SPDX-License-Identifier: MIT
"""arcaeon.connector.e2b: an E2B sandbox run, serialised to JSON by the caller,
becomes one relayed check.verdict row per run, on the one adapter base
(arcaeon.connector.core.VendorAdapter).

A RECEIPT THAT A RUN HAPPENED AS THE SENDER REPORTS IT. Not a check that the code
is correct, not proof that E2B ran it, not proof the output is unaltered.

THE SHAPES, from E2B's public SDK source (read 2026-10-05, nothing run):

  commands.run -> CommandResult {stdout: str, stderr: str, exit_code: int,
                                 error: str | None}
      https://raw.githubusercontent.com/e2b-dev/E2B/main/packages/python-sdk/e2b/sandbox/commands/command_handle.py
      ("exit_code ... `0` if the command finished successfully"; "error: Error
      message from command execution if it failed")
  code-interpreter run_code -> Execution {results: [Result], logs: Logs {stdout:
      [str], stderr: [str]}, error: ExecutionError {name, value, traceback} | None,
      execution_count: int | None}
      https://raw.githubusercontent.com/e2b-dev/E2B/main/packages/code-interpreter-python/e2b_code_interpreter/models.py
      Execution.to_json() writes `logs` and `error` as JSON-encoded STRINGS and
      leaves out execution_count; both forms are read.
  sandbox info -> SandboxInfo {sandbox_id, template_id, metadata, ...}
      https://raw.githubusercontent.com/e2b-dev/E2B/main/packages/python-sdk/e2b/sandbox/sandbox_api.py
  usage: https://docs.e2b.dev/commands.md

Neither run object carries a sandbox id; the caller adds `sandbox_id`,
`template_id` and `metadata` (a str -> str object) at the top level of the run.
Nothing in those sources signs a run result, so every row is unsigned
(signed_by_vendor False). That is "not found in the sources read", not a
statement from E2B. The JavaScript SDK names the exit code `exitCode`; only the
Python names are read.

THE BODY: one run object, or a JSON array of them (at most MAX_ROWS).

THE WORD. E2B writes no verdict word, so the adapter writes its own:

    command_exit_zero      exit_code 0, error null or ""              -> VERIFIED
    execution_no_error     an Execution whose `error` key is null     -> VERIFIED
    command_exit_nonzero   exit_code an int other than 0              -> BROKEN
    command_error          exit_code 0 but a non-empty error string   -> BROKEN
    execution_error        an Execution with an error (object/string) -> BROKEN
    no_exit_code           a command row with no exit_code            -> COULD NOT LOOK
    unreadable_exit_code   exit_code not an int (bool, float, str...) -> COULD NOT LOOK
    error_not_stated       an Execution with no `error` key           -> COULD NOT LOOK
    unreadable_error       an error that is not null, string, object  -> COULD NOT LOOK
    ambiguous_shape        both command and Execution keys            -> COULD NOT LOOK
    unknown_shape          neither                                    -> COULD NOT LOOK

VERIFIED here is the sender's word that the run reported success, nothing more.
A success word also needs every field it carries readable: a key the adapter
does not know, or a known key of the wrong type, turns it into COULD NOT LOOK
(named in `run.problems`). A BROKEN stays BROKEN whatever else the row holds.

THE ROW. The check.verdict.relayed row of arcaeon.connector.core, plus:

    signed_by_vendor  False. Always.
    standing          "reported_by_sender". Always.
    input_sha256      hex SHA-256 of the exact body bytes (None when given no bytes)
    run               {index, shape ("command" | "execution" | None), sandbox_id,
                       template_id, metadata_keys, metadata_digest, exit_code,
                       error_present, error_name, error_digest, stdout_sha256,
                       stdout_bytes, stdout_lines, stderr_sha256, stderr_bytes,
                       stderr_lines, results_count, execution_count, ignored_keys,
                       problems}
    vendor_id         the caller's sandbox_id, or None
    subject           {"name": "e2b:<sandbox_id>", "sha256": None}, or None

stdout and stderr are kept by SHA-256 of their UTF-8 bytes (an Execution's lines
joined with nothing between them) and length, never copied. An error message,
value or traceback is kept by digest only; only an Execution error's `name` (the
exception class) is copied, cut to 256 characters. Metadata is kept by
"sha256:jcs:v1" digest and key count.

`standing_verdict(rows)` (alias `rollup`): BROKEN when any row relays BROKEN,
otherwise COULD NOT LOOK. Never VERIFIED. `recheck` says COULD NOT LOOK for
these rows; re-run `ingest` with the same bytes. Never raises on what is sent.
Stdlib only. No network: this reads bytes you already hold.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from arcaeon.record.row import loads_strict
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED, could_not_look

from .core import (ATTESTATION_NONE, ROW_KIND, AdapterError, Extracted, VendorAdapter, _now_iso,
                   _safe_str, _too_deep, register)

__all__ = ["VENDOR", "ADAPTER_VERSION", "TABLE", "MAX_PAYLOAD_BYTES", "MAX_DEPTH", "MAX_ROWS",
           "STANDING", "E2BRunAdapter", "E2B", "ingest", "standing_verdict", "rollup"]

VENDOR = "e2b"
ADAPTER_VERSION = "1"
#: A body over this is digested, never read (stdout can be large).
MAX_PAYLOAD_BYTES = 8 << 20
#: Results can carry chart and JSON data; room for that, refused past it.
MAX_DEPTH = 64
#: More runs than this in one body: the rest are not read, and a row says so.
MAX_ROWS = 1000
STANDING = "reported_by_sender"

TABLE = {
    "command_exit_zero": VERIFIED,
    "execution_no_error": VERIFIED,
    "command_exit_nonzero": BROKEN,
    "command_error": BROKEN,
    "execution_error": BROKEN,
    "no_exit_code": COULD_NOT_LOOK,
    "unreadable_exit_code": COULD_NOT_LOOK,
    "error_not_stated": COULD_NOT_LOOK,
    "unreadable_error": COULD_NOT_LOOK,
    "ambiguous_shape": COULD_NOT_LOOK,
    "unknown_shape": COULD_NOT_LOOK,
}

_WHY = {
    "no_exit_code": ("missing", "the run names no exit_code, so success cannot be read"),
    "unreadable_exit_code": ("unreadable", "exit_code is not an integer"),
    "error_not_stated": ("missing", "the Execution has no `error` key, so it does not say "
                                    "whether it errored"),
    "unreadable_error": ("unreadable", "error is not null, a string or an object"),
    "ambiguous_shape": ("unreadable", "the run carries both CommandResult and Execution keys"),
    "unknown_shape": ("name_not_found", "the object is neither a CommandResult nor an "
                                        "Execution"),
}

_ENVELOPE = ("sandbox_id", "template_id", "metadata")
_COMMAND = ("stdout", "stderr", "exit_code", "error")
_EXECUTION = ("results", "logs", "error", "execution_count")
_WHERE = "e2b run"


class E2BRunAdapter(VendorAdapter):
    """E2B run receipts on the one adapter base. Read with `ingest`, not
    import_verdict (whose `extract` refuses it)."""
    name = VENDOR
    version = ADAPTER_VERSION
    table = TABLE
    max_payload_bytes = MAX_PAYLOAD_BYTES
    max_depth = MAX_DEPTH
    one_row_per_payload = False

    def extract(self, doc: dict) -> Extracted:
        raise AdapterError("an E2B run is read with arcaeon.connector.e2b.ingest")


E2B = register(E2BRunAdapter())

_cnl = E2B.mark_could_not_look


def _copy(row: dict) -> dict:
    return json.loads(json.dumps(row))


def _blank(index: int | None) -> dict:
    return {"index": index, "shape": None, "sandbox_id": None, "template_id": None,
            "metadata_keys": None, "metadata_digest": None, "exit_code": None,
            "error_present": None, "error_name": None, "error_digest": None,
            "stdout_sha256": None, "stdout_bytes": None, "stdout_lines": None,
            "stderr_sha256": None, "stderr_bytes": None, "stderr_lines": None,
            "results_count": None, "execution_count": None, "ignored_keys": [],
            "problems": []}


def _b(s: str) -> bytes:
    return s.encode("utf-8", "surrogatepass")


def _hash_into(run: dict, which: str, data: bytes, lines: int | None) -> None:
    run[f"{which}_sha256"] = hashlib.sha256(data).hexdigest()
    run[f"{which}_bytes"] = len(data)
    run[f"{which}_lines"] = lines


def _maybe_json(v: Any) -> tuple[bool, Any]:
    """Execution.to_json() writes logs and error as JSON strings: decode one level,
    bounded. (True, value) on a clean decode, else (False, None). Never raises."""
    try:
        doc = loads_strict(v)
    except Exception:  # noqa: BLE001 - hostile text is just not JSON
        return False, None
    if _too_deep(doc, MAX_DEPTH):
        return False, None
    return True, doc


def _jcs(v: Any) -> str | None:
    try:
        return E2B.digest(v)
    except Exception:  # noqa: BLE001 - a value JCS refuses has no digest
        return None


def _is_int(v: Any) -> bool:
    return type(v) is int


def _envelope(doc: dict, run: dict, problems: list) -> None:
    sid = doc.get("sandbox_id")
    if sid is not None:
        if isinstance(sid, str):
            run["sandbox_id"] = _safe_str(sid)
        else:
            problems.append("sandbox_id is not a string")
    tid = doc.get("template_id")
    if tid is not None:
        if isinstance(tid, str):
            run["template_id"] = _safe_str(tid)
        else:
            problems.append("template_id is not a string")
    md = doc.get("metadata")
    if md is not None:
        if isinstance(md, dict) and all(isinstance(k, str) and isinstance(x, str)
                                        for k, x in md.items()):
            run["metadata_keys"] = len(md)
            run["metadata_digest"] = _jcs(md)
            if run["metadata_digest"] is None:
                problems.append("metadata has no sha256:jcs:v1 digest")
        else:
            problems.append("metadata is not an object of strings")


def _command(doc: dict, run: dict, problems: list) -> str:
    for k in ("stdout", "stderr"):
        v = doc.get(k)
        if v is None:
            continue
        if isinstance(v, str):
            _hash_into(run, k, _b(v), None)
        else:
            problems.append(f"{k} is not a string")
    err = doc.get("error")
    err_word = None
    if err is None or err == "":
        run["error_present"] = False
    elif isinstance(err, str):
        run["error_present"] = True
        run["error_digest"] = hashlib.sha256(_b(err)).hexdigest()
        err_word = "command_error"
    else:
        problems.append("error is not a string or null")
    if "exit_code" not in doc or doc["exit_code"] is None:
        return err_word or "no_exit_code"
    code = doc["exit_code"]
    if not _is_int(code):
        return err_word or "unreadable_exit_code"
    run["exit_code"] = code
    if code != 0:
        return "command_exit_nonzero"
    return err_word or "command_exit_zero"


def _logs(v: Any, run: dict, problems: list) -> None:
    if v is None:
        return
    if isinstance(v, str):
        ok, v = _maybe_json(v)
        if not ok:
            problems.append("logs is a string that is not JSON")
            return
    if not isinstance(v, dict):
        problems.append("logs is not an object")
        return
    for k in ("stdout", "stderr"):
        lines = v.get(k, [])
        if not isinstance(lines, list) or not all(isinstance(x, str) for x in lines):
            problems.append(f"logs.{k} is not a list of strings")
            continue
        _hash_into(run, k, b"".join(_b(x) for x in lines), len(lines))
    extra = [k for k in v if k not in ("stdout", "stderr")]
    if extra:
        problems.append("logs carries keys this adapter does not know")


def _execution(doc: dict, run: dict, problems: list) -> str:
    _logs(doc.get("logs"), run, problems)
    res = doc.get("results")
    if res is not None:
        if isinstance(res, list):
            run["results_count"] = len(res)
        else:
            problems.append("results is not a list")
    ec = doc.get("execution_count")
    if ec is not None:
        if _is_int(ec):
            run["execution_count"] = ec
        else:
            problems.append("execution_count is not an integer")
    if "error" not in doc:
        return "error_not_stated"
    err = doc["error"]
    if err is None:
        run["error_present"] = False
        return "execution_no_error"
    if isinstance(err, str):
        ok, parsed = _maybe_json(err)
        if ok and isinstance(parsed, dict):
            err = parsed
        else:
            run["error_present"] = True
            run["error_digest"] = hashlib.sha256(_b(err)).hexdigest()
            return "execution_error"
    if isinstance(err, dict):
        run["error_present"] = True
        run["error_name"] = _safe_str(err.get("name"))
        run["error_digest"] = _jcs(err)
        return "execution_error"
    return "unreadable_error"


def _run_row(base: dict, i: int, doc: Any) -> dict:
    row = _copy(base)
    run = row["run"] = _blank(i)
    where = f"{_WHERE}[{i}]"
    if not isinstance(doc, dict):
        return _cnl(row, "an E2B run object", where, "unreadable",
                    "the entry is not a JSON object")
    has_cmd = any(k in doc for k in ("stdout", "stderr", "exit_code"))
    has_exe = any(k in doc for k in ("results", "logs", "execution_count"))
    known = _ENVELOPE + (_COMMAND if has_cmd and not has_exe else
                         _EXECUTION if has_exe and not has_cmd else ())
    run["ignored_keys"] = sorted(s for s in (_safe_str(k) for k in doc if k not in known)
                                 if s is not None)[:16]
    problems: list = []
    _envelope(doc, run, problems)
    row["vendor_id"] = run["sandbox_id"]
    if run["sandbox_id"]:
        row["subject"] = {"name": f"{VENDOR}:{run['sandbox_id']}", "sha256": None}
    if has_cmd and has_exe:
        word = "ambiguous_shape"
    elif has_cmd:
        run["shape"] = "command"
        word = _command(doc, run, problems)
    elif has_exe:
        run["shape"] = "execution"
        word = _execution(doc, run, problems)
    else:
        word = "unknown_shape"
    if run["ignored_keys"] and word in TABLE and TABLE[word] == VERIFIED:
        problems.append("the run carries keys this adapter does not know")
    run["problems"] = problems[:16]
    row["vendor_word"] = word
    row["mapping"] = {"rule": "table"}
    row["relayed_verdict"] = TABLE[word]
    if TABLE[word] == COULD_NOT_LOOK:
        _cnl(row, "an E2B run this adapter can read as success or failure", where,
             *_WHY[word])
    elif TABLE[word] == VERIFIED and problems:
        _cnl(row, "a readable E2B run that reports success", where, "unreadable",
             _safe_str(problems[0]) or "unreadable")
    return row


def _read(raw: Any, at: str) -> list:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogatepass")
    if isinstance(raw, bytearray):
        raw = bytes(raw)
    if not isinstance(raw, bytes):
        row = E2B.base_row(None, at)
        row["input_sha256"] = None
        return [_cnl(row, "E2B run JSON bytes", "argument", "unreadable",
                     f"payload is a {type(raw).__name__}, not bytes")]
    base = E2B.base_row(raw, at)
    base["input_sha256"] = hashlib.sha256(raw).hexdigest()
    if not raw:
        return [_cnl(base, "an E2B run", _WHERE, "empty", "the body is empty")]
    if len(raw) > MAX_PAYLOAD_BYTES:
        return [_cnl(base, "an E2B run", _WHERE, "bounded",
                     f"body is {len(raw)} bytes, over the {MAX_PAYLOAD_BYTES}-byte "
                     f"limit; digested, not read")]
    try:
        doc = loads_strict(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        return [_cnl(base, "an E2B run as JSON", _WHERE, "unreadable",
                     f"body is not one unambiguous UTF-8 JSON value: {type(e).__name__}")]
    if _too_deep(doc, MAX_DEPTH):
        return [_cnl(base, "an E2B run as JSON", _WHERE, "unreadable",
                     f"body nests deeper than {MAX_DEPTH}")]
    if isinstance(doc, dict):
        return [_run_row(base, 0, doc)]
    if not isinstance(doc, list):
        return [_cnl(base, "an E2B run object or a list of them", _WHERE, "name_not_found",
                     f"body is a JSON {type(doc).__name__}")]
    if not doc:
        return [_cnl(base, "an E2B run", _WHERE, "empty", "the body lists no runs")]
    rows = []
    for i, entry in enumerate(doc):
        if i >= MAX_ROWS:
            rows.append(_cnl(_copy(base), "every run in the body", _WHERE, "bounded",
                             f"more than {MAX_ROWS} runs; the rest were not read"))
            break
        rows.append(_run_row(base, i, entry))
    return rows


def _clean_verified(r: dict) -> bool:
    w = r.get("vendor_word")
    run = r.get("run")
    return (isinstance(w, str) and TABLE.get(w) == VERIFIED
            and r.get("mapping") == {"rule": "table"} and "could_not_look" not in r
            and isinstance(run, dict) and not run.get("problems")
            and not run.get("ignored_keys"))


def _seal(rows: list) -> list:
    """The one final step over every row ingest returns: this adapter's, unsigned,
    reported by the sender. Only a clean success word can stay VERIFIED; a BROKEN
    stays BROKEN."""
    for r in rows:
        r["vendor"] = {"name": VENDOR, "adapter_version": ADAPTER_VERSION}
        r["attestation"] = {"status": ATTESTATION_NONE, "checked_by_us": False, "claimed": None}
        r.setdefault("input_sha256", None)
        if not isinstance(r.get("run"), dict):
            r["run"] = _blank(None)
        if r.get("relayed_verdict") == VERIFIED and not _clean_verified(r):
            _cnl(r, "a readable E2B run that reports success", _WHERE, "unreadable",
                 f"{r.get('vendor_word')!r} cannot relay as VERIFIED from this row")
        r["signed_by_vendor"] = False
        r["standing"] = STANDING
    return rows


def ingest(raw: Any, *, received_at: str | None = None) -> list:
    """An E2B run (one JSON object) or a JSON array of runs, as the bytes you hold
    -> a list of relayed rows, one per run. Never raises on the body; an
    unreadable body is one COULD NOT LOOK row. Every row is signed_by_vendor
    False, standing reported_by_sender."""
    at = received_at if isinstance(received_at, str) else _now_iso()
    try:
        rows = _read(raw, at)
    except Exception as e:  # noqa: BLE001 - never a traceback on what is sent
        rows = [_cnl(E2B.base_row(None, at), "an E2B run", _WHERE, "unreadable",
                     f"the adapter failed: {type(e).__name__}")]
    return _seal(rows)


def standing_verdict(rows: Any) -> dict:
    """What E2B run rows can say on their own. BROKEN when any of them relays
    BROKEN; otherwise COULD NOT LOOK, because an unsigned run reported by the
    sender cannot make a VERIFIED by itself. Never VERIFIED. Never raises."""
    ours = []
    if isinstance(rows, (list, tuple)):
        ours = [r for r in rows if isinstance(r, dict) and r.get("kind") == ROW_KIND
                and isinstance(r.get("vendor"), dict) and r["vendor"].get("name") == VENDOR]
    words = [r.get("relayed_verdict") for r in ours]
    if BROKEN in words:
        relayed = BROKEN
    elif ours and all(w == VERIFIED for w in words):
        relayed = VERIFIED
    else:
        relayed = COULD_NOT_LOOK if ours else None
    out = {"verdict": BROKEN if relayed == BROKEN else COULD_NOT_LOOK,
           "relayed_verdict": relayed, "rows": len(ours), "signed_by_vendor": False,
           "standing": STANDING}
    if relayed == BROKEN:
        out["reason"] = "the sender reported at least one failed E2B run (relayed, unsigned)"
    else:
        out.update(could_not_look(
            "a check of our own or a signed vendor verdict", "rows",
            "missing" if ours else "empty",
            "E2B run rows are unsigned and reported by the sender; they cannot make a "
            "VERIFIED by themselves" if ours else "no E2B run rows were given"))
    return out


rollup = standing_verdict
