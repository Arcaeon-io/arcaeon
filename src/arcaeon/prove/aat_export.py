# SPDX-License-Identifier: MIT
"""arcaeon.prove.aat_export: a ledger as draft-sharif-agent-audit-trail records.

Spec: memory/EVIDENCE_PACK_SPEC_2026-09-27.md, section 3 (field names quoted
there from draft-sharif-agent-audit-trail-05). This module emits ONLY the
fields that section lists as "can emit now", each read straight off a row:

    timestamp            <- ts
    agent_id             <- agent, else system_id, with a URI prefix
    session_id           <- session (the proxy's uuid4 session)
    action_type          <- evt / event: tool_call, decision, error, lifecycle
    action_detail        <- {tool_name <- tool, parameters_hash <- args_digest}
    response_hash        <- result_digest
    input_hash           <- a digest of the row's `inputs`
    output_hash          <- a digest of the row's `outputs`
    outcome              <- status ok / error as success / failure; a mandate
                            block (enforce mode) as denied
    sequence_number      <- seq
    recording_component  <- proxy rows only (they carry `seam`): the proxy is
                            a separate process from the agent

A field the row does not hold is LEFT OUT, never filled with a guess. Never
emitted: `record_id` (a UUID minted at export is not original), `signature` /
`signer_kid` (rows are not signed), `trust_level`, `agent_version`,
`record_phase`, `human_override`, `risk_score`, `trust_assignment`, `batch`.

Each record also carries our original `chain` (and `source_line`, the row's
line in the ledger), because the draft's own chain (SHA-256 over RFC 8785 JCS)
would be computed at export and proves the export, not the original. JSONL
only: the draft calls CSV "inherently lossy".

The AAT chain (K062), as the draft defines it:

    prev_hash(1) = null
    prev_hash(N) = hex(SHA-256(JCS(record(N-1))))      64 hex

where record(N-1) is the whole previous record, its own `prev_hash`
included. Each line of the file IS the JCS form of its record, so a reader
can hash line N-1 as bytes. A value JCS cannot write exactly (NaN, Infinity,
an integer past 2**53, a lone surrogate) is refused, left out of its record
and listed, never rounded (`arcaeon.prove.jcs`).

Beside `FILE.jsonl` the export writes `FILE_gaps.json` (so `aat.jsonl` gets
`aat_gaps.json`, K063): its `which_chain` header says which chain proves
what, and every field left out is one COULD NOT LOOK entry with
`reason_word: "bounded"`. The export's verdict is still the source ledger's
chain check; the gaps say how far the export reaches, they are not a check.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from arcaeon import verdict as V

__all__ = ["map_row", "export_aat", "AAT_FORMAT", "AGENT_URI_PREFIX", "NEVER_EMITTED",
           "AatUsageError", "chain_records", "verify_aat_bytes", "AAT_CHAIN_ALGORITHM",
           "WHICH_CHAIN", "EMITTED_WHEN_HELD", "gaps_path", "build_gaps"]

AAT_FORMAT = "agent-audit-trail"
#: The URI prefix our agent names get, so `agent_id` is a URI as the draft
#: asks. The name after it is the row's own, percent-encoded, never altered.
AGENT_URI_PREFIX = "urn:arcaeon:agent:"
#: Fields the draft defines that this export never writes (spec section 3,
#: "cannot emit honestly now").
NEVER_EMITTED = ("record_id", "agent_version", "trust_level", "record_phase",
                 "signature", "signer_kid", "human_override", "risk_score",
                 "trust_assignment", "batch")

#: Why each field the draft defines is never written (spec section 3).
_NOT_EMITTED_WHY = {
    "record_id": "a UUIDv4 minted at export would not be original to the row",
    "agent_version": "the rows do not record which version of the agent ran",
    "trust_level": "we issue no identity passports, so no level above L0 or L1 is known",
    "record_phase": "when each row is written relative to the act has not been audited",
    "signature": "rows are not signed (the sign extra is not wired to rows)",
    "signer_kid": "rows are not signed, so there is no signing key id",
    "human_override": "the rows carry no field for it",
    "risk_score": "the rows carry no field for it",
    "trust_assignment": "the rows carry no field for it",
    "batch": "the rows carry no field for it",
    "external_timestamp": "the daily anchor is a pointer, not a timestamp token, so it "
                          "is not written as one",
}
#: The fields map_row writes when, and only when, the row holds them.
EMITTED_WHEN_HELD = ("timestamp", "agent_id", "session_id", "action_type",
                     "action_detail", "response_hash", "input_hash", "output_hash",
                     "outcome", "sequence_number", "recording_component")
#: The export's header line: which chain proves what (spec section 3).
WHICH_CHAIN = ("Two chains ride in this export. The AAT chain (prev_hash, SHA-256 over "
               "RFC 8785 JCS) was computed at export: it proves the export was not "
               "altered after export, and nothing about the ledger before it. The "
               "original chain is the `chain` field on each record: only it speaks for "
               "the rows as they were written.")

_LIFECYCLE = frozenset({"session_begin", "session_end", "mcp_initialize", "tools_list",
                        "system_start", "system_stop"})
_DECISION = frozenset({"decision", "mandate_outside", "mandate_could_not_look",
                       "mandate_cap_exceeded"})
_OUTCOME = {"ok": "success", "error": "failure"}


class AatUsageError(ValueError):
    """The export could not start on what it was given (exit 2)."""


#: How the AAT `prev_hash` chain is computed (the draft's rule, not ours).
AAT_CHAIN_ALGORITHM = "prev_hash = hex(sha256(jcs(previous record))); null at genesis"


def _drop(rec: dict, path: str) -> str:
    """Remove the value a JcsError names from `rec`; return its top-level field."""
    keys = path[2:].split(".") if path.startswith("$.") else []
    top = keys[0].split("[", 1)[0] if keys else ""
    if not top or top not in rec:
        raise ValueError(f"cannot place {path!r} in the record")
    parent, key = rec, top
    for k in keys[1:]:
        nxt = parent.get(key)
        if not isinstance(nxt, dict) or "[" in k or k not in nxt:
            break
        parent, key = nxt, k
    parent.pop(key, None)
    if isinstance(rec.get(top), dict) and not rec[top]:
        rec.pop(top)
    return top


def gaps_path(out: str | Path) -> Path:
    """The gaps sidecar for an export file: `aat.jsonl` -> `aat_gaps.json`."""
    out = Path(out)
    return out.with_name(out.stem + "_gaps.json")


def _lines_phrase(lines: list[int]) -> str:
    return ("ledger line " if len(lines) == 1 else "ledger lines ") + \
        ", ".join(str(n) for n in lines)


def build_gaps(records: list[dict], refused: list[dict], skipped: list[int]) -> list[dict]:
    """Every field left out, one COULD NOT LOOK entry each, reason_word bounded."""
    gaps: list[dict] = []
    for field, why in _NOT_EMITTED_WHY.items():
        gaps.append(V.could_not_look(f"AAT field {field}", "every record", "bounded",
                                     f"left out: {why}"))
    refused_at = {(r.get("source_line"), r["field"]) for r in refused}
    for field in EMITTED_WHEN_HELD:
        missing = [r.get("source_line") for r in records
                   if field not in r and (r.get("source_line"), field) not in refused_at]
        if missing:
            e = V.could_not_look(f"AAT field {field}", _lines_phrase(missing), "bounded",
                                 "left out: the row holds no value for it, and none is "
                                 "guessed")
            e["lines"] = missing
            gaps.append(e)
    for r in refused:
        e = V.could_not_look(f"AAT field {r['field']}", _lines_phrase([r["source_line"]]),
                             "bounded", f"left out: JCS cannot write it exactly "
                             f"({r['why']}), and it is not rounded")
        e["lines"] = [r["source_line"]]
        gaps.append(e)
    if skipped:
        e = V.could_not_look("an AAT record", _lines_phrase(skipped), "bounded",
                             "left out: the line is not a JSON object, so no record "
                             "was made from it")
        e["lines"] = list(skipped)
        gaps.append(e)
    return gaps


def chain_records(records: list[dict]) -> tuple[list[bytes], str | None, list[dict]]:
    """Give each record its AAT `prev_hash` and its JCS line.

    Returns (lines, head, refused): `lines` are the JCS bytes of each record
    in order, `head` is hex(SHA-256) of the last line (None when there are
    none), `refused` lists every value JCS could not write exactly, each as
    {"source_line", "field", "path", "why"}; that value is left out of its
    record, never rounded. `records` are updated in place.
    """
    from arcaeon.prove.jcs import JcsError, canonicalize

    lines: list[bytes] = []
    refused: list[dict] = []
    prev: str | None = None
    for rec in records:
        rec.pop("prev_hash", None)
        rec["prev_hash"] = prev
        while True:  # every refusal removes one value, so this ends
            try:
                b = canonicalize(rec)
                break
            except JcsError as e:
                field = _drop(rec, e.path)
                refused.append({"source_line": rec.get("source_line"), "field": field,
                                "path": e.path, "why": e.why})
        lines.append(b)
        prev = hashlib.sha256(b).hexdigest()
    return lines, prev, refused


def verify_aat_bytes(raw: bytes) -> dict:
    """Recompute the AAT chain of an exported file, line by line.

    Each line must be a JSON object whose bytes are its own JCS form, with
    `prev_hash` null on line 1 and hex(SHA-256(line N-1)) after. Returns
    {"ok": True, "records", "head"} or {"ok": False, "line", "finding"}.
    """
    from arcaeon.prove.jcs import JcsError, canonicalize

    prev: str | None = None
    n = 0
    body = raw[:-1] if raw.endswith(b"\n") else raw
    for n, line in enumerate(body.split(b"\n") if body else [], start=1):
        try:
            rec = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return {"ok": False, "line": n, "finding": f"AAT line {n} is not JSON"}
        if not isinstance(rec, dict):
            return {"ok": False, "line": n, "finding": f"AAT line {n} is not a JSON object"}
        try:
            if canonicalize(rec) != line:
                return {"ok": False, "line": n,
                        "finding": f"AAT line {n} is not in its JCS form"}
        except JcsError as e:
            return {"ok": False, "line": n, "finding": f"AAT line {n}: {e}"}
        if "prev_hash" not in rec or rec["prev_hash"] != prev:
            return {"ok": False, "line": n,
                    "finding": f"the AAT chain breaks at line {n}: prev_hash is not the "
                               "hash of the line before it"}
        prev = hashlib.sha256(line).hexdigest()
    return {"ok": True, "records": n, "head": prev}


def _digest(value: Any) -> str | None:
    from arcaeon.record.adapter._ledger import digest_json
    try:
        return digest_json(value)
    except (ValueError, TypeError, RecursionError):
        return None


def _action_type(row: dict) -> str | None:
    if row.get("record_error"):
        return "error"  # the proxy's skeleton row: an event whose content was lost
    kind = row.get("evt") or row.get("event")
    if kind == "tool_call":
        return "tool_call"
    if kind in _DECISION:
        return "decision"
    if kind in _LIFECYCLE:
        return "lifecycle"
    return None  # a kind the draft's list does not name: left out, not guessed


def _outcome(row: dict) -> str | None:
    if row.get("action") == "blocked" and row.get("mandate_mode") == "enforce":
        return "denied"
    status = row.get("status")
    return _OUTCOME.get(status) if isinstance(status, str) else None


def map_row(row: dict, *, line: int | None = None) -> dict:
    """One ledger row as one AAT record: only fields the row holds."""
    out: dict[str, Any] = {}
    if isinstance(row.get("ts"), str):
        out["timestamp"] = row["ts"]
    name = next((row[k] for k in ("agent", "system_id")
                 if isinstance(row.get(k), str) and row[k]), None)
    if name is not None:
        out["agent_id"] = AGENT_URI_PREFIX + quote(name, safe="")
    if isinstance(row.get("session"), str):
        out["session_id"] = row["session"]
    at = _action_type(row)
    if at is not None:
        out["action_type"] = at
    detail = {}
    if isinstance(row.get("tool"), str):
        detail["tool_name"] = row["tool"]
    if isinstance(row.get("args_digest"), str):
        detail["parameters_hash"] = row["args_digest"]
    if detail:
        out["action_detail"] = detail
    if isinstance(row.get("result_digest"), str):
        out["response_hash"] = row["result_digest"]
    for ours, theirs in (("inputs", "input_hash"), ("outputs", "output_hash")):
        if ours in row:
            d = _digest(row[ours])
            if d is not None:
                out[theirs] = d
    oc = _outcome(row)
    if oc is not None:
        out["outcome"] = oc
    if isinstance(row.get("seq"), int) and not isinstance(row.get("seq"), bool):
        out["sequence_number"] = row["seq"]
    if isinstance(row.get("seam"), str):
        impl = row.get("seam_impl")
        out["recording_component"] = (f"arcaeon proxy ({row['seam']}"
                                      + (f", {impl})" if isinstance(impl, str) else ")"))
    if isinstance(row.get("chain"), str):
        out["chain"] = row["chain"]
    if line is not None:
        out["source_line"] = line
    return out


def export_aat(ledger: str | Path, out: str | Path) -> dict:
    """Write `ledger` as AAT JSONL to the file `out`.

    Returns `verdict` (the source ledger's own chain check: the export copies
    what is there either way, and says what it copied), integer `exit`,
    `out`, `records` and `skipped_lines` (lines that are not a JSON object).
    Raises AatUsageError when `out` exists (an export never writes over a
    file) or is not a .jsonl path.
    """
    from arcaeon.prove.evidence_pack import _lines
    from arcaeon.record.ledger import verify_file

    ledger, out = Path(ledger), Path(out)
    if out.suffix.lower() != ".jsonl":
        raise AatUsageError(f"{out}: the export is JSONL only (the draft calls CSV "
                            "inherently lossy); name a .jsonl file")
    if out.exists():
        raise AatUsageError(f"{out} exists; an export is written to a new file")
    gp = gaps_path(out)
    if gp.exists():
        raise AatUsageError(f"{gp} exists; an export is written to new files")
    if not ledger.is_file():
        res = {"verdict": V.COULD_NOT_LOOK, "exit": V.EXIT_COULD_NOT_LOOK, "out": None}
        res.update(V.could_not_look("a ledger file", str(ledger), "missing",
                                    "the ledger named was not found, so nothing was exported"))
        return res
    records, skipped = [], []
    for n, line in enumerate(_lines(ledger.read_bytes()), start=1):
        try:
            row = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            skipped.append(n)
            continue
        if not isinstance(row, dict):
            skipped.append(n)
            continue
        records.append(map_row(row, line=n))
    lines, head, refused = chain_records(records)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as fh:
        for b in lines:
            fh.write(b + b"\n")
    gaps = build_gaps(records, refused, skipped)
    vr = verify_file(ledger)
    word = V.VERIFIED if vr.ok is True else V.BROKEN if vr.ok is False else V.COULD_NOT_LOOK
    res = {"verdict": word, "exit": V.EXIT_BY_WORD[word], "out": str(out),
           "format": AAT_FORMAT, "records": len(records), "skipped_lines": skipped,
           "source_chain": {"ok": vr.ok, "rows": vr.rows, "first_break": vr.first_break},
           "aat_chain": {"algorithm": AAT_CHAIN_ALGORITHM, "records": len(lines),
                         "head": head},
           "refused": refused, "which_chain": WHICH_CHAIN,
           "gaps_file": str(gp), "gaps": len(gaps)}
    sidecar = {"format": AAT_FORMAT,
               "scope": "a subset of draft-sharif-agent-audit-trail-05 fields; not "
                        "AAT-conformant",
               "which_chain": WHICH_CHAIN, "export": out.name,
               "aat_chain": res["aat_chain"], "source_chain": res["source_chain"],
               "gaps": gaps}
    gp.write_bytes((json.dumps(sidecar, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    if word == V.BROKEN:
        res["finding"] = f"the source ledger's chain breaks at {vr.first_break}"
    elif word == V.COULD_NOT_LOOK:
        scope = getattr(vr, "verified_scope", "") or ""
        res.update(V.could_not_look(
            "chain links for every row of the source ledger", str(ledger),
            "empty" if scope == "empty" else "bounded",
            "the source chain check reached no verdict, so the export copies rows "
            "nothing vouches for"))
    return res
