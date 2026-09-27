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
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from arcaeon import verdict as V

__all__ = ["map_row", "export_aat", "AAT_FORMAT", "AGENT_URI_PREFIX", "NEVER_EMITTED",
           "AatUsageError"]

AAT_FORMAT = "agent-audit-trail"
#: The URI prefix our agent names get, so `agent_id` is a URI as the draft
#: asks. The name after it is the row's own, percent-encoded, never altered.
AGENT_URI_PREFIX = "urn:arcaeon:agent:"
#: Fields the draft defines that this export never writes (spec section 3,
#: "cannot emit honestly now").
NEVER_EMITTED = ("record_id", "agent_version", "trust_level", "record_phase",
                 "signature", "signer_kid", "human_override", "risk_score",
                 "trust_assignment", "batch")

_LIFECYCLE = frozenset({"session_begin", "session_end", "mcp_initialize", "tools_list",
                        "system_start", "system_stop"})
_DECISION = frozenset({"decision", "mandate_outside", "mandate_could_not_look",
                       "mandate_cap_exceeded"})
_OUTCOME = {"ok": "success", "error": "failure"}


class AatUsageError(ValueError):
    """The export could not start on what it was given (exit 2)."""


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
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as fh:
        for r in records:
            fh.write((json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))
    vr = verify_file(ledger)
    word = V.VERIFIED if vr.ok is True else V.BROKEN if vr.ok is False else V.COULD_NOT_LOOK
    res = {"verdict": word, "exit": V.EXIT_BY_WORD[word], "out": str(out),
           "format": AAT_FORMAT, "records": len(records), "skipped_lines": skipped,
           "source_chain": {"ok": vr.ok, "rows": vr.rows, "first_break": vr.first_break}}
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
