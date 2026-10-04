# SPDX-License-Identifier: MIT
"""arcaeon.prove.ocsf: one arcaeon verdict as one OCSF Detection Finding (TE-34).

    from arcaeon.prove import ocsf
    event = ocsf.to_ocsf(report)        # an `envelope verify` report, a
                                        # `gate decide --json` decision, or a
                                        # gate evidence pack's evidence.json
    event = ocsf.to_ocsf(report, include_verified=True, now=fixed_utc_time)

The reverse direction of the bridge: arcaeon's three words go OUT to a SIEM
as an OCSF event, so a security team sees a BROKEN handoff where it already
looks. The event is shaped to OCSF schema 1.9.0, class Detection Finding
(class_uid 2004, category Findings, category_uid 2), with no profile applied.
The field-by-field mapping, and the pages it was read from, is docs/OCSF.md.

    verdict          severity_id          is_alert  emitted
    BROKEN           4 High               true      always
    COULD NOT LOOK   2 Low                false     always, naming what was not checked
    VERIFIED         1 Informational      false     only with include_verified

activity_id is 1 (Create), so type_uid = 2004 * 100 + 1 = 200401; status_id
is 1 (New); time is integer milliseconds since the epoch, the export time.
The three-word verdict goes in status_code (OCSF: "the source-specific status
... code as reported by the event source"), the reason in status_detail, the
handed file (name, size, sha256 when the input carries it) in evidences[].file.
Everything OCSF has no attribute for (signers, audience, binding, reasons,
steps, what could not be checked, the gate's action and decision) goes in
`unmapped.arcaeon`. No field name here is invented: every top-level and
object attribute is one the 1.9.0 schema lists for this class with no
profile, and the rest is under `unmapped`.

Paths never leave: only file names (the last path part) reach the event, and
every string is scrubbed of absolute directories before it is written.

Pure: reads nothing, hashes nothing, writes nothing; the CLI reads one JSON
file. Given the same input and the same `now` the output is byte-identical.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from arcaeon import verdict as V

__all__ = ["OCSF_VERSION", "OCSF_SOURCES", "CLASS_UID", "CATEGORY_UID", "ACTIVITY_ID",
           "TYPE_UID", "SEVERITY", "LIMITS_LINE", "ExportError", "normalize", "to_ocsf",
           "dumps", "main"]

#: The OCSF schema version the mapping was read from (schema.ocsf.io/api/version
#: answered 1.9.0 on 2026-10-04) and the pages it was read from.
OCSF_VERSION = "1.9.0"
OCSF_SOURCES = (
    "https://schema.ocsf.io/classes/detection_finding",
    "https://schema.ocsf.io/api/classes/detection_finding",
    "https://schema.ocsf.io/api/objects/finding_info",
    "https://schema.ocsf.io/api/classes/base_event",
    "https://schema.ocsf.io/api/objects/metadata",
    "https://schema.ocsf.io/api/objects/product",
    "https://schema.ocsf.io/api/objects/evidences",
    "https://schema.ocsf.io/api/objects/file",
    "https://schema.ocsf.io/api/objects/fingerprint",
    "https://schema.ocsf.io/api/data_types",
    "https://schema.ocsf.io/api/version",
)

CLASS_UID, CLASS_NAME = 2004, "Detection Finding"
CATEGORY_UID, CATEGORY_NAME = 2, "Findings"
ACTIVITY_ID, ACTIVITY_NAME = 1, "Create"
#: OCSF: "Producers and mappers must compute this as class_uid * 100 + activity_id".
TYPE_UID = CLASS_UID * 100 + ACTIVITY_ID
TYPE_NAME = f"{CLASS_NAME}: {ACTIVITY_NAME}"
STATUS_ID, STATUS_NAME = 1, "New"
#: verdict -> (severity_id, severity caption, is_alert)
SEVERITY = {V.BROKEN: (4, "High", True), V.COULD_NOT_LOOK: (2, "Low", False),
            V.VERIFIED: (1, "Informational", False)}
FILE_TYPE_REGULAR = (1, "Regular File")
SHA256_ALGORITHM = (3, "SHA-256")

LIMITS_LINE = ("Limits: VERIFIED means the bytes are unchanged since the named key sealed "
               "them and are labeled for this receiver; it never means the content is true "
               "or safe. BROKEN means a check came out wrong, not who is at fault. COULD NOT "
               "LOOK means something was not checked; it vouches for nothing.")

_EVIDENCE_KIND = "arcaeon.gate.evidence/v1"
_MAX_INPUT_BYTES = 16 << 20
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_WIN_ABS = re.compile(r"(?<![\w])[A-Za-z]:[\\/](?:[^\s\\/:*?\"'<>|()]+[\\/])*")
_UNC = re.compile(r"\\\\[^\s\\]+\\(?:[^\s\\\"'()]+\\)*")
_POSIX_ABS = re.compile(r"(?<![\w:/.~-])/(?:[^\s/\"'()]+/)+")


class ExportError(ValueError):
    """The input is not an arcaeon verdict this exporter reads (COULD NOT LOOK, exit 3)."""


def _name(p: Any) -> str | None:
    """The last part of a path, whichever slash it uses; None for nothing."""
    if not isinstance(p, str) or not p.strip():
        return None
    parts = [x for x in re.split(r"[\\/]", p) if x]
    return parts[-1] if parts else None


def _dirs(paths) -> list[str]:
    """The directory prefixes of known paths, longest first, both slash forms."""
    out = set()
    for p in paths:
        if isinstance(p, str) and p:
            for q in (p, p.replace("\\", "/"), p.replace("/", "\\")):
                for sep in ("/", "\\"):
                    i = q.rfind(sep)
                    if i > 0:
                        out.add(q[:i + 1])
    return sorted(out, key=len, reverse=True)


def _scrub(obj: Any, dirs: list[str]) -> Any:
    """Every string with known directories and any absolute directory cut away."""
    if isinstance(obj, str):
        for d in dirs:
            obj = obj.replace(d, "")
        return _POSIX_ABS.sub("", _UNC.sub("", _WIN_ABS.sub("", obj)))
    if isinstance(obj, list):
        return [_scrub(x, dirs) for x in obj]
    if isinstance(obj, dict):
        return {k: _scrub(v, dirs) for k, v in obj.items()}
    return obj


def _ms(now: datetime) -> int:
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return (now - _EPOCH) // timedelta(milliseconds=1)


def _cnl_reasons(text: Any) -> list[str]:
    return [s for s in str(text or "").split("; ") if s]


def normalize(obj: Any) -> dict:
    """The input as one flat record: which kind it was, the verdict and what
    the event carries. Raises ExportError on anything that is not an arcaeon
    envelope verify report, gate decision or gate evidence.json."""
    if not isinstance(obj, dict):
        raise ExportError("the input is not one JSON object")
    paths: list = []
    rec: dict[str, Any] = {"source": None, "action": None, "decision": None,
                           "gate_reason": None, "audience_checked": None, "deal_checked": None,
                           "purpose_checked": None, "signers_named": None, "checked_at": None,
                           "file_sha256": None, "file_sha256_of": None, "envelope_sha256": None,
                           "evidence": None}
    if obj.get("kind") == _EVIDENCE_KIND:
        rep = obj.get("report") if isinstance(obj.get("report"), dict) else {}
        f = obj.get("file") if isinstance(obj.get("file"), dict) else {}
        e = obj.get("envelope") if isinstance(obj.get("envelope"), dict) else {}
        rec.update(source="gate evidence pack", verdict=obj.get("verdict"),
                   action=obj.get("action"), decision=obj.get("decision"),
                   gate_reason=obj.get("reason"), audience_checked=obj.get("audience"),
                   deal_checked=obj.get("deal"), purpose_checked=obj.get("purpose"),
                   signers_named=obj.get("signers"), checked_at=obj.get("at"),
                   file_sha256=f.get("sha256"), envelope_sha256=e.get("sha256"),
                   file_sha256_of="the bytes copied into the evidence pack",
                   reasons=obj.get("reasons"))
        file_path, env_path = f.get("path"), e.get("path")
        paths += [file_path, env_path]
    elif "decision" in obj and "action" in obj and isinstance(obj.get("report"), dict):
        rep = obj["report"]
        rec.update(source="gate decision", verdict=obj.get("verdict"), action=obj.get("action"),
                   decision=obj.get("decision"), gate_reason=obj.get("reason"),
                   audience_checked=obj.get("audience"), deal_checked=obj.get("deal"),
                   purpose_checked=obj.get("purpose"), signers_named=obj.get("signers"),
                   checked_at=obj.get("at"), reasons=obj.get("reasons"),
                   evidence=_name(obj.get("evidence")))
        file_path, env_path = obj.get("file"), obj.get("envelope")
        paths += [file_path, env_path, obj.get("evidence")]
    elif "verdict" in obj:
        rep = obj
        rec.update(source="verify report", verdict=obj.get("verdict"), reasons=None)
        file_path = obj.get("file") or obj.get("path") or obj.get("ledger")
        env_path = obj.get("envelope")
        paths += [file_path, env_path]
    else:
        raise ExportError("not an arcaeon verify report, gate decision or gate evidence.json "
                          "(no verdict)")
    verdict = rec["verdict"]
    if verdict not in SEVERITY:
        raise ExportError(f"verdict {verdict!r} is not one of VERIFIED, BROKEN, COULD NOT LOOK")
    cc = obj.get("could_not_check") if isinstance(obj.get("could_not_check"), dict) else {}
    paths += [rep.get("file"), rep.get("envelope"), rep.get("where"), cc.get("where")]
    if rec.get("reasons") is None:
        rec["reasons"] = (list(rep.get("findings") or [rep.get("reason")])
                          if verdict == V.BROKEN else
                          _cnl_reasons(rep.get("reason")) if verdict == V.COULD_NOT_LOOK else [])
    rec["reasons"] = [str(r) for r in (rec["reasons"] or []) if r]
    sealed = rep.get("sealed") if isinstance(rep.get("sealed"), dict) else {}
    cnc = None
    if verdict == V.COULD_NOT_LOOK:
        src = obj.get("could_not_check") if isinstance(obj.get("could_not_check"), dict) else rep
        cnc = {"looked_for": src.get("looked_for"), "where": _name(src.get("where")),
               "reason_word": src.get("reason_word")}
    rec.update(
        verdict=verdict, reason=rep.get("reason"), file=_name(file_path),
        envelope=_name(env_path), steps=rep.get("steps"), signers_valid=rep.get("signers"),
        sealed_by=sealed.get("sealed_by"), sealed_at=sealed.get("sealed_at"),
        sealed_for=sealed.get("binding"), label=sealed.get("label"),
        sealed_bytes=sealed.get("bytes"), could_not_check=cnc,
        not_checked=list(rep.get("not_checked") or []), note=rep.get("note"))
    if not rec["file_sha256"] and isinstance(rep.get("file_sha256"), str):
        rec["file_sha256"], rec["file_sha256_of"] = rep["file_sha256"], "the verify report"
    return _scrub(rec, _dirs(paths))


def _file_evidence(name: str, sha256: Any, size: Any) -> dict:
    f: dict[str, Any] = {"name": name, "type_id": FILE_TYPE_REGULAR[0],
                         "type": FILE_TYPE_REGULAR[1]}
    if isinstance(size, int) and not isinstance(size, bool):
        f["size"] = size
    if isinstance(sha256, str) and re.fullmatch(r"[0-9a-f]{64}", sha256):
        f["hashes"] = [{"algorithm_id": SHA256_ALGORITHM[0], "algorithm": SHA256_ALGORITHM[1],
                        "value": sha256}]
    return {"file": f}


def _product_version() -> str:
    try:
        from arcaeon import __version__
        return str(__version__)
    except Exception:  # noqa: BLE001
        return "unknown"


def to_ocsf(obj: Any, *, now: datetime | None = None,
            include_verified: bool = False) -> dict | None:
    """One OCSF 1.9.0 Detection Finding for one arcaeon verdict, or None for a
    VERIFIED input unless include_verified. Raises ExportError on an input
    that is not an arcaeon verdict."""
    rec = normalize(obj)
    verdict = rec["verdict"]
    if verdict == V.VERIFIED and not include_verified:
        return None
    sev_id, sev, alert = SEVERITY[verdict]
    t = _ms(now or datetime.now(timezone.utc))
    what = rec["file"] or "the checked input"
    uid = "arcaeon-" + hashlib.sha256(
        json.dumps(rec, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()[:32]
    if verdict == V.BROKEN:
        title = f"BROKEN: {what} failed its arcaeon check"
        lead = f"BROKEN: {'; '.join(rec['reasons']) or rec['reason'] or 'a check failed'}."
    elif verdict == V.COULD_NOT_LOOK:
        c = rec["could_not_check"] or {}
        title = f"COULD NOT LOOK: {what} could not be fully checked"
        why = "; ".join(rec["reasons"]) or rec["reason"]
        lead = (f"COULD NOT LOOK: could not check {c.get('looked_for') or 'a step'} "
                f"({c.get('reason_word') or 'unreadable'})" + (f": {why}." if why else "."))
    else:
        title = f"VERIFIED: {what} passed its arcaeon check"
        lead = "VERIFIED: the bytes are the bytes the named key sealed, labeled for this receiver."
    unchecked = list(rec["not_checked"])
    desc = lead + (f" Not checked: {'; '.join(unchecked)}." if unchecked else "")
    desc += " " + LIMITS_LINE
    evidences = []
    if rec["file"]:
        evidences.append(_file_evidence(rec["file"], rec["file_sha256"], rec["sealed_bytes"]))
    if rec["envelope"]:
        evidences.append(_file_evidence(rec["envelope"], rec["envelope_sha256"], None))
    unmapped = {k: rec[k] for k in (
        "verdict", "source", "reason", "reasons", "could_not_check", "not_checked", "steps",
        "file", "file_sha256", "file_sha256_of", "envelope", "envelope_sha256", "label",
        "sealed_by", "sealed_at", "sealed_for", "signers_valid", "signers_named",
        "audience_checked", "deal_checked", "purpose_checked", "action", "decision",
        "gate_reason", "checked_at", "evidence", "note")}
    unmapped["limits"] = LIMITS_LINE
    event: dict[str, Any] = {
        "activity_id": ACTIVITY_ID, "activity_name": ACTIVITY_NAME,
        "category_uid": CATEGORY_UID, "category_name": CATEGORY_NAME,
        "class_uid": CLASS_UID, "class_name": CLASS_NAME,
        "type_uid": TYPE_UID, "type_name": TYPE_NAME,
        "severity_id": sev_id, "severity": sev,
        "status_id": STATUS_ID, "status": STATUS_NAME,
        "status_code": verdict,
        "status_detail": rec["reason"] or (rec["reasons"][0] if rec["reasons"] else verdict),
        "is_alert": alert,
        "time": t, "timezone_offset": 0,
        "message": f"{verdict}: {what}",
        "metadata": {"version": OCSF_VERSION, "profiles": [],
                     "product": {"name": "arcaeon", "vendor_name": "arcaeon",
                                 "version": _product_version()}},
        "finding_info": {"uid": uid, "title": title, "desc": desc, "created_time": t,
                         "types": [f"arcaeon {rec['source']}"]},
        "unmapped": {"arcaeon": unmapped},
    }
    if evidences:
        event["evidences"] = evidences
    return _scrub(event, [])


def dumps(event: dict) -> str:
    """The event as deterministic JSON text (sorted keys, one trailing newline)."""
    return json.dumps(event, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def _parse_now(text: str) -> datetime:
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as e:
        raise ValueError(f"--now {text!r} is not an ISO time") from e
    if dt.tzinfo is None:
        raise ValueError(f"--now {text!r} has no zone (end it in Z)")
    return dt


def read_input(path: str) -> Any:
    """The JSON at path ('-' for stdin), strictly parsed. Raises ExportError."""
    from arcaeon.record.row import loads_strict
    try:
        if path == "-":
            text = sys.stdin.read(_MAX_INPUT_BYTES + 1)
        else:
            p = Path(path)
            if p.stat().st_size > _MAX_INPUT_BYTES:
                raise ExportError(f"{p.name} is over {_MAX_INPUT_BYTES} bytes; not read")
            text = p.read_bytes().decode("utf-8")
    except ExportError:
        raise
    except (OSError, UnicodeDecodeError) as e:
        raise ExportError(f"{_name(path) or path} cannot be read ({type(e).__name__})") from e
    if len(text) > _MAX_INPUT_BYTES:
        raise ExportError(f"the input is over {_MAX_INPUT_BYTES} bytes; not read")
    try:
        return loads_strict(text.lstrip("\ufeff"))
    except ValueError as e:
        raise ExportError(f"the input is not one JSON object ({str(e)[:120]})") from e


def export_cli(argv: list[str], parse, usage_error) -> int:
    """`arcaeon envelope export-ocsf INPUT [--include-verified] [--now WHEN] [--out FILE]`."""
    pos, o = parse(argv, {"--include-verified": "bool", "--now": "value", "--out": "value"})
    if len(pos) != 1:
        raise usage_error("export-ocsf takes one input (a JSON file, or - for stdin)")
    try:
        now = _parse_now(o["--now"]) if o.get("--now") else None
    except ValueError as e:
        raise usage_error(str(e)) from e
    try:
        event = to_ocsf(read_input(pos[0]), now=now,
                        include_verified=bool(o.get("--include-verified")))
    except ExportError as e:
        print(f"arcaeon envelope export-ocsf: {V.COULD_NOT_LOOK}: {e}; nothing was exported",
              file=sys.stderr)
        return V.EXIT_COULD_NOT_LOOK
    if event is None:
        print("VERIFIED: nothing exported (pass --include-verified to emit an informational "
              "finding)", file=sys.stderr)
        return V.EXIT_GOOD
    text = dumps(event)
    if o.get("--out"):
        Path(o["--out"]).write_text(text, encoding="utf-8", newline="\n")
        print(o["--out"])
    else:
        sys.stdout.write(text)
    return V.EXIT_GOOD


def main(argv: list[str] | None = None) -> int:  # pragma: no cover  (envelope.main wires it)
    from arcaeon.prove import envelope as E
    try:
        return export_cli(list(sys.argv[1:] if argv is None else argv), E._parse, E._Usage)
    except E._Usage as e:
        print(f"arcaeon envelope export-ocsf: {e}", file=sys.stderr)
        return V.EXIT_USAGE
