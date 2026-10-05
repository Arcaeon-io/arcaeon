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
With ocsf_version="1.3.0" the same event is cut down to OCSF_13_ALLOW (the
1.3.0 attributes it uses; `is_alert` is not one) and stamped 1.3.0, for the
Security Lake custom-source and Datadog Remap to OCSF paths, which target 1.3
and earlier. That is the record's content only: no Parquet is written.

    verdict          severity_id          is_alert  emitted
    BROKEN           4 High               true      always
    COULD NOT LOOK   2 Low                false     always, naming what was not checked
    VERIFIED         1 Informational      false     only with include_verified

A gate refusal is never skipped and never reads VERIFIED: when a gate input's
decision is refuse but its verdict is VERIFIED (a veto), the event reports
BROKEN on checker-broken and COULD NOT LOOK on checks-unreadable, nonparty-check
or any other veto, with the veto and the broken check rows in unmapped.

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
           "TYPE_UID", "SEVERITY", "LIMITS_LINE", "OCSF_VERSIONS", "OCSF_13_SOURCES",
           "OCSF_13_ALLOW", "ExportError", "normalize", "restrict", "to_ocsf", "dumps", "main"]

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

#: The versions `to_ocsf` writes: 1.9.0 (the default) and 1.3.0 (compatibility).
OCSF_VERSIONS = ("1.9.0", "1.3.0")

#: Why 1.3.0, and where its allowlist was read (2026-10-05, research note R16
#: and the 1.3.0 schema pages): Security Lake custom sources: "For custom
#: sources, Security Lake supports OCSF version 1.3 and earlier" (and only in
#: Parquet, which this module does not write); Datadog's Remap to OCSF
#: processor ships library mappings for OCSF 1.1.0 to 1.3.0.
OCSF_13_SOURCES = (
    "https://docs.aws.amazon.com/security-lake/latest/userguide/custom-sources.html",
    "https://docs.datadoghq.com/observability_pipelines/processors/remap_ocsf/",
    "https://schema.ocsf.io/1.3.0/api/classes/detection_finding",
    "https://schema.ocsf.io/1.3.0/api/objects/finding_info",
    "https://schema.ocsf.io/1.3.0/api/objects/metadata",
    "https://schema.ocsf.io/1.3.0/api/objects/product",
    "https://schema.ocsf.io/1.3.0/api/objects/evidences",
    "https://schema.ocsf.io/1.3.0/api/objects/file",
    "https://schema.ocsf.io/1.3.0/api/objects/fingerprint",
)

#: The 1.3.0 allowlist: an allowlist, not a denylist, so a field added to the
#: 1.9.0 event later is dropped in 1.3.0 mode until someone checks it against
#: the 1.3.0 pages and adds it here. Each key is a path in the event ("" the
#: top level, "[]" a list item); each set is the keys kept there. Every name
#: was read on the 1.3.0 pages above, with no profile applied. Not here, so
#: dropped: `is_alert` (not in the 1.3.0 class), the 1.9.0 Record Integrity
#: profile (`attestation_list`), `ai_agent` in `evidences`, and every profile
#: name in `metadata.profiles`. `unmapped` is kept whole: it is OCSF's own
#: container for source-specific attributes and is in the 1.3.0 base event.
OCSF_13_ALLOW = {
    "": {"activity_id", "activity_name", "category_uid", "category_name", "class_uid",
         "class_name", "type_uid", "type_name", "severity_id", "severity", "status_id",
         "status", "status_code", "status_detail", "time", "timezone_offset", "message",
         "metadata", "finding_info", "evidences", "unmapped"},
    "metadata": {"version", "profiles", "product"},
    "metadata.product": {"name", "vendor_name", "version"},
    "finding_info": {"uid", "title", "desc", "created_time", "types"},
    "evidences[]": {"file"},
    "evidences[].file": {"name", "type_id", "type", "size", "hashes"},
    "evidences[].file.hashes[]": {"algorithm_id", "algorithm", "value"},
}
#: Profiles kept in 1.3.0 mode: none (the export applies none).
OCSF_13_PROFILES: frozenset = frozenset()
_OPAQUE = {"unmapped"}

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


#: The gate vetoes (gate.CHECKER_BROKEN, CHECKS_UNREADABLE, NONPARTY_VETO): each
#: refuses with the envelope's own verdict left VERIFIED. Named here, not
#: imported, so this module stays pure.
_CHECKER_BROKEN = "checker-broken"
_MAX_BROKEN_LISTED = 100


def _checks_summary(c: Any) -> dict | None:
    """A gate decision's --checks answer, cut to what a SIEM needs: the veto,
    how many rows were read, and each row that said BROKEN (by checker, id,
    word and where it was read), never the row's own payload."""
    if not isinstance(c, dict):
        return None
    broken = [b for b in (c.get("broken") or []) if isinstance(b, dict)]
    out = {"veto": c.get("veto"), "files": [_name(p) for p in (c.get("files") or [])],
           "rows": c.get("rows"), "file_sha256": c.get("file_sha256"),
           "broken_count": len(broken),
           "broken": [{k: b.get(k) for k in ("checker", "adapter_version", "vendor_id",
                                             "vendor_word", "subject", "attestation",
                                             "reported_by", "source", "line")}
                      | {"file": _name(b.get("file"))} for b in broken[:_MAX_BROKEN_LISTED]],
           "problems": [str(p) for p in (c.get("problems") or [])]}
    for k in ("would_veto", "carried"):
        if c.get(k) is not None:
            out[k] = c[k]
    return out


def _nonparty_summary(n: Any) -> dict | None:
    if not isinstance(n, dict):
        return None
    return {k: n.get(k) for k in ("rule", "cap", "amount", "applies", "satisfied", "veto")}


def _word(rec: dict) -> str:
    """The word the event reports (status_code, severity, title): the verdict,
    except that a gate refusal is never VERIFIED. A refusal of a VERIFIED
    envelope is BROKEN on checker-broken (the gate exits 1) and COULD NOT LOOK
    on any other veto (checks-unreadable, nonparty-check, or one not named;
    the gate exits 3)."""
    verdict = rec["verdict"]
    if rec.get("decision") == "refuse" and verdict == V.VERIFIED:
        return V.BROKEN if rec.get("veto") == _CHECKER_BROKEN else V.COULD_NOT_LOOK
    return verdict


def normalize(obj: Any) -> dict:
    """The input as one flat record: which kind it was, the verdict and what
    the event carries. Raises ExportError on anything that is not an arcaeon
    envelope verify report, gate decision or gate evidence.json. A gate input
    that carries `checks` (the --checks answer) or `nonparty_check` (the
    non-party rule) adds `veto`, `checks` and `nonparty_check` to the record."""
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
    if rec["source"] != "verify report":
        checks, nonparty = _checks_summary(obj.get("checks")), _nonparty_summary(
            obj.get("nonparty_check"))
        if checks is not None or nonparty is not None:
            rec["veto"] = (checks or {}).get("veto") or (nonparty or {}).get("veto")
            rec["checks"], rec["nonparty_check"] = checks, nonparty
    word = _word(rec)
    cc = obj.get("could_not_check") if isinstance(obj.get("could_not_check"), dict) else {}
    paths += [rep.get("file"), rep.get("envelope"), rep.get("where"), cc.get("where")]
    if rec.get("reasons") is None:
        rec["reasons"] = (list(rep.get("findings") or [rep.get("reason")])
                          if verdict == V.BROKEN else
                          _cnl_reasons(rep.get("reason")) if verdict == V.COULD_NOT_LOOK else [])
    rec["reasons"] = [str(r) for r in (rec["reasons"] or []) if r]
    sealed = rep.get("sealed") if isinstance(rep.get("sealed"), dict) else {}
    cnc = None
    if word == V.COULD_NOT_LOOK:
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


def _keep(obj: Any, path: str) -> Any:
    """obj with only the keys OCSF_13_ALLOW lists at path; a dict at a path the
    allowlist does not name is dropped whole (None), so nothing unlisted leaks."""
    if isinstance(obj, list):
        out = [_keep(x, path + "[]") for x in obj]
        return [x for x in out if x not in (None, {})]
    if not isinstance(obj, dict):
        return obj
    allowed = OCSF_13_ALLOW.get(path)
    if allowed is None:
        return None
    out = {}
    for k, v in obj.items():
        if k not in allowed:
            continue
        sub = f"{path}.{k}" if path else k
        if path == "" and k in _OPAQUE:
            out[k] = v
            continue
        if isinstance(v, (dict, list)):
            kept = _keep(v, sub)
            if kept is None or (isinstance(v, list) and v and not kept):
                continue            # nothing allowlisted was left in it
            v = kept
        out[k] = v
    return out


def restrict(event: dict, version: str) -> dict:
    """The event as the given OCSF version: 1.9.0 returns it unchanged; 1.3.0
    keeps only what OCSF_13_ALLOW lists, drops every profile not in
    OCSF_13_PROFILES, and stamps metadata.version 1.3.0."""
    if version not in OCSF_VERSIONS:
        raise ValueError(f"OCSF version {version!r} is not one of {', '.join(OCSF_VERSIONS)}")
    if version == OCSF_VERSION:
        return event
    out = _keep(json.loads(json.dumps(event)), "")
    meta = out.setdefault("metadata", {})
    meta["version"] = version
    meta["profiles"] = [p for p in meta.get("profiles") or [] if p in OCSF_13_PROFILES]
    return out


def to_ocsf(obj: Any, *, now: datetime | None = None,
            include_verified: bool = False, ocsf_version: str = OCSF_VERSION) -> dict | None:
    """One OCSF Detection Finding (1.9.0 by default, or 1.3.0) for one arcaeon
    verdict, or None for a VERIFIED input unless include_verified. Raises
    ExportError on an input that is not an arcaeon verdict, ValueError on an
    ocsf_version not in OCSF_VERSIONS."""
    if ocsf_version not in OCSF_VERSIONS:
        raise ValueError(f"OCSF version {ocsf_version!r} is not one of "
                         f"{', '.join(OCSF_VERSIONS)}")
    rec = normalize(obj)
    verdict = word = _word(rec)              # a gate refusal is never VERIFIED here
    if word == V.VERIFIED and not include_verified:
        return None
    sev_id, sev, alert = SEVERITY[word]
    t = _ms(now or datetime.now(timezone.utc))
    what = rec["file"] or "the checked input"
    uid = "arcaeon-" + hashlib.sha256(
        json.dumps(rec, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()[:32]
    veto = rec.get("veto") if word != rec["verdict"] else None
    refused = f"{rec['action'] or 'the action'} refused"
    if word == V.BROKEN and veto == _CHECKER_BROKEN:
        names = ", ".join(sorted({str(b.get("checker")) for b in rec["checks"]["broken"]})) \
            or "a checker"
        title = f"BROKEN: a checker says BROKEN for {what}; {refused} ({veto})"
        lead = (f"BROKEN ({veto}): the envelope reads VERIFIED, but {names} says BROKEN for "
                f"these bytes; {refused}: "
                f"{'; '.join(rec['reasons']) or rec['reason'] or 'a checker said BROKEN'}.")
    elif word == V.BROKEN:
        title = f"BROKEN: {what} failed its arcaeon check"
        lead = f"BROKEN: {'; '.join(rec['reasons']) or rec['reason'] or 'a check failed'}."
    elif word == V.COULD_NOT_LOOK:
        c = rec["could_not_check"] or {}
        title = f"COULD NOT LOOK: {what} could not be fully checked" + (
            f"; {refused}" + (f" ({veto})" if veto else "") if word != rec["verdict"] else "")
        why = "; ".join(rec["reasons"]) or rec["reason"]
        lead = (f"COULD NOT LOOK: could not check {c.get('looked_for') or 'a step'} "
                f"({c.get('reason_word') or 'unreadable'})" + (f": {why}." if why else "."))
        if word != rec["verdict"]:
            lead += (f" The envelope reads VERIFIED; {refused} "
                     f"({veto or 'a veto'}).")
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
    for k in ("veto", "checks", "nonparty_check"):   # only on a gate input that has them
        if k in rec:
            unmapped[k] = rec[k]
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
    return restrict(_scrub(event, []), ocsf_version)


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
    """`arcaeon envelope export-ocsf INPUT [--include-verified] [--now WHEN]
    [--ocsf-version {1.9.0,1.3.0}] [--out FILE]`."""
    pos, o = parse(argv, {"--include-verified": "bool", "--now": "value", "--out": "value",
                          "--ocsf-version": "value"})
    if len(pos) != 1:
        raise usage_error("export-ocsf takes one input (a JSON file, or - for stdin)")
    try:
        now = _parse_now(o["--now"]) if o.get("--now") else None
    except ValueError as e:
        raise usage_error(str(e)) from e
    version = o.get("--ocsf-version") or OCSF_VERSION
    if version not in OCSF_VERSIONS:
        raise usage_error(f"--ocsf-version {version!r} is not one of {', '.join(OCSF_VERSIONS)}")
    try:
        event = to_ocsf(read_input(pos[0]), now=now, ocsf_version=version,
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
