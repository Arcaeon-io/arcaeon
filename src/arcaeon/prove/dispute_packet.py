# SPDX-License-Identifier: MIT
"""arcaeon.prove.dispute_packet: a refused handoff on one page (TE-26).

    from arcaeon.prove import dispute_packet as P
    p = P.from_evidence("deals/DEAL-d-7f3a/gate/20261004T152828Z-0123456789ab")
    p = P.from_decision(gate.decide(...).to_dict())     # a refusal with no deal id
    P.render_markdown(p)     # the page a marketplace's dispute process can take
    P.render_json(p)         # the same facts, kind arcaeon.dispute.packet/v1

The gate (arcaeon.prove.gate) refuses an action and, on a refusal with a
deal id (BROKEN or COULD NOT LOOK), keeps an evidence pack. This module
renders that refusal, from the pack's evidence.json or from the gate's
decision dict (a refusal without a deal id writes no pack), as one page in plain words: what was handed, by whom, for
whom, when, what failed, what was not checked, the verdict and the decision,
and the envelope spec's "does not prove" list quoted word for word.

It renders; it does not judge. The facts are the gate's own record. The one
thing it checks itself is whether an evidence pack's bundle copy still hashes
to the sha256 the pack recorded, and it says so.

Paths: only file names reach the packet. The directories the files sat in on
the receiver's machine are left out (a dispute needs the bytes and their
sha256, not the receiver's disk layout), and any absolute path left inside a
reason sentence is cut to its last part.

A decision that allowed the action has nothing to dispute: rendering one
raises NothingToDispute. Stdlib only.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from string import Template
from typing import Any

from arcaeon import verdict as V

__all__ = ["KIND", "SECTIONS", "DOES_NOT_PROVE", "LIMITS_SOURCE", "PACKET_LIMITS",
           "PacketError", "NothingToDispute", "from_evidence", "from_decision",
           "from_decision_file", "render_markdown", "render_json", "TEMPLATE"]

KIND = "arcaeon.dispute.packet/v1"
TEMPLATE = Path(__file__).with_name("templates") / "dispute_packet.md"
SECTIONS = ("Verdict and decision", "What was handed", "By whom", "For whom", "When",
            "What failed", "What was not checked", "Evidence", "What this does not prove")

LIMITS_SOURCE = 'docs/ENVELOPE.md, "What VERIFIED does not prove"'
#: docs/ENVELOPE.md's "What VERIFIED does not prove" bullets, word for word
#: (each bullet's wrapped lines joined by one space). tests/test_dispute_packet.py
#: reads the doc and fails if these drift from it.
DOES_NOT_PROVE = (
    "**That the content is true or safe.** A sealer can seal a false or poisoned file "
    "honestly; the seal proves who and when, never true. A perfectly sealed file can carry "
    "a prompt injection. Checking content is other tools' job; the envelope only says which "
    "bytes they would be judging.",
    "**That the key belongs to who the label says.** `sealed_by.name` is the sealer's own "
    "claim. Which did:key stands for which party is the receiver's decision (`--signer`); "
    "this version has no key register and no revocation. A stolen key signs anything, and "
    "nothing here can tell.",
    "**When it was sealed.** `sealed_at` is the sealer's clock. Only a resolved witness pin "
    "could fix the time from outside, and refs are not resolved yet.",
    "**That it has not expired, by anyone's clock but the receiver's.** `not_after` is "
    "judged by the receiver's clock. A receiver whose clock is behind accepts an expired "
    "envelope; one whose clock is ahead refuses a good one. Keep the receiving machine's "
    "clock synced.",
    "**That nobody can spoil it.** A third party who can edit the sidecar can turn VERIFIED "
    "into BROKEN (add a bad signature entry, a stray key, change a byte) but never into "
    "VERIFIED: every change it can make without the sealer's key is caught. BROKEN "
    "therefore means \"do not act, keep the evidence\", not \"the sealer lied\".",
    "**That it was not replayed within its own binding.** Inside one audience, deal, "
    "purpose and validity window, the same envelope can be presented twice. A receiver "
    "that must act once keeps the envelopes it has acted on.",
    "**Anything about colluding parties.** If the sealer and the receiver are the same "
    "owner, the envelope records their agreement, not the truth.",
    "**That the verifier is the real one.** Run your own copy.",
    "**That the sidecar is a Sigstore bundle.** It is shaped like one and is not one: no "
    "certificate, no transparency-log entry.",
)

PACKET_LIMITS = (
    "This packet renders the gate's own record. It is not signed and adds no check of its "
    "own, except re-hashing an evidence pack's bundle copy where it says so.",
    "File names only: the directories the files sat in on the receiver's machine are left "
    "out.",
    "A refusal is the receiver's answer about the envelope, not a finding about the "
    "content or about who is at fault.",
)

_SIG_PLAIN = {
    V.VERIFIED: "checked: the signature verifies and is by a key the receiver named",
    V.BROKEN: "checked and failed (see What failed)",
    V.COULD_NOT_LOOK: "not checked (see What was not checked)",
    None: "not reached: the check stopped before the signature",
}
_STEPS = ("envelope", "signature", "file", "binding", "witness")
_ABS = re.compile(r"(?:(?<![A-Za-z])[A-Za-z]:[\\/]|\\\\|(?<![\w.:/~-])/(?=[^\s/]))[^\s'\"<>|]*")
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|#])")
_CTRL = re.compile(r"[\x00-\x1f\x7f]+")


class PacketError(Exception):
    """The input could not be read as a gate record."""


class NothingToDispute(PacketError):
    """The gate allowed the action: there is no refusal to put on a page."""


# --- facts ----------------------------------------------------------------------

def _name(p: Any) -> str | None:
    if not p:
        return None
    s = str(p)
    return (PureWindowsPath(s) if ("\\" in s or re.match(r"[A-Za-z]:", s)) else PurePosixPath(s)).name or s


class _Scrub:
    """Cuts every known local path, and any absolute path left over, to its name."""

    def __init__(self, paths):
        self.known = sorted({str(p) for p in paths if p}, key=len, reverse=True)

    def __call__(self, v: Any) -> Any:
        if isinstance(v, str):
            for p in self.known:
                if p in v:
                    v = v.replace(p, _name(p) or "")
            return _ABS.sub(lambda m: _name(m.group(0).rstrip(".,;:)")) +
                            m.group(0)[len(m.group(0).rstrip(".,;:)")):], v)
        if isinstance(v, list):
            return [self(x) for x in v]
        if isinstance(v, dict):
            return {k: self(x) for k, x in v.items()}
        return v


def _hash(path: Path) -> dict | None:
    try:
        h, n = hashlib.sha256(), 0
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
                n += len(chunk)
        return {"sha256": h.hexdigest(), "bytes": n}
    except OSError:
        return None


def _refusal_check(verdict, decision) -> None:
    if verdict == V.VERIFIED:
        raise NothingToDispute("VERIFIED: nothing to dispute. The gate allowed every action; "
                               "a dispute packet renders a refusal.")
    if decision != "refuse":
        raise NothingToDispute(f"the gate's decision was {decision!r}, not 'refuse': nothing "
                               f"was refused, so there is nothing to dispute.")
    if verdict not in (V.BROKEN, V.COULD_NOT_LOOK):
        raise PacketError(f"unknown verdict word {verdict!r}")


def _packet(*, source, rec: dict, report: dict, handed: dict, evidence: dict,
            scrub: _Scrub) -> dict:
    verdict, decision = rec.get("verdict"), rec.get("decision")
    sealed = report.get("sealed") if isinstance(report.get("sealed"), dict) else {}
    by = sealed.get("sealed_by") if isinstance(sealed.get("sealed_by"), dict) else {}
    binding = sealed.get("binding") if isinstance(sealed.get("binding"), dict) else {}
    steps = report.get("steps") if isinstance(report.get("steps"), dict) else {}
    reasons = [str(r) for r in (rec.get("reasons") or []) if r]
    failed = reasons if verdict == V.BROKEN else []
    not_checked: list[str] = []
    cnc = rec.get("could_not_check") or ({k: report.get(k) for k in
                                          ("looked_for", "where", "reason_word")}
                                         if report.get("looked_for") else None)
    if cnc and cnc.get("looked_for"):
        where = _name(cnc.get("where"))
        not_checked.append(f"{cnc['looked_for']} ({cnc.get('reason_word') or 'unreadable'})"
                           + (f", looked for in {where}" if where else ""))
    if verdict == V.COULD_NOT_LOOK:
        # verify's whole sentence when it is there: the gate's `reasons` split it on "; "
        whole = report.get("reason")
        not_checked.extend([str(whole)] if whole else reasons)
    not_checked.extend(str(x) for x in (report.get("not_checked") or []))
    for s in _STEPS:
        w = steps.get(s)
        if w is None and steps:
            not_checked.append(f"step {s}: not reached (the check stopped before it)")
        elif w == V.COULD_NOT_LOOK:
            not_checked.append(f"step {s}: COULD NOT LOOK")
    sig = steps.get("signature")
    p = {
        "kind": KIND,
        "source": source,
        "verdict": verdict,
        "decision": decision,
        "action": rec.get("action"),
        "reason": rec.get("reason"),
        "steps": {s: steps.get(s) for s in _STEPS} if steps else None,
        "handed": {**handed, "label": sealed.get("label"), "sealed_bytes": sealed.get("bytes")},
        "by": {"name": by.get("name"), "key": by.get("key"),
               "signature": sig, "signature_plain": _SIG_PLAIN.get(sig, _SIG_PLAIN[None]),
               "valid_signatures_by": list(report.get("signers") or []),
               "receiver_named": rec.get("signers")},
        "for": {"audience_checked": rec.get("audience"), "deal_checked": rec.get("deal"),
                "purpose_checked": rec.get("purpose"),
                "sealed_audience": binding.get("audience"), "sealed_deal": binding.get("deal"),
                "sealed_purpose": binding.get("purpose"),
                "not_after": binding.get("not_after"),
                "not_given": [k for k in ("audience", "deal", "purpose")
                              if k in rec and rec.get(k) is None]},
        "when": {"sealed_at": sealed.get("sealed_at"), "checked_at": rec.get("at")},
        "failed": failed,
        "not_checked": not_checked,
        "evidence": evidence,
        "limits": list(DOES_NOT_PROVE),
        "limits_source": LIMITS_SOURCE,
        "packet_limits": list(PACKET_LIMITS),
        "paths": "names only",
    }
    out = scrub(p)
    out["limits"], out["packet_limits"] = list(DOES_NOT_PROVE), list(PACKET_LIMITS)
    return out


def from_evidence(directory: str | Path) -> dict:
    """The packet for a gate evidence pack (the directory holding evidence.json)."""
    from arcaeon.prove.gate import EVIDENCE_KIND
    d = Path(directory)
    ev_path = d / "evidence.json" if d.is_dir() else d
    d = ev_path.parent
    try:
        ev = json.loads(ev_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as e:
        raise PacketError(f"cannot read {ev_path.name} ({type(e).__name__})") from None
    if not isinstance(ev, dict) or ev.get("kind") != EVIDENCE_KIND:
        raise PacketError(f"{ev_path.name} is not a gate evidence record (kind must be "
                          f"{EVIDENCE_KIND})")
    _refusal_check(ev.get("verdict"), ev.get("decision"))
    report = ev.get("report") if isinstance(ev.get("report"), dict) else {}
    parts, rechecked = {}, {}
    for key in ("file", "envelope"):
        e = ev.get(key) if isinstance(ev.get(key), dict) else {}
        parts[key] = e
        copy = e.get("copy")
        if not copy:
            rechecked[key] = "no copy in the pack" + (f" ({e['error']})" if e.get("error") else "")
            continue
        target = (d / copy).resolve()
        if d.resolve() not in target.parents:
            rechecked[key] = "the recorded copy path leaves the pack; not read"
            continue
        now = _hash(target)
        if now is None:
            rechecked[key] = "the copy is not there now"
        elif now["sha256"] == e.get("sha256") and now["bytes"] == e.get("bytes"):
            rechecked[key] = "re-hashed when this packet was made: matches"
        else:
            rechecked[key] = (f"re-hashed when this packet was made: DIFFERS (now "
                              f"{now['sha256']}, {now['bytes']} bytes)")
    f, env = parts["file"], parts["envelope"]
    handed = {"file": _name(f.get("path")) or _name(f.get("copy")),
              "sha256": f.get("sha256"), "bytes": f.get("bytes"),
              "sha256_of": "the bytes the gate copied into the evidence pack"}
    evidence = {"pack": d.name, "file_copy": f.get("copy"), "file_copy_check": rechecked["file"],
                "envelope_file": _name(env.get("path")) or _name(env.get("copy")),
                "envelope_copy": env.get("copy"), "envelope_sha256": env.get("sha256"),
                "envelope_bytes": env.get("bytes"),
                "envelope_copy_check": rechecked["envelope"], "error": None}
    scrub = _Scrub([f.get("path"), env.get("path"), report.get("file"), report.get("envelope"),
                    report.get("where"), str(d), str(d.resolve())])
    return _packet(source="evidence pack", rec=ev, report=report, handed=handed,
                   evidence=evidence, scrub=scrub)


def from_decision(decision: dict | Any, *, hash_file: bool = True) -> dict:
    """The packet for a gate decision (GateDecision or its to_dict()). With
    `hash_file`, the handed file is hashed now when it is readable, and the
    packet says the hash was taken when the packet was made."""
    if hasattr(decision, "to_dict"):
        decision = decision.to_dict()
    if not isinstance(decision, dict) or "verdict" not in decision or "decision" not in decision:
        raise PacketError("not a gate decision (needs verdict and decision; use the output of "
                          "`arcaeon gate decide --json`)")
    _refusal_check(decision.get("verdict"), decision.get("decision"))
    report = decision.get("report") if isinstance(decision.get("report"), dict) else {}
    file = decision.get("file") or report.get("file")
    got = _hash(Path(file)) if (hash_file and file) else None
    handed = {"file": _name(file), "sha256": got and got["sha256"], "bytes": got and got["bytes"],
              "sha256_of": ("the file as found when this packet was made (the gate keeps no "
                            "copy without an evidence pack)") if got else
                           "not recorded: the gate keeps no copy without an evidence pack"}
    ev_dir = decision.get("evidence")
    evidence = {"pack": _name(ev_dir), "file_copy": None, "file_copy_check": None,
                "envelope_file": _name(decision.get("envelope") or report.get("envelope")),
                "envelope_copy": None, "envelope_sha256": None, "envelope_bytes": None,
                "envelope_copy_check": None, "error": decision.get("evidence_error")}
    rec = dict(decision)
    if isinstance(rec.get("reason"), str):
        rec["reason"] = rec["reason"].split(" Evidence pack written to ")[0]
    scrub = _Scrub([file, decision.get("envelope"), report.get("file"), report.get("envelope"),
                    report.get("where"), ev_dir])
    return _packet(source="gate decision", rec=rec, report=report, handed=handed,
                   evidence=evidence, scrub=scrub)


def from_decision_file(path: str | Path, *, hash_file: bool = True) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as e:
        raise PacketError(f"cannot read {_name(path)} ({type(e).__name__})") from None
    return from_decision(data, hash_file=hash_file)


# --- rendering ------------------------------------------------------------------

def render_json(packet: dict) -> str:
    return json.dumps(packet, indent=1, ensure_ascii=False, sort_keys=False) + "\n"


def _one(v: Any, limit: int = 300) -> str:
    s = _CTRL.sub(" ", str(v)).strip()
    return s if len(s) <= limit else s[:limit] + "..."


def _code(v: Any) -> str:
    """An untrusted value as a code span: markdown inside it is inert."""
    if v is None or v == "":
        return "not recorded"
    s = _one(v)
    tick = "``" if "`" in s else "`"
    pad = " " if tick == "``" else ""
    return f"{tick}{pad}{s.replace('``', '` `')}{pad}{tick}"


def _text(v: Any) -> str:
    return _MD_SPECIAL.sub(r"\\\1", _one(v, 2000))


def _bullets(items, empty: str) -> str:
    return "\n".join(f"- {_text(i)}" for i in items) if items else f"- {empty}"


def _rows(rows) -> str:
    return "\n".join(f"- {k}: {v}" for k, v in rows)


def render_markdown(packet: dict) -> str:
    p = packet
    h, by, fo, wh, ev = p["handed"], p["by"], p["for"], p["when"], p["evidence"]
    steps = p.get("steps") or {}
    summary = (f"The receiver refused to **{_text(p['action'])}** on the file "
               f"{_code(h.get('file'))}. The envelope check answered **{p['verdict']}**.")
    verdict_block = _rows([
        ("Verdict", f"**{p['verdict']}**"),
        ("Decision", f"**{p['decision']}** `{_one(p['action'])}`"),
        ("The gate's sentence", _text(p.get("reason") or "not recorded")),
        ("Each step's word", ", ".join(f"{s} {steps.get(s) or 'not reached'}" for s in _STEPS)
         if steps else "not recorded"),
    ])
    handed_block = _rows([
        ("File name", _code(h.get("file"))),
        ("sha256", _code(h.get("sha256"))),
        ("Size", f"{h['bytes']} bytes" if h.get("bytes") is not None else "not recorded"),
        ("The sha256 is of", _text(h.get("sha256_of"))),
        ("Label (the sealer's words, not checked)", _code(h.get("label"))),
        ("Size when sealed", f"{h['sealed_bytes']} bytes" if h.get("sealed_bytes") is not None
         else "not recorded"),
    ])
    named = by.get("receiver_named")
    by_block = _rows([
        ("Sealed by, as named in the envelope (the sealer's claim, not checked)",
         _code(by.get("name"))),
        ("Key named in the envelope", _code(by.get("key"))),
        ("Signature", (f"{by['signature']}: " if by.get("signature") else "")
         + _text(by["signature_plain"])),
        ("Signatures that verified, by key", ", ".join(_code(k) for k in
                                                       by.get("valid_signatures_by") or [])
         or "none"),
        ("Keys the receiver named", ", ".join(_code(k) for k in named) if named
         else "not recorded"),
    ])
    def given(k):
        v = fo.get(f"{k}_checked")
        if v is None and k in (fo.get("not_given") or []):
            return "not given by the receiver, so not held against the envelope"
        return _code(v)

    for_block = _rows([
        ("Audience checked (the receiver)", given("audience")),
        ("Deal checked", given("deal")),
        ("Purpose checked", given("purpose")),
        ("Sealed for audience", _code(fo.get("sealed_audience"))),
        ("Sealed for deal", _code(fo.get("sealed_deal"))),
        ("Sealed for purpose", _code(fo.get("sealed_purpose"))),
    ])
    when_block = _rows([
        ("Sealed at (the sealer's clock, not checked)", _code(wh.get("sealed_at"))),
        ("Checked at (the receiver's clock, UTC)", _code(wh.get("checked_at"))),
        ("Not after", _code(fo.get("not_after"))),
    ])
    failed_block = _bullets(p["failed"], "Nothing checked came out wrong. The refusal is "
                                         "because something could not be checked (below).")
    not_checked_block = _bullets(p["not_checked"], "Every step was checked.")
    if ev.get("pack"):
        evidence_block = _rows([
            ("Evidence pack", _code(ev["pack"])),
            ("File copy", f"{_code(ev.get('file_copy'))}; {_text(ev.get('file_copy_check'))}"
             if ev.get("file_copy_check") else _code(ev.get("file_copy"))),
            ("Envelope", _code(ev.get("envelope_file"))),
            ("Envelope copy", f"{_code(ev.get('envelope_copy'))}; sha256 "
                              f"{_code(ev.get('envelope_sha256'))}, "
                              f"{ev.get('envelope_bytes')} bytes; "
                              f"{_text(ev.get('envelope_copy_check'))}"
             if ev.get("envelope_copy") else "not recorded"),
        ])
    else:
        evidence_block = _rows([
            ("Evidence pack", "none written (the gate writes one only on a refusal with a deal id)"
             + (f"; {_text(ev['error'])}" if ev.get("error") else "")),
            ("Envelope", _code(ev.get("envelope_file"))),
        ])
    limits_block = "\n".join(f"> - {t}" for t in p["limits"])
    tpl = Template(TEMPLATE.read_text(encoding="utf-8"))
    return tpl.substitute(
        summary=summary, kind=p["kind"],
        source=("an " if p["source"][:1] in "aeiou" else "a ") + p["source"],
        verdict_block=verdict_block, handed_block=handed_block, by_block=by_block,
        for_block=for_block, when_block=when_block, failed_block=failed_block,
        not_checked_block=not_checked_block, evidence_block=evidence_block,
        limits_source=p["limits_source"], limits_block=limits_block,
        packet_limits_block="\n".join(f"- {t}" for t in p["packet_limits"]))
