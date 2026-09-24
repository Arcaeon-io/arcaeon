"""Receipt core: build, verify, exhibit.

A receipt is a JSON object with a BODY (kind, subject, checks, scope, extra,
issued_at) and three attachments that bind the body to things outside the
issuer's control, in increasing order of independence:

  ledger   one hash-chained row in an arcaeon-ledger file holding the body
           digest -- proves sequence relative to the issuer's other receipts.
  witness  the ledger head pinned somewhere else -- hosted arcaeon-witness if
           configured (public GitHub commits), otherwise a LOCAL file that the
           receipt labels as self-controlled. The label is the honesty.
  anchor   an OpenTimestamps stamp of the body digest -- proves the body
           existed by a time no party in the dispute controls (Bitcoin).
           Fresh stamps are calendar-pending; they upgrade hours later.

verify_receipt recomputes the body digest from the body fields (any edit to
a check, a status, a scope sentence, breaks it), optionally re-walks the
ledger, and optionally runs `ots verify`. It returns typed verdicts and
never raises on malformed input; a receipt that cannot be verified says why.
"""
from __future__ import annotations

from arcaeon.record.row import body_digest

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sysconfig
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from arcaeon.record.ledger import (Ledger, WitnessStore, chain_at, digest_json,
                            publish_head, verify_file)

RECEIPT_VERSION = "arcaeon-receipt/0.1"
BODY_FIELDS = ("receipt_version", "kind", "issued_at", "subject", "checks",
               "scope", "extra")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _body_of(receipt: dict) -> dict:
    return {k: receipt.get(k) for k in BODY_FIELDS}


# --------------------------------------------------------------------------
# witness
# --------------------------------------------------------------------------

def _witness_pin(ledger: Ledger, ledger_path: Path, namespace: str) -> dict:
    """Pin the ledger head. Hosted if ARCAEON_WITNESS_URL/KEY are set, else a
    local sidecar file. Either way the receipt says which, and what that is
    worth: a local witness is self-controlled and proves nothing to a
    stranger; it exists so the shape is exercised end to end before a key
    is provisioned, and so the verifier code path is one path."""
    head = ledger.head()
    url = os.environ.get("ARCAEON_WITNESS_URL", "").rstrip("/")
    key = os.environ.get("ARCAEON_WITNESS_KEY", "")
    if url and key:
        # A pin is the one artifact a stranger is meant to trust, so it is never
        # minted over a ledger that does not verify. Found 2026-09-19: this
        # branch POSTed head.rows/head.chain directly, and arcaeon-ledger 0.7.5's
        # head() returns chain="genesis", rows=0 on a CORRUPT file without
        # raising, so a damaged log would have been published as a fresh one.
        # Version-independent on purpose: newer ledgers carry the verdict on
        # Head, older ones do not, so fall back to verify_file. Refuse only on
        # an explicit False; a bounded/declared verdict (None) still pins.
        if hasattr(head, "ok"):
            ok, why = head.ok, getattr(head, "first_break", None)
        else:
            vr = verify_file(ledger_path)
            ok, why = vr.ok, vr.first_break
        if ok is False:
            return {"kind": "hosted", "url": url, "namespace": namespace,
                    "rows": head.rows, "chain": head.chain,
                    "status": "pin_refused",
                    "error": ("ledger does not verify: %s" % why)[:200],
                    "independence": "none: no pin was requested, because the "
                                    "ledger it would describe does not verify"}
        body = json.dumps({"namespace": namespace, "rows": head.rows,
                           "chain": head.chain}).encode()
        req = urllib.request.Request(url + "/api/pin", data=body, method="POST")
        req.add_header("Authorization", "Bearer " + key)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                d = json.loads(r.read() or b"{}")
            return {"kind": "hosted", "independence": "third-party-timestamped public commits",
                    "url": url, "namespace": namespace, "rows": head.rows,
                    "chain": head.chain, "pin": d.get("pin") or d,
                    "history": d.get("history"), "status": "pinned"}
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError, OSError) as e:
            return {"kind": "hosted", "url": url, "namespace": namespace,
                    "rows": head.rows, "chain": head.chain,
                    "status": "pin_failed", "error": str(e)[:200],
                    "independence": "none: the pin did not land; this receipt is unwitnessed"}
    store = WitnessStore(str(ledger_path) + ".witness.jsonl")
    pin = publish_head(store, namespace, ledger, received_at=_now_iso())
    return {"kind": "local-file", "independence": "none (self-controlled file)",
            "path": str(ledger_path) + ".witness.jsonl", "namespace": namespace,
            "rows": head.rows, "chain": head.chain, "pin": pin, "status": "pinned"}


# --------------------------------------------------------------------------
# OpenTimestamps anchor
# --------------------------------------------------------------------------

def ots_exe() -> Optional[Path]:
    for cand in (Path(sysconfig.get_path("scripts", "nt_user") or "") / "ots.exe",
                 Path(sysconfig.get_path("scripts") or "") / "ots.exe"):
        if cand.exists():
            return cand
    found = shutil.which("ots")
    return Path(found) if found else None


def _run_ots(args: list, timeout: int = 180) -> subprocess.CompletedProcess:
    exe = ots_exe()
    if exe is None:
        raise FileNotFoundError("ots client not installed (pip install opentimestamps-client)")
    env = dict(os.environ)
    env["PATH"] = str(exe.parent) + os.pathsep + env.get("PATH", "")
    return subprocess.run([str(exe)] + args, capture_output=True, text=True,
                          timeout=timeout, env=env,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _anchor_bytes(body_digest: str) -> bytes:
    # The stamped file is reconstructible from the receipt alone, so a
    # verifier never needs anything from us: write this line, drop the .ots
    # beside it, run `ots verify`.
    return (body_digest + "\n").encode("utf-8")


def _ots_stamp(body_digest: str) -> dict:
    data = _anchor_bytes(body_digest)
    if ots_exe() is None:
        return {"kind": "opentimestamps", "status": "not_stamped",
                "reason": "ots client not installed on the issuing machine",
                "stamped_sha256": hashlib.sha256(data).hexdigest()}
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "receipt.anchor"
        f.write_bytes(data)
        try:
            r = _run_ots(["stamp", str(f)])
        except (subprocess.TimeoutExpired, OSError) as e:
            return {"kind": "opentimestamps", "status": "not_stamped",
                    "reason": f"ots stamp failed: {str(e)[:120]}",
                    "stamped_sha256": hashlib.sha256(data).hexdigest()}
        ots = f.with_suffix(".anchor.ots")
        if not ots.exists():
            return {"kind": "opentimestamps", "status": "not_stamped",
                    "reason": "ots stamp produced no proof: " + (r.stderr or r.stdout).strip()[:160],
                    "stamped_sha256": hashlib.sha256(data).hexdigest()}
        return {"kind": "opentimestamps", "status": "pending-calendar",
                "note": "calendar attestation only; upgrades to a Bitcoin attestation hours later via `ots upgrade`",
                "stamped_sha256": hashlib.sha256(data).hexdigest(),
                "ots_b64": base64.b64encode(ots.read_bytes()).decode("ascii")}


#: The only ots_verify statuses that count as a proven anchor when a caller
#: asks for the anchor to be checked. Everything else is not a yes.
ANCHOR_POSITIVE = ("bitcoin-attested",)


def ots_verify(receipt: dict) -> dict:
    """Reconstruct the anchored file from the receipt and run `ots verify`.
    Typed result, never raises."""
    anc = receipt.get("anchor") or {}
    if anc.get("kind") != "opentimestamps" or not anc.get("ots_b64"):
        return {"status": "no_anchor"}
    if ots_exe() is None:
        return {"status": "tool_missing",
                "note": "install opentimestamps-client to verify locally; the .ots bytes are in the receipt"}
    body_digest = receipt.get("body_digest", "")
    if not isinstance(body_digest, str):
        return {"status": "error", "detail": "body_digest is not a string; nothing to anchor"}
    try:
        ots_bytes = base64.b64decode(anc["ots_b64"], validate=True)
    except (ValueError, TypeError) as e:
        # binascii.Error is a ValueError: a corrupt proof is a typed error,
        # never an exception out of the verifier.
        return {"status": "error", "detail": f"ots_b64 is not valid base64: {str(e)[:160]}"}
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "receipt.anchor"
        f.write_bytes(_anchor_bytes(body_digest))
        f.with_suffix(".anchor.ots").write_bytes(ots_bytes)
        try:
            r = _run_ots(["verify", str(f.with_suffix(".anchor.ots"))], timeout=120)
        except (subprocess.TimeoutExpired, OSError) as e:
            return {"status": "error", "detail": str(e)[:200]}
    out = ((r.stdout or "") + "\n" + (r.stderr or "")).strip()
    low = out.lower()
    if "bitcoin block" in low and "success" in low:
        return {"status": "bitcoin-attested", "detail": out[:400]}
    if "pending" in low or "not enough confirmations" in low or "calendar" in low:
        return {"status": "pending", "detail": out[:400]}
    if "bad" in low or "fail" in low or r.returncode != 0:
        return {"status": "failed", "detail": out[:400]}
    return {"status": "unknown", "detail": out[:400]}


# --------------------------------------------------------------------------
# AB 1405 (Cal. Gov. Code S11549.83(d)(1)) report-element carriers
# --------------------------------------------------------------------------
# A registered AI auditor's report to the auditee must include six elements,
# (A) through (F) -- see projects/arcaeon/AB1405_REPORT_ELEMENT_MAP_2026-09-15.md
# for the full statute-to-field mapping this section implements. Two of the
# six are already carried by shapes this module has had since the start:
# (B) results/documentation is the `checks` list and `subject` dict; (E) is
# the mandatory, non-empty `scope["does_not_prove"]` build_receipt() already
# refuses to omit. The four helpers/fields below are the optional,
# backward-compatible carriers for (A), (C), (D), and (F).
#
# None of these fields can be filled in by this tool. Every value here is a
# professional judgment the AUDITOR makes -- whether a deficiency calls for
# remediation, whether the auditee met its own named standard, whether the
# audit itself complied with the statute. This module's only job is to seal
# whatever the auditor writes against later editing, the same way
# ballot.branding() seals a vendor name: an ordinary dict key that
# build_receipt() was already digesting via BODY_FIELDS, so no digest-path
# change is needed and every receipt minted before this existed verifies
# byte-for-byte, unchanged.
#
# (A) extra.engagement_scope -- built by engagement_scope() below.
# (B) HAVE already: `checks` + `subject`.
# (C) checks[]["remediation"] -- an ordinary optional string key an adapter
#     or caller sets directly on a check dict before calling build_receipt().
#     The statute's own qualifier is "if appropriate": this field is never
#     required, and build_receipt() never invents or requires a value here
#     -- it is meaningful only on a flagged/deficient check, and only the
#     auditor decides whether one applies and what it says.
# (D) subject.internal_standards_ref -- an ordinary optional string/URI key
#     on the `subject` dict, naming the auditee's own internal safety
#     standard/protocol document. checks[]["adherence"] -- an ordinary
#     optional key on a check dict, restricted to ADHERENCE_VALUES and
#     validated by build_receipt() above. Neither field asserts adherence;
#     both only carry the auditor's own finding about it.
# (E) HAVE already: mandatory `scope["does_not_prove"]`.
# (F) extra.attestation -- built by attestation() below. Carries the
#     statute's own sentence and the auditor's name/date; the actual
#     cryptographic signature over that sentence is a DETACHED signature
#     over the body digest and is carried OUTSIDE the digested body, by
#     construction -- see attach_attestation_signature() for why and how.

#: (D) checks[]["adherence"] is restricted to these three values, or absent.
#: "not_assessed" exists because element (D) is scoped to "protocols that
#: are within the scope of the covered AI audit" -- a check outside that
#: scope has a true, non-evasive answer that is neither "adhered" nor
#: "not_adhered".
ADHERENCE_VALUES = ("adhered", "not_adhered", "not_assessed")


def engagement_scope(text: str) -> dict:
    """extra["engagement_scope"] for AB 1405 element (A): the audit's scope
    and objectives AT ENGAGEMENT LEVEL -- which systems were in scope, over
    what period, against which named state-law requirement. The per-check
    `scope["proves"]`/`scope["method"]` already states what ONE check
    attests; this is the wider sentence the auditor writes once for the
    whole engagement this receipt is one exhibit within.

    Blank/absent text returns {} and writes no key -- an unbranded receipt
    stays byte-identical to one minted before this function existed, same
    absent-writes-no-key convention as `ballot.branding()`.
    """
    text = (text or "").strip()
    return {"engagement_scope": text} if text else {}


def attestation(statement: str, auditor_name: str, *, auditor_registry_id: Optional[str] = None,
               signed_at: Optional[str] = None) -> dict:
    """extra["attestation"] for AB 1405 element (F): "A statement indicating
    that the audit was conducted in accordance with the requirements of
    this chapter, signed and dated by the AI auditor."

    That signature is the auditor's own act, by law -- never this tool's.
    This function only gives the statute's sentence, the auditor's name,
    and a date a place to live inside the digested body, so none of the
    three can be edited after issue. Calling this function proves nothing
    about whether the audit actually complied with anything: verify_receipt()
    checks only that this block, if present, is byte-identical to what was
    sealed at issue -- never that its contents are true, and its presence
    or absence never changes verify_receipt()'s "ok" verdict either way.

    The cryptographic signature the statute's "signed ... by the AI
    auditor" language calls for is intentionally NOT a field this function
    accepts: see attach_attestation_signature() below for where that lives
    and why it cannot live here.

    Blank/absent statement or auditor_name returns {} and writes no key,
    same convention as engagement_scope() and ballot.branding().
    """
    statement, auditor_name = (statement or "").strip(), (auditor_name or "").strip()
    if not statement or not auditor_name:
        return {}
    block = {"statement": statement, "auditor_name": auditor_name,
             "signed_at": signed_at or _now_iso()}
    if auditor_registry_id and str(auditor_registry_id).strip():
        block["auditor_registry_id"] = str(auditor_registry_id).strip()
    return {"attestation": block}


def attach_attestation_signature(receipt: dict, signature: str, *, algorithm: str = "unspecified") -> dict:
    """Attach the auditor's detached signature over this receipt's
    body_digest, AFTER issue -- as a fourth top-level attachment beside
    `ledger`/`witness`/`anchor`, never inside `extra.attestation` and never
    part of BODY_FIELDS.

    This is by construction, not by omission: a signature over the body
    digest can only be computed once the digest exists, so it cannot also
    be one of the inputs that produces that same digest without becoming
    circular. Every other AB 1405 field in this module goes INSIDE the
    digested body; this is the one exception, and it is the only field
    among the four this task added that is not tamper-evident by the body
    digest -- editing or stripping `receipt["attestation_signature"]"`
    after the fact does NOT change `body_digest_ok`. That is the honest
    shape: this tool never signs anything, so it has no mechanism of its
    own to make a detached signature tamper-evident, and would rather say
    so plainly than imply a guarantee the digest does not actually give.

    Mutates and returns `receipt`.

    What verify_receipt() does with it (2026-09-22, receipt-fix-round2): a
    signature whose `body_digest` is not this receipt's, or whose
    `signed_over` is not "body_digest", does not belong to this receipt and
    fails ("mismatch"). The `value` itself is reported as "could_not_look":
    the format carries no public key and names no scheme, so nobody holding
    only the receipt can check it, and the result says so rather than
    staying silent. Proposed fix: FORMAT_CHANGE_PROPOSAL.md s.3.
    """
    receipt["attestation_signature"] = {
        "algorithm": algorithm, "signed_over": "body_digest",
        "body_digest": receipt.get("body_digest"), "value": signature,
    }
    return receipt


# --------------------------------------------------------------------------
# attachments outside the body digest: CHECKED, CLAIMED, or COULD NOT LOOK
# --------------------------------------------------------------------------
# The body digest covers BODY_FIELDS and nothing else. `ledger`, `witness`,
# `anchor` and `attestation_signature` are the issuer's statements ABOUT the
# body, attached after the digest exists, so an edit to any of them leaves
# body_digest_ok untouched (conformance findings, 2026-09-22). A verifier that
# prints those statements beside a PASS without saying so presents an
# unchecked claim as a checked one. The rule from 2026-09-22 on:
#
#   checked        this run recomputed or looked it up, and it held
#   claimed        the issuer says so; nothing in the receipt lets this run
#                  check it offline (shown, labelled, never as a pass)
#   could_not_look the thing is checkable in principle but the format carries
#                  nothing to check it WITH (no key, no scheme)
#   inconsistent / mismatch
#                  the attachment contradicts the receipt's own other fields
#                  or its own self-digest. That IS determined, so it fails.
#
# What still cannot be closed without a format change is written up in
# FORMAT_CHANGE_PROPOSAL.md (issuer signature over the body digest; a pin
# signed by the witness's own key; a public key and scheme for the attestation
# signature).

#: Verdict vocabulary for attachments outside the body digest.
ATTACH_CLAIMED = "claimed"
ATTACH_INCONSISTENT = "inconsistent"
ATTACH_ABSENT = "absent"
ATTACH_COULD_NOT_LOOK = "could_not_look"
ATTACH_MISMATCH = "mismatch"


def _pin_self_digest(pin: dict) -> str:
    """The `self` digest arcaeon_ledger.WitnessStore writes on every pin
    (0.5.9+): sha256 over the pin minus `prev`/`self`, sorted keys, Python
    json.dumps default separators, ensure_ascii=False, first 32 hex chars.
    Uses the library's own function when it exposes one, so there is one
    recipe, and falls back to the same recipe written out."""
    fn = getattr(WitnessStore, "_digest_record", None)
    if callable(fn):
        return fn(pin)
    return body_digest(pin, ("prev", "self"))


def _check_witness(receipt: dict, ledger_status: str) -> dict:
    """What can be said about the witness block offline. Never raises.

    Checkable here: that the block agrees with itself and with the ledger
    block (the pin was taken of the head the receipt's own ledger row made),
    and that a WitnessStore-shaped pin still hashes to its own `self`. When the
    ledger was walked and held, those rows/chain are bound to a verified row.

    NOT checkable here, so CLAIMED: `kind`, `independence`, `url`, `status`.
    Whether a pin is hosted by a third party or sits in the issuer's own file
    is the issuer's word until someone asks the witness itself; this verifier
    does not contact anyone. Relabelling a local pin as hosted therefore does
    not fail here, and it no longer reads as checked either."""
    wit = receipt.get("witness")
    if wit is None:
        return {"verdict": ATTACH_ABSENT, "note": "the receipt carries no witness block"}
    if not isinstance(wit, dict):
        return {"verdict": ATTACH_INCONSISTENT, "problems": ["the witness block is not an object"]}
    if wit.get("status") == "skipped" and not any(k in wit for k in ("kind", "pin", "rows", "chain")):
        return {"verdict": ATTACH_ABSENT, "note": "no witness was requested at issue"}
    led = receipt.get("ledger") if isinstance(receipt.get("ledger"), dict) else {}
    problems = []
    for k in ("rows", "chain", "namespace"):
        if k in wit and k in led and wit[k] != led[k]:
            problems.append(f"witness.{k} ({wit[k]!r}) disagrees with ledger.{k} ({led[k]!r})")
    pin = wit.get("pin")
    pin_self = None
    if pin is not None:
        if not isinstance(pin, dict):
            problems.append("witness.pin is not an object")
        else:
            for k in ("rows", "chain", "namespace"):
                if k in pin and k in wit and pin[k] != wit[k]:
                    problems.append(f"witness.pin.{k} ({pin[k]!r}) disagrees with witness.{k} ({wit[k]!r})")
            if "self" in pin and "prev" in pin:
                try:
                    pin_self = _pin_self_digest(pin) == pin["self"]
                except (TypeError, ValueError):
                    pin_self = False
                if not pin_self:
                    problems.append("witness.pin.self does not recompute: the pin was edited after it was recorded")
    claimed = {k: wit.get(k) for k in ("kind", "independence", "url", "status") if k in wit}
    out = {"claimed": claimed,
           "note": ("kind, independence, url and status are the issuer's statements. They sit "
                    "outside the body digest and this verifier did not contact the witness, so "
                    "they are CLAIMED, not checked.")}
    if problems:
        out.update(verdict=ATTACH_INCONSISTENT, problems=problems)
        return out
    out["verdict"] = ATTACH_CLAIMED
    out["pin_self_digest"] = "checked" if pin_self else "not_present"
    out["rows_chain"] = ("bound to the walked ledger row" if ledger_status == "consistent"
                         else "agree with the ledger block (itself unchecked in this run)")
    return out


def _check_attestation_signature(receipt: dict, body_digest: Any) -> dict:
    """The detached AB 1405 (F) signature. Never raises.

    Checkable here: that it says it was made over THIS receipt's body digest.
    Not checkable here: the signature value. Format arcaeon-receipt/0.1 carries
    no public key and names no scheme (`algorithm` is free text, default
    "unspecified"), and does not fix which bytes were signed beyond
    "body_digest". So the value's verdict is COULD NOT LOOK, never a pass and
    never silence."""
    sig = receipt.get("attestation_signature")
    if sig is None:
        return {"verdict": ATTACH_ABSENT}
    if not isinstance(sig, dict):
        return {"verdict": ATTACH_MISMATCH, "problems": ["attestation_signature is not an object"]}
    problems = []
    if sig.get("signed_over", "body_digest") != "body_digest":
        problems.append(f"signed_over is {sig.get('signed_over')!r}, not 'body_digest'")
    if sig.get("body_digest") != body_digest:
        problems.append("the signature says it was made over a different body digest "
                        f"({sig.get('body_digest')!r}) than this receipt carries")
    if problems:
        return {"verdict": ATTACH_MISMATCH, "problems": problems}
    return {"verdict": ATTACH_COULD_NOT_LOOK,
            "algorithm_claimed": sig.get("algorithm"),
            "note": ("the signature value was NOT checked: the receipt format carries no public "
                     "key and names no signature scheme this verifier can run. Check it against "
                     "the auditor's published key out of band.")}


def _claimed_fields(receipt: dict, res: dict, ots: bool) -> list:
    """Every issuer statement this run SHOWS but did not check."""
    out = ["issuer (format 0.1 carries no issuer signature; see FORMAT_CHANGE_PROPOSAL.md)"]
    if res["ledger"].get("status") == "not_checked" and receipt.get("ledger") is not None:
        out.append("ledger (rows/chain; no ledger file was given to this run)")
    if res["witness"].get("verdict") == ATTACH_CLAIMED:
        out.append("witness.kind / independence / url / status")
    anc = receipt.get("anchor")
    if not ots and isinstance(anc, dict) and anc.get("status") not in (None, "skipped"):
        out.append("anchor.status (the OpenTimestamps proof was not run)")
    if res["attestation_signature"].get("verdict") == ATTACH_COULD_NOT_LOOK:
        out.append("attestation_signature.value (could not look: no key in the format)")
    return out


# --------------------------------------------------------------------------
# build / verify / exhibit
# --------------------------------------------------------------------------

def build_receipt(kind: str, subject: dict, checks: list, scope: dict, *,
                  ledger_path: str | Path, namespace: str,
                  extra: Optional[dict] = None, witness: bool = True,
                  anchor: bool = True, issued_at: Optional[str] = None) -> dict:
    """Build a receipt: body -> digest -> ledger row -> witness pin -> OTS.

    scope MUST carry both "proves" and "does_not_prove" as non-empty lists;
    a receipt without a stated limit is refused. That is the one rule the
    core enforces on every adapter, because it is the one a buyer under a
    court order or an auditor will be judged on.

    checks[]["adherence"], when present, is validated against
    ADHERENCE_VALUES -- see the "AB 1405 report-element carriers" section
    below for what that field is and who is allowed to fill it in.
    """
    if not isinstance(scope, dict) or not scope.get("proves") or not scope.get("does_not_prove"):
        raise ValueError("scope must state both 'proves' and 'does_not_prove' (non-empty lists)")
    for c in checks:
        adherence = c.get("adherence") if isinstance(c, dict) else None
        if adherence is not None and adherence not in ADHERENCE_VALUES:
            raise ValueError(f"checks[].adherence must be one of {ADHERENCE_VALUES}, got {adherence!r}")
    body = {"receipt_version": RECEIPT_VERSION, "kind": kind,
            "issued_at": issued_at or _now_iso(), "subject": subject,
            "checks": checks, "scope": scope, "extra": extra or {}}
    body_digest = digest_json(body)
    ledger_path = Path(ledger_path)
    ledger = Ledger(ledger_path)
    row = {"evt": "receipt", "kind": kind, "namespace": namespace,
           "body_digest": body_digest, "checks": len(checks)}
    chain = ledger.append(row)
    head = ledger.head()
    receipt = dict(body)
    receipt["body_digest"] = body_digest
    receipt["ledger"] = {"path": ledger_path.name, "namespace": namespace,
                         "rows": head.rows, "chain": chain,
                         "algorithm": "truncated_sha256_128 hash chain (arcaeon-ledger)"}
    receipt["witness"] = _witness_pin(ledger, ledger_path, namespace) if witness else {"status": "skipped"}
    receipt["anchor"] = _ots_stamp(body_digest) if anchor else {"status": "skipped"}
    return receipt


def verify_receipt(receipt: Any, *, ledger_path: Optional[str | Path] = None,
                   ots: bool = False, source_text: Optional[str] = None) -> dict:
    """Recompute what can be recomputed. Typed, never raises.

    source_text, when given, is the file the receipt was parsed from. It is
    re-read with duplicate keys refused: a file that carries a key twice means
    one thing to a last-wins parser and another to a first-wins one, so it can
    never be ok, whatever the last-wins parse recomputes to."""
    res: dict = {"ok": False, "body_digest_ok": False, "ledger": {"status": "not_checked"},
                 "anchor": {"status": "not_checked"},
                 "witness": {"verdict": "not_checked"},
                 "attestation_signature": {"verdict": "not_checked"},
                 "issuer": {"verdict": ATTACH_CLAIMED,
                            "note": ("format arcaeon-receipt/0.1 carries no issuer signature: "
                                     "body_digest_ok says the body matches the digest printed "
                                     "on it, and anyone can recompute both. Only the ledger "
                                     "check ties a receipt to the issuer's own sequence.")},
                 "claimed": [], "notes": []}
    if not isinstance(receipt, dict):
        res["notes"].append("receipt must be a JSON object")
        return res
    dup = None
    if source_text is not None:
        try:
            loads_strict(source_text)
        except DuplicateKeyError as e:
            dup = str(e)
        except (ValueError, TypeError):
            pass  # unparseable text is the caller's verdict to give
    if dup:
        res["duplicate_keys"] = dup
        res["notes"].append(f"{dup}: the file is ambiguous between JSON parsers")
    try:
        expected = digest_json(_body_of(receipt))
    except (TypeError, ValueError) as e:
        res["notes"].append(f"body not canonicalizable: {e}")
        return res
    claimed = receipt.get("body_digest")
    res["body_digest_ok"] = (claimed == expected)
    if not res["body_digest_ok"]:
        res["notes"].append("body digest mismatch: a body field was altered after issue")
    led = receipt.get("ledger") or {}
    if ledger_path is not None:
        vr = verify_file(ledger_path)
        rows, chain = led.get("rows"), led.get("chain")
        at = chain_at(ledger_path, rows) if isinstance(rows, int) else None
        found = any(isinstance(r, dict) and r.get("body_digest") == claimed
                    and r.get("chain") == chain for r in Ledger(ledger_path))
        status = ("consistent" if (vr.ok and at == chain and found)
                  else "chain_broken" if not vr.ok
                  else "row_not_found" if not found
                  else "head_mismatch")
        res["ledger"] = {"status": status, "chain_ok": bool(vr.ok),
                         "first_break": vr.first_break, "row_present": found,
                         "chain_at_rows": at}
    if ots:
        res["anchor"] = ots_verify(receipt)
    # FAIL CLOSED ON THE ANCHOR. When the caller asked for the anchor to be
    # checked (ots=True), only a positive, recognised verification counts:
    # a stripped anchor block, a missing tool, a tool error, pending, or
    # output we do not recognise all mean "the anchor was not proven", and
    # that must never read as ok. Without ots, the anchor is not_checked and
    # does not enter the verdict, as before.
    anchor_status = res["anchor"].get("status")
    anchor_ok = (anchor_status in ANCHOR_POSITIVE) if ots else (anchor_status != "failed")
    if ots and not anchor_ok:
        res["notes"].append(f"anchor was asked for and not proven (status {anchor_status})")
    # Attachments outside the digest: never shown as checked when they were
    # not, and a determined contradiction fails.
    res["witness"] = _check_witness(receipt, res["ledger"]["status"])
    res["attestation_signature"] = _check_attestation_signature(receipt, claimed)
    res["claimed"] = _claimed_fields(receipt, res, ots)
    witness_ok = res["witness"]["verdict"] != ATTACH_INCONSISTENT
    if not witness_ok:
        res["notes"].append("witness block is inconsistent: " + "; ".join(res["witness"]["problems"]))
    sig_ok = res["attestation_signature"]["verdict"] != ATTACH_MISMATCH
    if not sig_ok:
        res["notes"].append("attestation signature does not belong to this receipt: "
                            + "; ".join(res["attestation_signature"]["problems"]))
    res["ok"] = res["body_digest_ok"] and res["ledger"]["status"] in ("not_checked", "consistent") \
        and anchor_ok and not dup and witness_ok and sig_ok
    return res


# The strict reader (duplicate keys refused at any depth, deep nesting a
# ValueError) is the row format's: one copy, in arcaeon.record.row. Every
# receipt the verifier reads goes through it.
from arcaeon.record.row import DuplicateKeyError, _reject_duplicate_keys  # noqa: E402,F401
from arcaeon.record.row import loads_strict  # noqa: E402


def load_receipt(path: str | Path) -> dict:
    return loads_strict(Path(path).read_text(encoding="utf-8"))


def save_receipt(receipt: dict, path: str | Path) -> Path:
    p = Path(path)
    p.write_text(json.dumps(receipt, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return p


def render_exhibit(receipt: dict, *, title: Optional[str] = None,
                   check_line: Optional[Callable[[dict], str]] = None) -> str:
    """Plain-text exhibit. The scope block is printed BEFORE the results so
    the first thing a reader meets is what this document is not."""
    kind = receipt.get("kind", "receipt")
    scope = receipt.get("scope") or {}
    lines = [f"{title or kind.upper().replace('-', ' ')}  (arcaeon-receipt)",
             f"Issued (UTC): {receipt.get('issued_at')}", ""]
    lines.append("WHAT THIS RECEIPT PROVES")
    lines += [f"  - {s}" for s in scope.get("proves", [])]
    lines.append("WHAT THIS RECEIPT DOES NOT PROVE")
    lines += [f"  - {s}" for s in scope.get("does_not_prove", [])]
    if scope.get("method"):
        lines += ["", f"Method: {scope['method']}"]
    subj = receipt.get("subject") or {}
    if subj:
        lines += ["", "SUBJECT"]
        for k, v in subj.items():
            lines.append(f"  {k}: {v}")
    checks = receipt.get("checks") or []
    lines += ["", f"RESULTS ({len(checks)} check{'s' if len(checks) != 1 else ''})"]
    for c in checks:
        lines.append("  " + (check_line(c) if check_line else json.dumps(c, ensure_ascii=False)))
    extra = receipt.get("extra") or {}
    att = extra.get("attestation") if isinstance(extra, dict) else None
    remediated = [c for c in checks if isinstance(c, dict) and c.get("remediation")]
    adhered = [c for c in checks if isinstance(c, dict) and c.get("adherence")]
    ab1405 = bool((isinstance(extra, dict) and extra.get("engagement_scope")) or remediated
                  or adhered or att or receipt.get("attestation_signature"))
    if ab1405:
        lines += ["", "AB 1405 REPORT ELEMENTS (auditor-supplied; not asserted by this tool)"]
        if isinstance(extra, dict) and extra.get("engagement_scope"):
            lines.append(f"  (A) engagement scope: {extra['engagement_scope']}")
        for c in remediated:
            lines.append(f"  (C) remediation: {c.get('remediation')}")
        for c in adhered:
            lines.append(f"  (D) internal-standards adherence: {c.get('adherence')}")
        if isinstance(att, dict) and att:
            lines.append(f"  (F) attestation: \"{att.get('statement')}\" "
                         f"-- {att.get('auditor_name')}, {att.get('signed_at')}"
                         + (f" (registry id {att['auditor_registry_id']})"
                            if att.get("auditor_registry_id") else ""))
            sig = receipt.get("attestation_signature")
            lines.append("  (F) signature: " + ("attached (detached, outside the digested body) -- "
                         "CLAIMED, NOT VERIFIED: the receipt carries no public key to check it with"
                         if sig else "NOT attached -- statement above is unsigned"))
    led, wit, anc = receipt.get("ledger") or {}, receipt.get("witness") or {}, receipt.get("anchor") or {}
    lines += ["", "INTEGRITY",
              f"  body digest: {receipt.get('body_digest')}",
              "  (the three lines below are the issuer's statements, outside the body",
              "   digest; they are CLAIMED until checked as described at the end)",
              f"  ledger (claimed): namespace={led.get('namespace')} rows={led.get('rows')} chain={led.get('chain')}",
              f"  witness (claimed, not verified): {wit.get('kind')} ({wit.get('independence', wit.get('status'))})",
              f"  anchor (claimed): {anc.get('kind', 'none')} status={anc.get('status')}",
              "", "To verify: recompute the body digest from the JSON receipt's body fields "
              "(canonical JSON, sha256), compare to body_digest; if an OpenTimestamps proof is "
              "attached, write the body_digest plus a newline to a file, save the proof beside it, "
              "and run `ots verify`. No contact with the issuer is required."]
    return "\n".join(lines) + "\n"
