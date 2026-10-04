# SPDX-License-Identifier: MIT
"""arcaeon.prove.gate: the rule as code (TE-21). Verify before act, decided.

    from arcaeon.prove import gate
    d = gate.decide("grades.csv", action="pay", audience="instructor-1",
                    signers=["did:key:z6Mk..."], deal="d-7f3a", record_dir="deals")
    d.decision        # "allow" or "refuse"
    d.reason          # one plain sentence or three
    d.evidence        # the evidence pack's directory, on BROKEN with a deal id

THE RULE. The envelope's verify (arcaeon.prove.envelope.verify, the one and
only verifier; this module never checks a byte itself) answers one of three
words. The gate turns that word and the action the receiver is about to take
into allow or refuse:

    verdict          read    act     pay     irreversible
    VERIFIED         allow   allow   allow   allow
    BROKEN           refuse  refuse  refuse  refuse
    COULD NOT LOOK   allow   refuse  refuse  refuse

Allow means: the bytes are unchanged since the key you named sealed them, and
they were labeled for you, for this deal when you gave one, and are in date.
It never means the content is true or safe (docs/ENVELOPE.md, "What VERIFIED
does not prove"). COULD NOT LOOK allows `read` because reading changes
nothing; every refusal on it names what could not be checked.

THE EVIDENCE PACK. On BROKEN with a deal id, the gate copies the handed file
and its envelope into the deal's record and writes evidence.json beside them:

    <record_dir>/DEAL-<deal>/gate/<UTC stamp>-<sha256[:12]>/
        bundle/<file name>              the handed file's bytes
        bundle/<file name>.envelope.json the sidecar's bytes (when there is one)
        evidence.json                   kind, deal, action, decision, verdict,
                                        reason, reasons, at (UTC), file and
                                        envelope {path, copy, sha256, bytes},
                                        audience, signers, the verify report

`DEAL-<deal>` is the directory `arcaeon deal pack` writes by default, so the
gate's packs sit beside the deal's own pack. The sha256 is of the bytes as
copied (hashed while copying). Without a deal id no pack is written.

THE DISPUTE PACKET. `arcaeon gate packet` (arcaeon.prove.dispute_packet)
renders a refusal, from an evidence pack or from a decision's to_dict(), as
one page in markdown and JSON for a marketplace's dispute process.

A NON-PARTY CHECK ABOVE A CAP (TE-35). A receiver may add one rule on top of
the table: `require_nonparty_check_above=CAP`. When the deal's amount is over
CAP, a VERIFIED envelope allows act, pay and irreversible only if at least one
check (a check.verdict.relayed row, TE-31) counts. A check counts when:

    (a) its own envelope sidecar (CHECK.envelope.json) verifies, through the
        same envelope.verify, under a key that is neither a key that signed
        the handed envelope (or that the receiver named for it) nor the
        audience: a non-party (and, with `checkers`, one of those keys);
    (b) a row in it names the handed file's sha256 as its subject.sha256;
    (c) that row's relayed_verdict is VERIFIED.

An unsigned row is the sender's report and never counts, whatever its
`attestation` claims. A counting key's row on the same sha256 that says
BROKEN vetoes. No amount (neither `amount` nor the deal record carries one)
refuses those three actions as could-not-look. `read` and every case at or
under the cap are the table above, unchanged. The amount is the LARGER of
`amount` and every commit total / pay amount in the deal record
(record_dir/DEAL-<deal>/{buyer,seller}.deal.jsonl), so neither source can
lower it below the other. Limit: this raises the cost of collusion between
the two parties; it does not prove the checker is independent of them.

Stdlib only (verify loads the [sign] backend itself). `decide` raises only on
an unknown action or an unreadable cap; anything else is an answer.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from arcaeon import verdict as V
from arcaeon.prove import envelope as E
from arcaeon.record.row import file_pin, loads_strict

__all__ = ["ACTIONS", "ALLOW", "REFUSE", "RULES", "GateDecision", "decide", "resolve",
           "EVIDENCE_KIND", "GUARDED", "CHECK_KIND", "NONPARTY_RULE", "main"]

ACTIONS = ("read", "act", "pay", "irreversible")
ALLOW, REFUSE = "allow", "refuse"
#: verdict -> the actions it allows. Anything not listed is refused.
RULES = {V.VERIFIED: frozenset(ACTIONS), V.BROKEN: frozenset(),
         V.COULD_NOT_LOOK: frozenset({"read"})}
EVIDENCE_KIND = "arcaeon.gate.evidence/v1"

ALLOW_MEANS = ("allow means the bytes are unchanged since the key you named sealed them "
               "and they are labeled for you and in date; it does not say the content is "
               "true or safe")
LIMITS = [
    ALLOW_MEANS,
    "the gate decides from the envelope's verdict alone; checking the content is other "
    "tools' job",
    "a third party who can edit the sidecar can turn allow into refuse, never into allow",
    "the evidence pack's copy is taken after the check; its sha256 is of the bytes copied",
]

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")

#: the actions the non-party check rule guards; `read` is never among them.
GUARDED = frozenset({"act", "pay", "irreversible"})
#: the only row kind a check file is read for (arcaeon.connector, TE-31).
CHECK_KIND = "check.verdict.relayed"
NONPARTY_RULE = "require_nonparty_check_above"
NONPARTY_LIMIT = ("the non-party check rule raises the cost of collusion between the two "
                  "parties; it does not prove the checker is independent of them (a party "
                  "can make a new key, or pay a checker)")
#: a check file bigger than this is not read: a few rows are a few KiB.
MAX_CHECK_BYTES = 1 << 20
_MAX_ROWS = 1000


@dataclass
class GateDecision:
    """One gate answer. `decision` is "allow" or "refuse"; `verdict` is the
    verify word it came from; `reasons` are verify's findings (BROKEN) or its
    could-not-look reasons; `could_not_check` names what was not checked
    (looked_for, where, reason_word) on COULD NOT LOOK; `evidence` is the pack
    directory when one was written; `report` is verify's full report."""
    decision: str
    action: str
    verdict: str
    reason: str
    reasons: list = field(default_factory=list)
    could_not_check: dict | None = None
    file: str = ""
    envelope: str = ""
    audience: str | None = None
    deal: str | None = None
    purpose: str | None = None
    signers: list = field(default_factory=list)
    at: str | None = None
    evidence: str | None = None
    evidence_error: str | None = None
    report: dict = field(default_factory=dict)
    limits: list = field(default_factory=lambda: list(LIMITS))
    nonparty_check: dict | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW

    def __bool__(self) -> bool:
        return self.allowed

    @property
    def exit_code(self) -> int:
        """0 allow; 1 refuse on BROKEN; 3 refuse on COULD NOT LOOK."""
        if self.allowed:
            return V.EXIT_GOOD
        return V.EXIT_BAD if self.verdict == V.BROKEN else V.EXIT_COULD_NOT_LOOK

    def to_dict(self) -> dict:
        out = {"decision": self.decision, "action": self.action, "verdict": self.verdict,
               "reason": self.reason, "reasons": list(self.reasons),
               "could_not_check": dict(self.could_not_check) if self.could_not_check else None,
               "file": self.file, "envelope": self.envelope, "audience": self.audience,
               "deal": self.deal, "purpose": self.purpose, "signers": list(self.signers),
               "at": self.at, "evidence": self.evidence,
               "evidence_error": self.evidence_error, "exit_code": self.exit_code,
               "limits": list(self.limits), "report": self.report}
        if self.nonparty_check is not None:          # only when the rule was set
            out["nonparty_check"] = self.nonparty_check
        return out


def resolve(path: str | Path, file: str | Path | None = None) -> tuple[Path, Path]:
    """(handed file, sidecar) from what `--envelope` named. A path ending in
    `.envelope.json` is the sidecar and the handed file is the same path
    without the suffix (or `file`). Any other path, with `file` given, is a
    sidecar under another name; without `file` it is the handed file, with its
    sidecar beside it."""
    p = Path(path)
    if file is not None:
        return Path(file), p
    if p.name.endswith(E.SUFFIX) and len(p.name) > len(E.SUFFIX):
        return p.with_name(p.name[:-len(E.SUFFIX)]), p
    return p, E.envelope_path(p)


def _utc(now: datetime) -> str:
    return now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _deal_dir_name(deal: str) -> str:
    if _SAFE_ID.fullmatch(deal) and ".." not in deal:
        return f"DEAL-{deal}"
    return "DEAL-sha256-" + hashlib.sha256(deal.encode("utf-8")).hexdigest()[:16]


def _copy(src: Path, dst: Path) -> dict:
    """Copy src to dst, hashing the bytes as they are written."""
    h, n = hashlib.sha256(), 0
    with open(src, "rb") as fi, open(dst, "xb") as fo:
        for chunk in iter(lambda: fi.read(1 << 20), b""):
            h.update(chunk)
            fo.write(chunk)
            n += len(chunk)
    return {"sha256": h.hexdigest(), "bytes": n}


def _write_evidence(d: GateDecision, file: Path, env_path: Path, signers: list,
                    record_dir: Path, now: datetime) -> Path:
    base = record_dir / _deal_dir_name(d.deal) / "gate"
    seed = hashlib.sha256(f"{file}\0{env_path}".encode("utf-8", "replace"))
    try:
        with open(file, "rb") as fi:
            seed = hashlib.sha256()
            for chunk in iter(lambda: fi.read(1 << 20), b""):
                seed.update(chunk)
    except OSError:
        pass
    seed = seed.hexdigest()
    stem = now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + seed[:12]
    base.mkdir(parents=True, exist_ok=True)
    out, k = base / stem, 1
    while True:
        try:
            out.mkdir()
            break
        except FileExistsError:
            k += 1
            out = base / f"{stem}-{k}"
    (out / "bundle").mkdir()
    parts = {}
    for key, src in (("file", file), ("envelope", env_path)):
        entry: dict[str, Any] = {"path": str(src), "copy": None, "sha256": None, "bytes": None}
        if src.is_file():
            try:
                entry.update(_copy(src, out / "bundle" / src.name))
                entry["copy"] = f"bundle/{src.name}"
            except OSError as e:
                entry["error"] = f"could not copy ({type(e).__name__})"
        else:
            entry["error"] = "not there to copy"
        parts[key] = entry
    ev = {"kind": EVIDENCE_KIND, "deal": d.deal, "action": d.action, "decision": d.decision,
          "verdict": d.verdict, "reason": d.reason, "reasons": list(d.reasons),
          "at": _utc(now), "file": parts["file"], "envelope": parts["envelope"],
          "audience": d.audience, "purpose": d.purpose, "signers": list(signers), "limits": list(d.limits),
          "report": d.report}
    (out / "evidence.json").write_text(json.dumps(ev, indent=1, ensure_ascii=False) + "\n",
                                       encoding="utf-8")
    return out


def _reason(action: str, verdict: str, r: dict, audience, deal) -> str:
    allowed = action in RULES.get(verdict, frozenset())
    head = f"{ALLOW if allowed else REFUSE} {action}: {verdict}"
    if verdict == V.VERIFIED:
        bound = f"labeled for {audience!r}" + (f" in deal {deal!r}" if deal else "")
        return (f"{head}. The bytes are unchanged since the key you named sealed them, "
                f"{bound}, and in date. This does not say the content is true or safe.")
    if verdict == V.BROKEN:
        return (f"{head}: {r.get('reason')}. Do not act on it; keep the file and the "
                f"envelope as evidence.")
    what = f"{r.get('looked_for') or 'a step'} ({r.get('reason_word') or 'unreadable'})"
    if allowed:
        return (f"{head}: could not check {what}. Reading is allowed; nothing here vouches "
                f"for the bytes. {r.get('reason')}")
    return (f"{head}: could not check {what}: {r.get('reason')}. Only read is allowed "
            f"until that can be checked.")


# --- the non-party check rule (TE-35) ---------------------------------------------

def _decimal(v: Any) -> Decimal | None:
    """A finite, non-negative amount, or None."""
    if isinstance(v, bool) or not isinstance(v, (str, int, Decimal)):
        return None
    try:
        d = Decimal(str(v).strip())
    except (InvalidOperation, ValueError):
        return None
    return d if d.is_finite() and d >= 0 else None


def _deal_amounts(record_dir: Path, deal: str) -> tuple[list, str, list]:
    """Every readable commit total and pay amount for `deal` in its record
    (DEAL-<deal>/{buyer,seller}.deal.jsonl). Returns (amounts, where, notes)."""
    base = record_dir / _deal_dir_name(deal)
    amounts, notes = [], []
    for name in ("buyer.deal.jsonl", "seller.deal.jsonl"):
        p = base / name
        try:
            if not p.is_file():
                continue
            if p.stat().st_size > 16 * MAX_CHECK_BYTES:
                notes.append(f"{name}: over {16 * MAX_CHECK_BYTES} bytes, not read")
                continue
            lines = p.read_bytes().decode("utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as e:
            notes.append(f"{name}: not read ({type(e).__name__})")
            continue
        for n, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                row = loads_strict(line)
            except ValueError:
                notes.append(f"{name} line {n}: not one JSON object, skipped")
                continue
            if not isinstance(row, dict) or row.get("deal", deal) != deal:
                continue
            shared = row.get("shared") if isinstance(row.get("shared"), dict) else {}
            if row.get("kind") == "deal.commit" and isinstance(shared.get("terms"), dict):
                a = _decimal(shared["terms"].get("total"))
            elif row.get("kind") == "deal.pay":
                a = _decimal(shared.get("amount"))
            else:
                continue
            if a is not None:
                amounts.append(a)
    return amounts, str(base), notes


def _read_check_rows(path: Path) -> tuple[list | None, str]:
    """The rows in a check file (one JSON object, a JSON list, or JSON lines),
    or (None, why). Never raises on content."""
    try:
        if not path.is_file():
            return None, "not there" if not path.exists() else "not a regular file"
        if path.stat().st_size > MAX_CHECK_BYTES:
            return None, f"over {MAX_CHECK_BYTES} bytes, not read"
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return None, f"cannot be read as UTF-8 text ({type(e).__name__})"
    try:
        doc = loads_strict(text)
        rows = doc if isinstance(doc, list) else [doc]
    except ValueError:
        try:
            rows = [loads_strict(ln) for ln in text.splitlines() if ln.strip()]
        except ValueError as e:
            return None, f"not JSON or JSON lines ({str(e)[:80]})"
    if not rows or len(rows) > _MAX_ROWS or not all(isinstance(x, dict) for x in rows):
        return None, "not a list of check rows (JSON objects)"
    return rows, ""


def _judge_check(path: Path, *, sha: str, parties: set, checkers: list, audience, deal,
                 now: datetime) -> dict:
    """Does one check file count toward the rule? Never raises."""
    out: dict[str, Any] = {"check": path.name, "counts": False, "vetoes": False,
                           "signed_by": [], "nonparty": [], "row_verdict": None, "why": ""}
    try:
        rows, why = _read_check_rows(path)
        if rows is None:
            out["why"] = f"unreadable: {why}"
            return out
        side = E.envelope_path(path)
        if not side.exists():
            out["why"] = (f"unsigned (no {side.name}): a row nobody signed is reported by the "
                          f"sender, never a check")
            return out
        first = E.verify(path, side, audience=audience, deal=deal, signers=(), now=now)
        valid = [k for k in (first.get("signers") or []) if isinstance(k, str)]
        out["signed_by"] = valid
        if first.get("verdict") == V.BROKEN:
            out["why"] = f"its envelope is BROKEN: {first.get('reason')}"
            return out
        if not valid:
            out["why"] = f"its envelope does not verify under any key: {first.get('reason')}"
            return out
        nonparty = [k for k in valid if k not in parties]
        if checkers:
            nonparty = [k for k in nonparty if k in checkers]
        out["nonparty"] = nonparty
        if not nonparty:
            out["why"] = ("signed only by a party (the envelope's signer or the audience)"
                          if not checkers or not [k for k in valid if k not in parties]
                          else "signed by no key you named with --checker")
            return out
        second = E.verify(path, side, audience=audience, deal=deal, signers=nonparty, now=now)
        if second.get("verdict") != V.VERIFIED:
            out["why"] = f"its envelope reads {second.get('verdict')}: {second.get('reason')}"
            return out
        mine = [x for x in rows if x.get("kind") == CHECK_KIND
                and isinstance(x.get("subject"), dict)
                and isinstance(x["subject"].get("sha256"), str)
                and x["subject"]["sha256"].lower() == sha]
        if not mine:
            out["why"] = f"signed by a non-party, but no {CHECK_KIND} row names sha256 {sha}"
            return out
        words = [x.get("relayed_verdict") for x in mine]
        if V.BROKEN in words:
            out.update(row_verdict=V.BROKEN, vetoes=True,
                       why="a non-party signed a check that says BROKEN for these bytes")
        elif V.VERIFIED in words:
            out.update(row_verdict=V.VERIFIED, counts=True,
                       why=f"signed by non-party {nonparty[0]}, names this sha256, says VERIFIED")
        else:
            out["row_verdict"] = str(words[0])[:64]
            out["why"] = f"signed by a non-party, but it says {out['row_verdict']}, not VERIFIED"
        return out
    except Exception as e:  # noqa: BLE001  a hostile check is an answer, never a traceback
        out.update(counts=False, vetoes=False,
                   why=f"unreadable: the check could not finish ({type(e).__name__})")
        return out


def _nonparty_rule(*, cap: Decimal, amount, checks, checkers, file: Path, r: dict,
                   signers: list, audience, deal, record_dir: Path, now: datetime) -> dict:
    """The rule's answer: {applies, satisfied, amount, ...}; `satisfied` None means
    the amount could not be found (could not look)."""
    given = _decimal(amount) if amount is not None else None
    sources = []
    if given is not None:
        sources.append(("--amount", given))
    info: dict[str, Any] = {"rule": NONPARTY_RULE, "cap": str(cap), "amount": None,
                            "amount_source": None, "amount_notes": [], "applies": None,
                            "satisfied": None, "checks": [], "limit": NONPARTY_LIMIT}
    if amount is not None and given is None:
        info["amount_notes"].append(f"--amount {str(amount)[:40]!r} is not a readable amount")
    where = None
    if deal is not None:
        found, where, notes = _deal_amounts(record_dir, deal)
        info["amount_notes"].extend(notes)
        if found:
            sources.append(("deal record", max(found)))
    if not sources:
        info["could_not_check"] = V.could_not_look(
            "the deal's amount (--amount, or a commit total or pay amount in the deal record)",
            where or "--amount", "missing",
            "no amount was given and no deal record carries one, so whether the cap applies "
            "cannot be checked")
        return info
    src, amt = max(sources, key=lambda s: s[1])
    info["amount"], info["amount_source"] = str(amt), src
    info["applies"] = amt > cap
    if not info["applies"]:
        return info
    sha = (file_pin(file).get("sha256") or "").lower()
    parties = {k for k in list(signers) + list(r.get("signers") or []) if isinstance(k, str)}
    sealed = r.get("sealed") if isinstance(r.get("sealed"), dict) else {}
    by = sealed.get("sealed_by") if isinstance(sealed.get("sealed_by"), dict) else {}
    if isinstance(by.get("key"), str):
        parties.add(by["key"])
    if isinstance(audience, str):
        parties.add(audience)
    judged = [_judge_check(Path(c), sha=sha, parties=parties, checkers=list(checkers or ()),
                           audience=audience, deal=deal, now=now) for c in (checks or ())]
    info["checks"] = judged
    info["satisfied"] = (bool(sha) and any(j["counts"] for j in judged)
                         and not any(j["vetoes"] for j in judged))
    return info


def _nonparty_reason(action: str, verdict: str, info: dict, base: str) -> str:
    cap = info["cap"]
    if info["applies"] is None:
        c = info["could_not_check"]
        return (f"refuse {action}: {verdict}, but the non-party check rule (over {cap}) could "
                f"not look: could not check {c['looked_for']} ({c['reason_word']}): "
                f"{c['reason']}. Only read is allowed until it can be checked.")
    amt = f"amount {info['amount']} (from {info['amount_source']})"
    if info["satisfied"]:
        ok = next(j for j in info["checks"] if j["counts"])
        return (f"{base} The {amt} is over the cap {cap}, and {ok['check']} is a check "
                f"{ok['why']}.")
    why = "; ".join(f"{j['check']}: {j['why']}" for j in info["checks"]) or "no --check was given"
    return (f"refuse {action}: {verdict}, but the non-party check rule refuses it: the {amt} "
            f"is over the cap {cap} and no check counts ({why}). A check counts only when "
            f"a key that is neither the envelope's signer nor the audience signed it, it "
            f"names this file's sha256 and it says VERIFIED; a row nobody signed is the "
            f"sender's report. Only read is allowed until one does.")


def decide(file: str | Path, *, action: str, audience: str | None,
           signers=(), deal: str | None = None, envelope: str | Path | None = None,
           purpose: str | None = None, record_dir: str | Path | None = None,
           now: datetime | None = None, require_nonparty_check_above=None,
           amount=None, checks=(), checkers=()) -> GateDecision:
    """allow or refuse `action` on `file`, from `envelope.verify`'s verdict.

    `file` is the handed file; `envelope` its sidecar (default: beside it).
    `audience`, `signers`, `deal` and `purpose` go to verify unchanged (a
    wrong one is BROKEN there). On BROKEN with a `deal`, an evidence pack is
    written under `record_dir` (default: the current directory).

    `require_nonparty_check_above` (an amount) adds the non-party check rule
    (module docstring): over it, a VERIFIED envelope allows act, pay and
    irreversible only with a counting check among `checks` (paths); `amount`
    is the deal's amount (the larger of it and the deal record's is used);
    `checkers` optionally narrows which non-party keys count. Unset, nothing
    changes. Raises ValueError on an unknown action or an unreadable cap;
    otherwise never raises."""
    if action not in ACTIONS:
        raise ValueError(f"action must be one of {ACTIONS}, got {action!r}")
    cap = None
    if require_nonparty_check_above is not None:
        cap = _decimal(require_nonparty_check_above)
        if cap is None:
            raise ValueError(f"require_nonparty_check_above must be a non-negative amount, "
                             f"got {require_nonparty_check_above!r}")
    now = now or datetime.now(timezone.utc)
    file = Path(file)
    env_path = Path(envelope) if envelope is not None else E.envelope_path(file)
    signers = list(signers or ())
    r = E.verify(file, env_path, audience=audience, deal=deal, purpose=purpose,
                 signers=signers, now=now)
    verdict = r.get("verdict")
    if verdict not in RULES:                     # never a green on an unknown word
        verdict = V.COULD_NOT_LOOK
    allowed = action in RULES[verdict]
    if verdict == V.BROKEN:
        reasons = list(r.get("findings") or [r.get("reason")])
    elif verdict == V.COULD_NOT_LOOK:
        reasons = [s for s in str(r.get("reason") or "").split("; ") if s]
    else:
        reasons = []
    cnc = ({k: r.get(k) for k in ("looked_for", "where", "reason_word")}
           if verdict == V.COULD_NOT_LOOK else None)
    reason = _reason(action, verdict, r, audience, deal)
    policy = None
    if cap is not None:
        policy = {"rule": NONPARTY_RULE, "cap": str(cap), "applies": False, "satisfied": None,
                  "checks": [], "limit": NONPARTY_LIMIT,
                  "note": "the table decides: read, or a verdict that already refuses"}
        if verdict == V.VERIFIED and action in GUARDED:
            try:
                policy = _nonparty_rule(
                    cap=cap, amount=amount, checks=checks, checkers=checkers, file=file, r=r,
                    signers=signers, audience=audience, deal=deal, now=now,
                    record_dir=Path(record_dir) if record_dir is not None else Path.cwd())
            except Exception as e:  # noqa: BLE001  never a green on a crash
                policy.update(applies=None, could_not_check=V.could_not_look(
                    "the non-party check rule's inputs", "gate", "unreadable",
                    f"the rule could not finish ({type(e).__name__})"))
            if policy["applies"] is None or (policy["applies"] and not policy["satisfied"]):
                allowed = False
                cnc = policy.get("could_not_check") or V.could_not_look(
                    "a signed non-party check that says VERIFIED for this sha256",
                    ", ".join(str(c) for c in checks) or "--check", "missing",
                    "no check given counts toward the non-party check rule")
                reasons = [j["check"] + ": " + j["why"] for j in policy["checks"]] or \
                    [cnc["reason"]]
            reason = _nonparty_reason(action, verdict, policy, reason) \
                if policy["applies"] is not False else reason
    d = GateDecision(decision=ALLOW if allowed else REFUSE, action=action, verdict=verdict,
                     reason=reason, reasons=reasons,
                     could_not_check=cnc, file=str(file), envelope=str(env_path),
                     audience=audience, deal=deal, purpose=purpose, signers=list(signers),
                     at=_utc(now), report=r, nonparty_check=policy)
    if verdict == V.BROKEN and deal is not None:
        try:
            out = _write_evidence(d, file, env_path, signers,
                                  Path(record_dir) if record_dir is not None else Path.cwd(), now)
            d.evidence = str(out)
            d.reason += f" Evidence pack written to {out}."
        except Exception as e:  # noqa: BLE001  the refusal stands either way
            d.evidence_error = f"evidence pack not written ({type(e).__name__}: {e})"
            d.reason += f" The evidence pack could not be written ({type(e).__name__})."
    elif verdict == V.BROKEN:
        d.reason += " No deal id was given, so no evidence pack was written."
    return d


# --- CLI ------------------------------------------------------------------------

USAGE = """usage: arcaeon gate decide --envelope PATH --audience ID --signer DID
                           --action {read,act,pay,irreversible} [--deal ID]
                           [--purpose TEXT] [--file PATH] [--record-dir DIR]
                           [--require-nonparty-check-above AMOUNT
                            [--amount N] [--check FILE ...] [--checker DID ...]]
                           [--json]
       arcaeon gate packet (--evidence DIR | --decision FILE.json)
                           [--out DIR] [--json]"""

HELP = USAGE + """

decide runs `envelope verify` and turns its word into allow or refuse for the
action you are about to take:

  VERIFIED        allows read, act, pay and irreversible
  BROKEN          refuses all four; with --deal, writes an evidence pack (the
                  file and envelope bytes, their sha256, the verdict, the
                  reasons, the UTC time) to DIR/DEAL-<deal>/gate/<stamp>/
  COULD NOT LOOK  allows read only; refuses act, pay and irreversible,
                  naming what could not be checked

--envelope names the sidecar (FILE.envelope.json; the handed file is FILE)
or the handed file itself (its sidecar beside it); with --file, --envelope is
the sidecar under any name and --file the handed file. --signer may be
repeated. --deal and --purpose are held against the envelope's binding.
--record-dir defaults to the current directory.

Allow means the bytes are unchanged since the key you named sealed them and
are labeled for you and in date. It does not say the content is true or safe.

--require-nonparty-check-above AMOUNT: when the deal's amount is over AMOUNT,
a VERIFIED envelope allows act, pay and irreversible only if one --check
FILE counts: a check.verdict.relayed row naming this file's sha256 and
saying VERIFIED, in a file whose own envelope (FILE.envelope.json, labeled
for you) verifies under a key that is neither the handed envelope's signer
nor the audience (with --checker, one of those keys). An unsigned row is the
sender's report and never counts; a counting key's BROKEN vetoes. The amount
is the larger of --amount and the deal record's commit total / pay amount
(DIR/DEAL-<deal>/); with neither, those actions are refused (exit 3). read,
and anything at or under AMOUNT, follow the table. This raises the cost of
collusion between the parties; it does not prove the checker independent.

Prints one line, `allow <action>: ...` or `refuse <action>: ...` (--json:
the whole decision).
Exit codes: 0 allow, 1 refuse (BROKEN), 3 refuse (COULD NOT LOOK, or no
counting non-party check), 2 bad usage. Spec and limits: docs/ENVELOPE.md.

packet renders a refusal as one page a dispute process can take: what was
handed (name, sha256, size), by whom, for whom, when, what failed, what was
not checked, the verdict and decision, and the envelope spec's "does not
prove" list word for word. --evidence is an evidence pack directory (BROKEN
with a deal id); --decision is the `decide --json` output (so a COULD NOT
LOOK refusal, which writes no pack, can be rendered too). File names only,
never the directories. Prints markdown (--json: the JSON form, kind
arcaeon.dispute.packet/v1); --out DIR writes dispute-packet.md and
dispute-packet.json there instead.
Exit codes: 0 written, 2 bad usage or nothing to dispute (the gate allowed
the action), 3 the input could not be read as a gate record."""

_SPEC = {"--envelope": "value", "--audience": "value", "--signer": "list",
         "--action": "value", "--deal": "value", "--purpose": "value", "--file": "value",
         "--record-dir": "value", "--json": "bool",
         "--require-nonparty-check-above": "value", "--amount": "value", "--check": "list",
         "--checker": "list"}


def _decide_cli(argv: list[str]) -> int:
    pos, o = E._parse(argv, _SPEC)
    if pos:
        raise E._Usage(f"unexpected argument {pos[0]!r}")
    for need in ("--envelope", "--audience", "--signer", "--action"):
        if not o.get(need):
            raise E._Usage(f"decide needs {need}")
    if o["--action"] not in ACTIONS:
        raise E._Usage(f"--action must be one of {', '.join(ACTIONS)}")
    cap = o.get("--require-nonparty-check-above")
    if cap is None:
        for dep in ("--amount", "--check", "--checker"):
            if o.get(dep):
                raise E._Usage(f"{dep} needs --require-nonparty-check-above AMOUNT")
    else:
        for flag in ("--require-nonparty-check-above", "--amount"):
            if o.get(flag) is not None and _decimal(o[flag]) is None:
                raise E._Usage(f"{flag} must be a non-negative amount, got {o[flag]!r}")
    file, env_path = resolve(o["--envelope"], o.get("--file"))
    d = decide(file, envelope=env_path, action=o["--action"], audience=o["--audience"],
               signers=o["--signer"], deal=o.get("--deal"), purpose=o.get("--purpose"),
               record_dir=o.get("--record-dir"), require_nonparty_check_above=cap,
               amount=o.get("--amount"), checks=o.get("--check", []),
               checkers=o.get("--checker", []))
    if o.get("--json"):
        print(json.dumps(d.to_dict(), indent=1, ensure_ascii=False))
    else:
        print(d.reason)
    return d.exit_code


_PACKET_SPEC = {"--evidence": "value", "--decision": "value", "--out": "value", "--json": "bool"}


def _packet_cli(argv: list[str]) -> int:
    from arcaeon.prove import dispute_packet as P
    pos, o = E._parse(argv, _PACKET_SPEC)
    if pos:
        raise E._Usage(f"unexpected argument {pos[0]!r}")
    if bool(o.get("--evidence")) == bool(o.get("--decision")):
        raise E._Usage("packet needs exactly one of --evidence DIR or --decision FILE.json")
    try:
        p = (P.from_evidence(o["--evidence"]) if o.get("--evidence")
             else P.from_decision_file(o["--decision"]))
    except P.NothingToDispute as e:
        print(f"arcaeon gate packet: {e}", file=sys.stderr)
        return V.EXIT_USAGE
    except P.PacketError as e:
        print(f"arcaeon gate packet: COULD NOT LOOK: {e}", file=sys.stderr)
        return V.EXIT_COULD_NOT_LOOK
    md, js = P.render_markdown(p), P.render_json(p)
    if o.get("--out"):
        out = Path(o["--out"])
        out.mkdir(parents=True, exist_ok=True)
        for name, text in (("dispute-packet.md", md), ("dispute-packet.json", js)):
            (out / name).write_text(text, encoding="utf-8", newline="\n")
            print(out / name)
    else:
        sys.stdout.write(js if o.get("--json") else md)
    return V.EXIT_GOOD


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help") or any(a in ("-h", "--help") for a in argv):
        print(HELP)
        return V.EXIT_GOOD if argv else V.EXIT_USAGE
    sub, rest = argv[0], argv[1:]
    try:
        if sub == "decide":
            return _decide_cli(rest)
        if sub == "packet":
            return _packet_cli(rest)
        raise E._Usage(f"unknown subcommand {sub!r} (decide, packet)")
    except E._Usage as e:
        print(f"arcaeon gate: {e}\n{USAGE}", file=sys.stderr)
        return V.EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
