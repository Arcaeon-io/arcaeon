# SPDX-License-Identifier: MIT
"""arcaeon.prove.gate: the rule as code (TE-21). Verify before act, decided.

    from arcaeon.prove import gate
    d = gate.decide("grades.csv", action="pay", audience="instructor-1",
                    signers=["did:key:z6Mk..."], deal="d-7f3a", purpose="grading",
                    record_dir="deals",
                    ledger="my-deal-tape.jsonl")
    d.decision        # "allow" or "refuse"
    d.reason          # one plain sentence or three
    d.evidence        # the evidence pack's directory, on a refusal with a deal id

THE RULE. The envelope's verify (arcaeon.prove.envelope.verify, the one and
only verifier; this module never checks a byte itself) answers one of three
words. The gate turns that word and the action the receiver is about to take
into allow or refuse:

    verdict          read    act     pay     irreversible
    VERIFIED         allow   allow   allow   allow
    BROKEN           refuse  refuse  refuse  refuse
    COULD NOT LOOK   allow   refuse  refuse  refuse

act, pay and irreversible need the exchange named: without `deal` (or without
`purpose`) the verdict is COULD NOT LOOK before the table is read, with the
reason "pass --deal so the envelope is held to this exchange" (or "pass
--purpose ...", and "pass --deal and --purpose ..." when both are missing, or
for act when either is), one sentence naming every missing one, so an envelope
sealed for one deal cannot be replayed into an act or a pay that names none. A
BROKEN verdict stays BROKEN. read is the only action an unbound check allows.

Allow means: the bytes are unchanged since the key you named sealed them, and
they were labeled for you, for this deal when you gave one, and are in date.
It never means the content is true or safe (docs/ENVELOPE.md, "What VERIFIED
does not prove"). COULD NOT LOOK allows `read` because reading changes
nothing; every refusal on it names what could not be checked.

THE EVIDENCE PACK. On a refusal with a deal id (BROKEN, or COULD NOT LOOK on
act, pay or irreversible: a refusal is evidence, D066), the gate copies the
handed file and its envelope into the deal's record and writes evidence.json
(LF line endings) beside them:

    <record_dir>/DEAL-<deal>/gate/<UTC stamp>-<sha256[:12]>/
        bundle/<file name>              the handed file's bytes
        bundle/<file name>.envelope.json the sidecar's bytes (when there is one)
        evidence.json                   kind, deal, action, decision, verdict,
                                        reason, reasons, could_not_check,
                                        at (UTC), file and
                                        envelope {path, copy, sha256, bytes},
                                        audience, signers, the verify report

`DEAL-<deal>` is the directory `arcaeon deal pack` writes by default, so the
gate's packs sit beside the deal's own pack. The sha256 is of the bytes as
copied (hashed while copying). Without a deal id no pack is written.

THE CHAIN ROW (D056). Once the pack is written, one row is appended to a
hash-chained ledger through `arcaeon.record.ledger.Ledger.append`, the same
writer the deal lane's rows go through (no second chain format):

    {"kind": "gate.evidence", "deal", "file_sha256", "verdict", "reason",
     "pack", "pack_digest", "pack_digest_of", "at"}   (+ "ts", "chain")

`verdict` is the envelope's word: BROKEN or COULD NOT LOOK, or VERIFIED on a
refusal by a rule on top of it, whose row adds `"veto"`: checker-broken or
checks-unreadable (D067), or nonparty-check (the non-party rule). The ledger is
`ledger=` (`--ledger`), the receiver's own deal chain, and it is required
whenever a deal id is given (D066): a row written next to the pack could be
rewritten along with it. `deal dispute` reads only `deal.*` rows, so this row
never enters a deal verdict. The pack digest (PACK_DIGEST_OF, v2) is sha256
over the UTF-8 text made of one line per regular file in the pack,
`<sha256 hex of its LF-canonical bytes><two spaces><path relative to the
pack, / separated>\n`, sorted by the path's UTF-8 bytes (sha256sum's format;
LF-canonical: every CRLF read as LF, a bare CR kept, the W18 rule, so a
checkout that rewrites line endings still matches; empty directories add
nothing; a symlink or other non-regular entry is refused). A row naming
PACK_DIGEST_OF_V1 (D056, raw bytes) or no rule reads by the raw-byte rule.
`verify_evidence_pack(pack_dir, row)` recomputes it: VERIFIED when
it matches, BROKEN when the pack changed, COULD NOT LOOK when the pack or the
row cannot be read. It says the pack still matches the row; that the row
itself was not rewritten is the chain's and a witness pin's job.

A CHECKER THAT SAYS BROKEN (D067). `check_files=` (`--checks FILE`, repeatable;
the one check input, which the non-party rule below reads too) names files of
`check.verdict.relayed` rows, as one JSON object, a list or JSON lines
(arcaeon.connector.core's shape, read here as plain JSON: kind, vendor
{name, adapter_version}, vendor_id, vendor_word, relayed_verdict, subject {name, sha256}, attestation).
Any row whose relayed_verdict is BROKEN and whose subject.sha256 is the handed
file's sha256 (64 hex, case and a `sha256:` prefix ignored) vetoes act, pay
and irreversible on a VERIFIED envelope: the verdict stays VERIFIED (the bytes
match), the decision is refuse, `checks.veto` is CHECKER_BROKEN and the reason
names the checker. `read` stays allowed and its reason names the checker.
Rows for another sha256, rows that say VERIFIED or COULD NOT LOOK, and rows
of any other kind are ignored. An unsigned row counts: it is reported by the
sender and can only turn allow into refuse, never refuse into allow. A file
that cannot be read (missing, too big, a line that is not a JSON object)
refuses those three actions as CHECKS_UNREADABLE: a veto that could be in it
cannot be ruled out. The veto is evidence like any refusal: with a deal id it
writes the pack, evidence.json carries `checks`, and the gate.evidence row
carries `"veto": "checker-broken"` with verdict VERIFIED. Exit code 1 on
checker-broken (a checker said BROKEN), 3 on checks-unreadable.

ROWS CARRIED IN THE ENVELOPE (TE-31). `envelope seal --checks` puts the same
rows inside the signed Statement (predicate.checks, "checks[]"). On a
VERIFIED envelope the gate reads them exactly as it reads --checks rows, and
the two sources combine: a carried BROKEN for the handed file's sha256 vetoes
as checker-broken (exit 1; its `checks.broken` entry has `source` "envelope",
a --checks row "--checks"); a checks[] that is not a list, has too many items,
an item that is not an object or is too big, vetoes as checks-unreadable;
other kinds and other sha256s are ignored. `checks.carried` = {where, rows}
appears whenever the envelope carries checks[]. On anything but VERIFIED the
carried rows are not read: a carried row never lifts a verdict, and the
verdict already refuses what a veto would. Counting: a carried row counts
exactly as an UNSIGNED --checks row does. It can veto; it never allows; and it
never counts toward the non-party rule below, because the key that signed it
is the envelope's own signer, a party by definition. A vendor's own signature
claim in its `attestation` is never checked, so no carried row is signed by
the vendor as far as the gate can tell.

THE DISPUTE PACKET. `arcaeon gate packet` (arcaeon.prove.dispute_packet)
renders a refusal, from an evidence pack or from a decision's to_dict(), as
one page in markdown and JSON for a marketplace's dispute process. A refusal
on a VERIFIED envelope (checker-broken, or a non-party check rule) renders
too; a VERIFIED allow is nothing to dispute.

A2A. `arcaeon gate a2a` (arcaeon.prove.a2a_receiver) takes the envelope from
an A2A Artifact's metadata under https://arcaeon.io/a2a/witness/v1 and runs
`decide` on it (docs/A2A.md).

A NON-PARTY CHECK ABOVE A CAP (TE-35). A receiver may add one rule on top of
the table: `require_nonparty_check_above=CAP`. When the deal's amount is over
CAP, a VERIFIED envelope allows act, pay and irreversible only if at least one
check among the same `check_files` (`--checks`) counts. A check counts when:

    (a) its own envelope sidecar (CHECK.envelope.json) verifies, through the
        same envelope.verify, under a key that is neither a key that signed
        the handed envelope (or that the receiver named for it) nor the
        audience: a non-party (and, with `checkers` / `--checker DID`, one of
        those pinned keys);
    (b) a row in it names the handed file's sha256 as its subject.sha256;
    (c) that row's relayed_verdict is VERIFIED.

An unsigned row is the sender's report and never counts, whatever its
`attestation` claims. A counting key's row on the same sha256 that says
BROKEN vetoes. No amount (neither `amount` nor the deal record carries one)
refuses those three actions as could-not-look. `read` and every case at or
under the cap are the table above, unchanged. A refusal by this rule carries
`nonparty_check.veto` NONPARTY_VETO ("nonparty-check"), and so does its
gate.evidence row; its reason and exit 3 stand when a --checks file would
also veto (that answer is kept under `checks.would_veto`). The amount is the LARGER of
`amount` and every commit total / pay amount in the deal record
(record_dir/DEAL-<deal>/{buyer,seller}.deal.jsonl), so neither source can
lower it below the other. A deal-record line that is not valid JSON or not
a JSON object, an amount that is not one, and a deal file over the size cap,
not UTF-8 or not readable could each hide an amount, so each refuses those
three actions as could-not-look too, naming the file and line; none is skipped. Limit: this raises the cost of collusion between
the two parties; it does not prove the checker is independent of them.

Stdlib only (verify loads the [sign] backend itself). `decide` raises only on
a caller error, the list in decide's docstring (the one place it is stated),
before anything is read or written; anything else is an answer.
"""
from __future__ import annotations

import hashlib
import json
import os
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

__all__ = ["ACTIONS", "ALLOW", "REFUSE", "RULES", "NEEDS_EXCHANGE", "GateDecision", "decide", "resolve",
           "EVIDENCE_KIND", "CHAIN_KIND", "PACK_DIGEST_OF", "PACK_DIGEST_OF_V1",
           "pack_digest", "CHECK_ROW_KIND", "CHECKER_BROKEN", "CHECKS_UNREADABLE",
           "VETOED", "NONPARTY_VETO", "read_check_rows", "read_carried_rows",
           "FILE_SOURCE", "CARRIED_SOURCE",
           "verify_evidence_pack", "GUARDED", "CHECK_KIND", "NONPARTY_RULE",
           "main"]

ACTIONS = ("read", "act", "pay", "irreversible")
ALLOW, REFUSE = "allow", "refuse"
#: verdict -> the actions it allows. Anything not listed is refused.
RULES = {V.VERIFIED: frozenset(ACTIONS), V.BROKEN: frozenset(),
         V.COULD_NOT_LOOK: frozenset({"read"})}
EVIDENCE_KIND = "arcaeon.gate.evidence/v1"
#: actions that need the exchange named (deal and purpose) before any allow:
#: every action but read (read is the only action an unbound check allows).
NEEDS_EXCHANGE = frozenset({"act", "pay", "irreversible"})
NEED_DEAL = "pass --deal so the envelope is held to this exchange"
NEED_PURPOSE = "pass --purpose so the envelope is held to this exchange"
NEED_BOTH = "pass --deal and --purpose so the envelope is held to this exchange"
#: The ledger row kind a refusal's evidence pack is chained under (D056).
CHAIN_KIND = "gate.evidence"
#: Names the pack digest rule (module docstring, docs/VERBS.md `gate`). v2
#: (D066): each file's sha256 is over its bytes with every CRLF turned into LF
#: (W18's rule), so a checkout that rewrites line endings still matches.
PACK_DIGEST_OF = ("sha256 over sorted '<sha256>  <relpath>' lines (sha256sum format), "
                  "file sha256 over LF-canonical bytes (CRLF to LF), v2")
#: The D056 rule (raw bytes). A row naming it, or no rule, reads by it.
PACK_DIGEST_OF_V1 = "sha256 over sorted '<sha256>  <relpath>' lines (sha256sum format), v1"
_RULES_READ = (PACK_DIGEST_OF, PACK_DIGEST_OF_V1)
#: The D056 default ledger name beside the packs. No longer written (D066: the
#: row belongs in the party's own chain, `ledger=` / `--ledger`, required with
#: a deal); kept so a reader can find rows written before it.
LEDGER_NAME = "ledger.jsonl"
_NEEDS_LEDGER = ("--deal needs --ledger: the gate.evidence row goes in your own deal "
                 "chain (a row written beside the pack could be rewritten along with it)")
_HEX64 = re.compile(r"[0-9a-f]{64}")

#: The row kind a --checks file is read for: arcaeon.connector.core.ROW_KIND.
#: connector is not on this base; once the stack merges, import it from there.
CHECK_ROW_KIND = "check.verdict.relayed"
#: The veto reasons (D067). checker-broken: a check row says BROKEN for these
#: bytes. checks-unreadable: a --checks file could not be read.
CHECKER_BROKEN = "checker-broken"
CHECKS_UNREADABLE = "checks-unreadable"
#: The actions a check veto refuses; `read` is never among them.
VETOED = frozenset({"act", "pay", "irreversible"})
#: A --checks file bigger than this is not read (and so vetoes).
MAX_CHECKS_BYTES = 16 << 20

ALLOW_MEANS = ("allow means the bytes are unchanged since the key you named sealed them "
               "and they are labeled for you and in date; it does not say the content is "
               "true or safe")
LIMITS = [
    ALLOW_MEANS,
    "the gate decides from the envelope's verdict, plus any check rows given or carried "
    "in the envelope that say BROKEN for the same sha256; checking the content is other "
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
#: The veto word a non-party check rule refusal carries (its evidence row and
#: `nonparty_check.veto`), beside D067's checker-broken / checks-unreadable.
NONPARTY_VETO = "nonparty-check"
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
    chain_row: dict | None = None
    chain_error: str | None = None
    report: dict = field(default_factory=dict)
    limits: list = field(default_factory=lambda: list(LIMITS))
    #: the --checks answer (D067), only when check files were given:
    #: {files, rows, file_sha256, broken, problems, veto}
    checks: dict | None = None
    #: the non-party check rule's answer (D061), only when the rule was set
    nonparty_check: dict | None = None
    #: the enforce mode (L4-01, arcaeon.prove.gate_mode): block or warn, and
    #: where it came from (flag, env, latest.json, default)
    enforce_mode: str = "block"
    enforce_source: str = "default"
    enforce_detail: str | None = None
    #: the exit code the decision had before warn let it through (1 or 3), on
    #: any refusal the rules made; None when the rules allowed
    would_exit_code: int | None = None
    #: warn mode only, on a would-refuse: the loud line
    warning: str | None = None

    @property
    def would_refuse(self) -> bool:
        """True when the rules refuse, whether or not warn let it through."""
        return self.would_exit_code is not None or not self.allowed

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW

    def __bool__(self) -> bool:
        return self.allowed

    @property
    def veto(self) -> str | None:
        """What refused a VERIFIED envelope, if anything: checker-broken or
        checks-unreadable (D067), or nonparty-check (the non-party rule)."""
        return (self.checks or {}).get("veto") or (self.nonparty_check or {}).get("veto")

    @property
    def exit_code(self) -> int:
        """0 allow; 1 refuse on BROKEN or checker-broken; 3 refuse on COULD NOT
        LOOK, checks-unreadable or nonparty-check."""
        if self.allowed:
            return V.EXIT_GOOD
        if self.verdict == V.BROKEN or self.veto == CHECKER_BROKEN:
            return V.EXIT_BAD
        return V.EXIT_COULD_NOT_LOOK

    def to_dict(self) -> dict:
        out = self._dict()
        if self.checks is not None:                  # only when check files were given
            out["checks"] = self.checks
        if self.nonparty_check is not None:          # only when the rule was set
            out["nonparty_check"] = self.nonparty_check
        return out

    def _dict(self) -> dict:
        return {"decision": self.decision, "action": self.action, "verdict": self.verdict,
                "reason": self.reason, "reasons": list(self.reasons),
                "could_not_check": dict(self.could_not_check) if self.could_not_check else None,
                "file": self.file, "envelope": self.envelope, "audience": self.audience,
                "deal": self.deal, "purpose": self.purpose, "signers": list(self.signers),
                "at": self.at, "evidence": self.evidence,
                "evidence_error": self.evidence_error,
                "chain_row": dict(self.chain_row) if self.chain_row else None,
                "chain_error": self.chain_error, "exit_code": self.exit_code,
                "enforce_mode": self.enforce_mode, "enforce_source": self.enforce_source,
                "enforce_detail": self.enforce_detail, "would_refuse": self.would_refuse,
                "would_exit_code": (self.would_exit_code if self.would_exit_code is not None
                                    else (None if self.allowed else self.exit_code)),
                "warning": self.warning,
                "limits": list(self.limits), "report": self.report}


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
          "could_not_check": dict(d.could_not_check) if d.could_not_check else None,
          "at": _utc(now), "file": parts["file"], "envelope": parts["envelope"],
          "audience": d.audience, "purpose": d.purpose, "signers": list(signers), "limits": list(d.limits),
          "report": d.report}
    if d.checks is not None:
        ev["checks"] = d.checks
    if d.nonparty_check is not None:
        ev["nonparty_check"] = d.nonparty_check
    (out / "evidence.json").write_text(json.dumps(ev, indent=1, ensure_ascii=False) + "\n",
                                       encoding="utf-8", newline="\n")
    return out


def _file_sha256_lf(path: Path) -> str:
    """sha256 of the file's LF-canonical bytes: every CRLF becomes LF (a bare
    CR is content and stays), streamed; a CR at a chunk's end waits for the
    next chunk so a CRLF split across the edge still counts as one LF."""
    h, held = hashlib.sha256(), b""
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            chunk = held + chunk
            held = b""
            if chunk.endswith(b"\r"):
                chunk, held = chunk[:-1], b"\r"
            h.update(chunk.replace(b"\r\n", b"\n"))
    h.update(held)
    return h.hexdigest()


def _file_sha256_raw(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pack_digest(pack_dir: str | Path, *, of: str = PACK_DIGEST_OF) -> str:
    """The pack digest (PACK_DIGEST_OF): sha256 over one `<sha256>  <relpath>\\n`
    line per regular file under `pack_dir`, sorted by the relpath's UTF-8 bytes,
    each file's sha256 over its LF-canonical bytes (CRLF to LF). `of` =
    PACK_DIGEST_OF_V1 hashes raw bytes instead (rows written before D066).
    Raises ValueError on a symlink or other non-regular entry (the gate never
    writes one) or an unknown rule, OSError when the pack cannot be read."""
    if of not in _RULES_READ:
        raise ValueError(f"unknown pack digest rule {of!r}")
    file_sha = _file_sha256_lf if of == PACK_DIGEST_OF else _file_sha256_raw
    root = Path(pack_dir)
    if not root.is_dir() or root.is_symlink():
        raise FileNotFoundError(f"no evidence pack directory at {root}")
    lines = []
    for here, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            p = Path(here) / name
            rel = p.relative_to(root).as_posix()
            junction = getattr(p, "is_junction", lambda: False)()
            if p.is_symlink() or junction:
                raise ValueError(f"the pack holds {rel!r}, a link; the gate never writes one")
            if name in dirs:
                continue
            if not p.is_file():
                raise ValueError(f"the pack holds {rel!r}, which is not a regular file")
            lines.append((rel.encode("utf-8"), f"{file_sha(p)}  {rel}\n"))
    lines.sort(key=lambda t: t[0])
    return hashlib.sha256("".join(t[1] for t in lines).encode("utf-8")).hexdigest()


def verify_evidence_pack(pack_dir: str | Path, row: dict) -> dict:
    """Does the pack at `pack_dir` still match the `gate.evidence` row's
    pack_digest? {"verdict", "reason", "recorded", "now"}: VERIFIED when it
    matches, BROKEN when a file in the pack was edited, added, removed or
    renamed (or a link was put in it), COULD NOT LOOK when the row is not a
    gate.evidence row with a digest, or the pack is not there or unreadable.
    Never raises. It does not check the row against its chain."""
    out = {"verdict": V.COULD_NOT_LOOK, "reason": "", "recorded": None, "now": None}
    if not isinstance(row, dict) or row.get("kind") != CHAIN_KIND:
        out["reason"] = f"the row is not a {CHAIN_KIND} row"
        return out
    rec = row.get("pack_digest")
    out["recorded"] = rec
    if not isinstance(rec, str) or not _HEX64.fullmatch(rec):
        out["reason"] = "the row carries no readable pack_digest"
        return out
    rule = row.get("pack_digest_of")
    if rule is None:                          # D056 rows always named v1; absent reads as v1
        rule = PACK_DIGEST_OF_V1
    if rule not in _RULES_READ:
        out["reason"] = f"the row's digest rule {rule!r} is not one this reads"
        return out
    try:
        now = pack_digest(pack_dir, of=rule)
    except ValueError as e:
        out.update(verdict=V.BROKEN, reason=str(e))
        return out
    except OSError as e:
        out["reason"] = f"the evidence pack could not be read ({type(e).__name__}: {e})"
        return out
    out["now"] = now
    if now == rec:
        out.update(verdict=V.VERIFIED, reason="every file in the pack hashes to the digest "
                                              "the gate.evidence row recorded")
    else:
        out.update(verdict=V.BROKEN, reason=f"the pack changed after the row was written: "
                                            f"digest now {now}, the row recorded {rec}")
    return out


def _append_chain_row(d: GateDecision, pack: Path, ledger: Path, now: datetime) -> dict:
    """One gate.evidence row, through the ledger writer the deal rows use."""
    from arcaeon.record.ledger import Ledger
    ev = json.loads((pack / "evidence.json").read_text(encoding="utf-8"))
    row = {"kind": CHAIN_KIND, "deal": d.deal,
           "file_sha256": (ev.get("file") or {}).get("sha256"),
           "verdict": d.verdict, "reason": ev.get("reason"), "pack": pack.name,
           "pack_digest": pack_digest(pack), "pack_digest_of": PACK_DIGEST_OF,
           "at": _utc(now)}
    if d.veto:                                # D067: a refusal on a VERIFIED envelope
        row["veto"] = d.veto
    row["ts"] = row["at"]                    # as Deal._write: the returned row is the line
    row["chain"] = Ledger(ledger).append(row)
    return row


def _norm_sha(v: Any) -> str | None:
    if not isinstance(v, str):
        return None
    s = v.strip().lower()
    if s.startswith("sha256:"):
        s = s[len("sha256:"):]
    return s if _HEX64.fullmatch(s) else None


def read_check_rows(paths) -> tuple[list[tuple[str, int, dict]], list[str]]:
    """((file name, line number, row) for every check.verdict.relayed row in
    `paths`, problems). A row is plain JSON with arcaeon.connector.core's field
    names (read here without importing it). A file is one JSON object, a JSON
    list of objects, or JSON lines (the shapes the non-party rule reads too;
    the number is the line, or the list item, from 1). A problem is a file that
    cannot be read: missing, over MAX_CHECKS_BYTES, not UTF-8, a list item or
    a non-blank line that is not a JSON object. Rows of other kinds are
    skipped. Never raises."""
    from arcaeon.record.row import loads_strict
    rows: list[tuple[str, int, dict]] = []
    problems: list[str] = []
    for p in paths or ():
        try:
            p = Path(p)
            if p.stat().st_size > MAX_CHECKS_BYTES:
                problems.append(f"{p.name}: over {MAX_CHECKS_BYTES} bytes, not read")
                continue
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError, ValueError, TypeError) as e:
            problems.append(f"{Path(str(p)).name}: cannot be read ({type(e).__name__})")
            continue
        try:
            doc = loads_strict(text) if text.strip() else None
        except (ValueError, RecursionError):
            doc = None                               # not one document: JSON lines below
        if isinstance(doc, (dict, list)):
            for n, row in enumerate(doc if isinstance(doc, list) else [doc], 1):
                if not isinstance(row, dict):
                    problems.append(f"{p.name} item {n}: not a JSON object")
                elif row.get("kind") == CHECK_ROW_KIND:
                    rows.append((p.name, n, row))
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = loads_strict(line)
            except (ValueError, RecursionError) as e:
                problems.append(f"{p.name} line {n}: not JSON ({type(e).__name__})")
                continue
            if not isinstance(row, dict):
                problems.append(f"{p.name} line {n}: not a JSON object")
            elif row.get("kind") == CHECK_ROW_KIND:
                rows.append((p.name, n, row))
    return rows, problems


def _who(b: dict) -> str:
    s = f"{b['checker']!r}"
    at = "item" if b.get("source") == CARRIED_SOURCE else "line"
    extra = [f"subject {b['subject']!r}" if b.get("subject") else None,
             f"vendor id {b['vendor_id']!r}" if b.get("vendor_id") else None,
             f"{b['file']} {at} {b['line']}"]
    return s + " (" + ", ".join(x for x in extra if x) + ")"


#: Where a check row came from: a --checks file, or the envelope's checks[] (TE-31).
FILE_SOURCE, CARRIED_SOURCE = "--checks", "envelope"


def read_carried_rows(r: dict, env_path) -> tuple[list[tuple[str, int, dict]] | None, list[str],
                                                    str]:
    """The check rows a VERIFIED envelope carries (TE-31): (rows, problems,
    where), rows as read_check_rows gives them ((where, item number, row) for
    each check.verdict.relayed row), or None when the envelope carries no
    checks[] at all. `r` is envelope.verify's report; the rows were signed with
    the payload, so this reads them only after verify said VERIFIED. A checks[]
    that is not a list, holds more than envelope.MAX_CARRIED_CHECKS items, an
    item that is not a JSON object or is over envelope.MAX_CARRIED_CHECK_BYTES
    is a problem (it vetoes as checks-unreadable, as an unreadable --checks file
    does); a row of another kind is skipped, as in a --checks file. Never raises."""
    where = f"{Path(str(env_path)).name} checks[]"
    sealed = r.get("sealed") if isinstance(r.get("sealed"), dict) else {}
    if E.CHECKS_KEY not in sealed:
        return None, [], where
    value = sealed[E.CHECKS_KEY]
    if not isinstance(value, list):
        return [], [f"{where}: a {type(value).__name__}, not a list of check rows"], where
    if len(value) > E.MAX_CARRIED_CHECKS:
        return [], [f"{where}: {len(value)} items, over the {E.MAX_CARRIED_CHECKS} an "
                    f"envelope carries; not read"], where
    rows, problems = [], []
    for n, row in enumerate(value, 1):
        if not isinstance(row, dict):
            problems.append(f"{where} item {n}: not a JSON object")
            continue
        try:
            size = len(json.dumps(row, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=False).encode("utf-8"))
        except (TypeError, ValueError, RecursionError) as e:
            problems.append(f"{where} item {n}: not plain JSON ({type(e).__name__})")
            continue
        if size > E.MAX_CARRIED_CHECK_BYTES:
            problems.append(f"{where} item {n}: {size} bytes, over the "
                            f"{E.MAX_CARRIED_CHECK_BYTES}-byte limit for a carried row")
        elif row.get("kind") == CHECK_ROW_KIND:
            rows.append((where, n, row))
    return rows, problems, where


def _judge_checks(paths, file: Path, carried=None) -> dict:
    """The --checks answer for `file`: which rows say BROKEN for its sha256.
    `carried` is read_carried_rows' answer: the envelope's own rows join the
    --checks rows and are judged by the same rule."""
    from arcaeon.record.row import file_pin
    got, problems = read_check_rows(paths)
    rows = [(name, n, row, FILE_SOURCE) for name, n, row in got]
    if carried is not None and carried[0] is not None:
        rows += [(name, n, row, CARRIED_SOURCE) for name, n, row in carried[0]]
        problems.extend(carried[1])
    pin = file_pin(file)
    sha = pin.get("sha256")
    if not sha:
        problems.append(f"the handed file's sha256 could not be taken ({pin.get('error')})")
    broken = []
    for name, n, row, source in rows:
        subj = row.get("subject") if isinstance(row.get("subject"), dict) else {}
        if not sha or row.get("relayed_verdict") != V.BROKEN or _norm_sha(subj.get("sha256")) != sha:
            continue
        vendor = row.get("vendor") if isinstance(row.get("vendor"), dict) else {}
        att = row.get("attestation") if isinstance(row.get("attestation"), dict) else {}
        keep = {k: v for k, v in row.items() if k != "vendor_payload"}
        broken.append({"checker": str(vendor.get("name") or "an unnamed checker")[:128],
                       "adapter_version": vendor.get("adapter_version"),
                       "vendor_id": row.get("vendor_id"), "vendor_word": row.get("vendor_word"),
                       "subject": subj.get("name"), "sha256": sha,
                       "attestation": att.get("status") or "NONE",
                       "reported_by": "sender", "source": source, "file": name, "line": n,
                       "row": keep})
    info = {"files": [Path(p).name for p in paths], "rows": len(rows), "file_sha256": sha,
            "broken": broken, "problems": problems, "veto": None}
    if carried is not None and carried[0] is not None:
        info["carried"] = {"where": carried[2], "rows": len(carried[0])}
    return info


def _broken_finding(b: dict) -> str:
    return (f"checker {_who(b)} says BROKEN (its word {b.get('vendor_word')!r}) for sha256 "
            f"{b['sha256']}; reported by the sender, attestation {b['attestation']}, "
            f"not checked by us")


def _apply_checks(d: GateDecision, info: dict) -> None:
    """Fold the --checks answer into a VERIFIED decision (D067). After a
    non-party rule refusal the rule's reason, reasons and exit 3 stand: the
    answer is recorded, and what it would have vetoed is `would_veto` (F9)."""
    d.checks = info
    if d.veto == NONPARTY_VETO:
        would = (CHECKER_BROKEN if info["broken"] else
                 CHECKS_UNREADABLE if info["problems"] else None)
        if would and d.action in VETOED:
            info["would_veto"] = would
        return
    names = ", ".join(_who(b) for b in info["broken"])
    if d.action not in VETOED:
        if info["broken"]:
            d.reason += (f" Note: {names} says BROKEN for these bytes ({CHECKER_BROKEN}); "
                         f"read is allowed, act, pay and irreversible would be refused.")
        return
    if info["broken"]:
        info["veto"] = CHECKER_BROKEN
        d.decision = REFUSE
        d.reasons = [_broken_finding(b) for b in info["broken"]]
        d.reason = (f"refuse {d.action}: {CHECKER_BROKEN}: {names} says BROKEN for sha256 "
                    f"{info['file_sha256']}, the bytes the envelope sealed. The envelope "
                    f"reads VERIFIED (the bytes are unchanged since the key you named "
                    f"sealed them); the checker's word vetoes {d.action}. Its row is "
                    f"reported by the sender, not checked by us: it can turn allow into "
                    f"refuse, never into allow. Read is allowed; keep the file, the "
                    f"envelope and the check row as evidence.")
    elif info["problems"]:
        info["veto"] = CHECKS_UNREADABLE
        d.decision = REFUSE
        d.reasons = list(info["problems"])
        d.could_not_check = {"looked_for": "a check row that says BROKEN for these bytes",
                             "where": ", ".join(list(info["files"]) + (
                                 [info["carried"]["where"]] if info.get("carried") else []))
                             or "--checks",
                             "reason_word": "unreadable"}
        d.reason = (f"refuse {d.action}: {CHECKS_UNREADABLE}: the envelope reads VERIFIED, "
                    f"but a check file (or the envelope's checks[]) could not be read "
                    f"({'; '.join(info['problems'])}), "
                    f"so a checker's BROKEN in it cannot be ruled out. Only read is "
                    f"allowed until it can be read.")


def _unbound(action: str, deal, purpose) -> dict | None:
    """The could-not-look keys when `action` needs the exchange named and it
    is not: act, pay and irreversible need both `deal` and `purpose`, so an
    envelope sealed for one exchange cannot be replayed into another. read is
    the only action an unbound check allows. None otherwise. With both missing
    the answer is one sentence naming both, deal first, for every action (A07);
    act names both whenever either is missing."""
    if action not in NEEDS_EXCHANGE:
        return None
    if (action == "act" and not (deal and purpose)) or not (deal or purpose):
        return V.could_not_look("the deal and purpose this exchange is for "
                                "(--deal and --purpose)", "the gate call", "missing", NEED_BOTH)
    if not deal:
        return V.could_not_look("the deal this exchange is for (--deal)", "the gate call",
                                "missing", NEED_DEAL)
    if not purpose:
        return V.could_not_look("the purpose this exchange is for (--purpose)",
                                "the gate call", "missing", NEED_PURPOSE)
    return None


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
    """A finite, non-negative amount, or None. A JSON number (float) counts:
    a record row written as 1000000.5 is an amount, never a skip (R3-3)."""
    if isinstance(v, bool) or not isinstance(v, (str, int, float, Decimal)):
        return None
    try:
        d = Decimal(str(v).strip())
    except (InvalidOperation, ValueError):
        return None
    return d if d.is_finite() and d >= 0 else None


def _deal_amounts(record_dir: Path, deal: str) -> tuple[list, str, list, list]:
    """Every readable commit total and pay amount for `deal` in its record
    (DEAL-<deal>/{buyer,seller}.deal.jsonl). Returns (amounts, where, notes,
    unreadable): `unreadable` names, by file and line, each line that is not
    valid JSON or not a JSON object and each matching row whose amount is not
    one, and by file each file over the size cap, not UTF-8 or not readable;
    any of them could hide an amount over the cap, so the rule refuses on it
    (R3, fail closed on money), never skips it."""
    base = record_dir / _deal_dir_name(deal)
    amounts, notes, unreadable = [], [], []
    for name in ("buyer.deal.jsonl", "seller.deal.jsonl"):
        p = base / name
        try:
            if not p.is_file():
                continue
            if p.stat().st_size > 16 * MAX_CHECK_BYTES:     # fail closed: its amounts are unread
                unreadable.append(f"{name}: over {16 * MAX_CHECK_BYTES} bytes, not read")
                continue
            lines = p.read_bytes().decode("utf-8").splitlines()
        except UnicodeDecodeError:
            unreadable.append(f"{name}: not UTF-8, not read")
            continue
        except OSError as e:
            unreadable.append(f"{name}: not read ({type(e).__name__})")
            continue
        for n, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                row = loads_strict(line)
            except ValueError:
                unreadable.append(f"{name} line {n}: not valid JSON")
                continue
            if not isinstance(row, dict):                 # not a row: could stand for one
                unreadable.append(f"{name} line {n}: JSON but not an object")
                continue
            if row.get("deal", deal) != deal:
                continue
            shared = row.get("shared") if isinstance(row.get("shared"), dict) else {}
            if row.get("kind") == "deal.commit" and isinstance(shared.get("terms"), dict):
                raw = shared["terms"].get("total")
            elif row.get("kind") == "deal.pay":
                raw = shared.get("amount")
            else:
                continue
            a = _decimal(raw)
            if a is not None:
                amounts.append(a)
            else:                                # R3-3: a skipped amount could be the large one
                unreadable.append(f"{name} line {n}: {row.get('kind')} amount "
                                  f"{str(raw)[:40]!r} is not a readable amount")
    return amounts, str(base), notes, unreadable


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
                and _norm_sha(x["subject"].get("sha256")) == sha]
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
        found, where, notes, unreadable = _deal_amounts(record_dir, deal)
        info["amount_notes"].extend(notes + unreadable)
        if unreadable:
            info["could_not_check"] = V.could_not_look(
                "every file and line of the deal record (an amount could be in any)", where,
                "unreadable",
                f"{'; '.join(unreadable[:5])}{' and more' if len(unreadable) > 5 else ''}: "
                f"a part of the deal record the rule cannot read could hide an amount "
                f"over the cap, so whether the cap applies cannot be checked")
            return info
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
    why = "; ".join(f"{j['check']}: {j['why']}" for j in info["checks"]) or "no --checks file was given"
    return (f"refuse {action}: {verdict}, but the non-party check rule refuses it: the {amt} "
            f"is over the cap {cap} and no check counts ({why}). A check counts only when "
            f"a key that is neither the envelope's signer nor the audience signed it, it "
            f"names this file's sha256 and it says VERIFIED; a row nobody signed is the "
            f"sender's report. Only read is allowed until one does.")


def decide(file: str | Path, *, action: str, audience: str | None,
           signers=(), deal: str | None = None, envelope: str | Path | None = None,
           purpose: str | None = None, record_dir: str | Path | None = None,
           ledger: str | Path | None = None, now: datetime | None = None,
           check_files=(), require_nonparty_check_above=None,
           amount=None, checks=(), checkers=(), on_pack=None,
           enforce=None, record: bool = True) -> GateDecision:
    """allow or refuse `action` on `file`, from `envelope.verify`'s verdict.

    `file` is the handed file; `envelope` its sidecar (default: beside it).
    `audience`, `signers`, `deal` and `purpose` go to verify unchanged (a
    wrong one is BROKEN there). On a refusal (BROKEN, or COULD NOT LOOK on
    anything but read) with a `deal`, an evidence pack is written under
    `record_dir` (default: the current directory) and one gate.evidence row
    is appended to `ledger`, the party's own chain. `ledger` is required with
    `deal` (D066): a row written beside the pack could be rewritten with it.
    `check_files` (paths of check.verdict.relayed rows, D067): on a
    VERIFIED envelope, a row saying BROKEN for the file's sha256 refuses act,
    pay and irreversible as CHECKER_BROKEN (an unreadable file: as
    CHECKS_UNREADABLE); read stays allowed. Rows the envelope carries in its
    signed checks[] (TE-31) join them on a VERIFIED envelope, by the same rule.
    `require_nonparty_check_above` (an amount, D061) adds the non-party check
    rule (module docstring): over it, a VERIFIED envelope allows act, pay and
    irreversible only with a counting check among the same `check_files`;
    `amount` is the deal's amount (the larger of it and the deal record's is
    used); `checkers` (DIDs) pins which non-party keys count. Unset, nothing
    changes. `checks` is a deprecated alias: its paths join `check_files`.
    `on_pack(pack_dir)`, when given, runs after the evidence pack is written
    and before its gate.evidence row is appended, so what it adds to the pack
    is covered by the row's pack_digest (the A2A receiver keeps its message
    this way); an exception in it is swallowed.
    `enforce` (L4-01, arcaeon.prove.gate_mode): "block", "warn" (source
    flag), a gate_mode.Mode (what gate_mode.resolve() answered: the CLI and
    the MCP tools pass this), or None: block, source default, without reading
    the environment or the check-in cache. In warn mode a refusal is still
    computed, packed and chained, then let through: decision allow, exit 0,
    `warning` says it would refuse in block mode and `would_exit_code` keeps
    the refusal's code. `record=False` writes nothing (no pack, no row; a
    `deal` then needs no `ledger`): the decision only.
    Raises ValueError on an unknown action, a `deal` without a `ledger` or an
    unreadable cap (and on an unknown `enforce` value; with record=False a
    `deal` needs no `ledger`), before anything is read or written; otherwise
    never raises."""
    from arcaeon.prove import gate_mode as _gm
    if action not in ACTIONS:
        raise ValueError(f"action must be one of {ACTIONS}, got {action!r}")
    if isinstance(enforce, _gm.Mode):
        mode = enforce
    elif enforce is None:
        mode = _gm.LIBRARY_DEFAULT
    else:
        mode = _gm.resolve(enforce)
    if record and deal is not None and ledger is None:
        raise ValueError(_NEEDS_LEDGER)
    cap = None
    if require_nonparty_check_above is not None:
        cap = _decimal(require_nonparty_check_above)
        if cap is None:
            raise ValueError(f"require_nonparty_check_above must be a non-negative amount, "
                             f"got {require_nonparty_check_above!r}")
    now = now or datetime.now(timezone.utc)
    check_files = list(check_files or ()) + list(checks or ())   # one input (--checks)
    file = Path(file)
    env_path = Path(envelope) if envelope is not None else E.envelope_path(file)
    signers = list(signers or ())
    r = E.verify(file, env_path, audience=audience, deal=deal, purpose=purpose,
                 signers=signers, now=now)
    verdict = r.get("verdict")
    if verdict not in RULES:                     # never a green on an unknown word
        verdict = V.COULD_NOT_LOOK
    unbound = _unbound(action, deal, purpose)
    if unbound is not None and verdict != V.BROKEN:   # before the table: no replay
        if verdict == V.VERIFIED:
            r = {**r, "verdict": V.COULD_NOT_LOOK, "verify_verdict": V.VERIFIED,
                 **unbound}
        else:
            r = {**r, "reason": "; ".join(s for s in (unbound["reason"], r.get("reason"))
                                          if s)}
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
                    cap=cap, amount=amount, checks=check_files, checkers=checkers, file=file,
                    r=r,
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
                    ", ".join(str(c) for c in check_files) or "--checks", "missing",
                    "no check given counts toward the non-party check rule")
                reasons = [j["check"] + ": " + j["why"] for j in policy["checks"]] or \
                    [cnc["reason"]]
                policy["veto"] = NONPARTY_VETO
            reason = _nonparty_reason(action, verdict, policy, reason) \
                if policy["applies"] is not False else reason
    d = GateDecision(decision=ALLOW if allowed else REFUSE, action=action, verdict=verdict,
                     reason=reason, reasons=reasons,
                     could_not_check=cnc, file=str(file), envelope=str(env_path),
                     audience=audience, deal=deal, purpose=purpose, signers=list(signers),
                     at=_utc(now), report=r, nonparty_check=policy)
    # TE-31: a VERIFIED envelope's own checks[] rows join the --checks rows. Read
    # only on VERIFIED: the rows were signed with the payload, and a carried row
    # can only turn allow into refuse, so it is never needed to refuse.
    carried = read_carried_rows(r, env_path) if verdict == V.VERIFIED else (None, [], "")
    if (check_files or carried[0] is not None) and verdict == V.VERIFIED:
        try:
            _apply_checks(d, _judge_checks(check_files, file, carried))
        except Exception as e:  # noqa: BLE001  never a green on a crash
            _apply_checks(d, {"files": [Path(p).name for p in check_files], "rows": 0,
                              "file_sha256": None, "broken": [], "veto": None,
                              "problems": [f"the checks could not be read ({type(e).__name__})"]})
        allowed = d.decision == ALLOW
    if not allowed and deal is not None and not record:
        d.reason += " Nothing was recorded (a decision only)."
    elif not allowed and deal is not None:
        try:
            out = _write_evidence(d, file, env_path, signers,
                                  Path(record_dir) if record_dir is not None else Path.cwd(), now)
            d.evidence = str(out)
            d.reason += f" Evidence pack written to {out}."
        except Exception as e:  # noqa: BLE001  the refusal stands either way
            d.evidence_error = f"evidence pack not written ({type(e).__name__}: {e})"
            d.reason += f" The evidence pack could not be written ({type(e).__name__})."
        if d.evidence is not None:
            out = Path(d.evidence)
            if on_pack is not None:
                try:
                    on_pack(out)
                except Exception:  # noqa: BLE001  the refusal and the pack stand either way
                    pass
            try:
                d.chain_row = _append_chain_row(d, out, Path(ledger), now)
            except Exception as e:  # noqa: BLE001  the refusal stands either way
                d.chain_error = f"gate.evidence row not appended ({type(e).__name__}: {e})"
                d.reason += (f" The {CHAIN_KIND} row could not be appended "
                             f"({type(e).__name__}).")
    elif not allowed:
        d.reason += " No deal id was given, so no evidence pack was written."
    return _enforce(d, mode)


def _enforce(d: GateDecision, mode) -> GateDecision:
    """Stamp the mode; in warn mode let a refusal through, loudly (L4-01)."""
    from arcaeon.prove import gate_mode as _gm
    d.enforce_mode, d.enforce_source, d.enforce_detail = mode.mode, mode.source, mode.detail
    if d.decision != REFUSE:
        return d
    d.would_exit_code = d.exit_code
    if mode.mode == _gm.WARN:
        d.warning = (f"WARNING: {_gm.WOULD_REFUSE} (enforce warn, from {mode.source}); "
                     f"the {d.action} is let through and only recorded: {d.reason}")
        d.reason = (f"allow {d.action} (enforce warn, from {mode.source}): "
                    f"{_gm.WOULD_REFUSE}. {d.reason}")
        d.decision = ALLOW
    return d


# --- CLI ------------------------------------------------------------------------

USAGE = """usage: arcaeon gate decide --envelope PATH --audience ID --signer DID
                           --action {read,act,pay,irreversible}
                           [--deal ID --ledger PATH] [--purpose TEXT]
                           [--checks FILE ...] [--file PATH]
                           [--record-dir DIR]
                           [--require-nonparty-check-above AMOUNT
                            [--amount N] [--checker DID ...]]
                           [--enforce {warn,block}] [--json]
       arcaeon gate packet (--evidence DIR | --decision FILE.json)
                           [--out DIR] [--json]
       arcaeon gate a2a --message FILE.json --audience ID --signer DID
                        --action {read,act,pay,irreversible} [--file PATH]
                        [--artifact ID] [--deal ID --ledger PATH]
                        [--purpose TEXT] [--activated URIS]
                        [--record-dir DIR] [--json]
       arcaeon gate mcp-after [--config FILE] [--tool NAME]
                              [--action {read,act,pay,irreversible}]
                              [--enforce {warn,block}]"""

HELP = USAGE + """

decide runs `envelope verify` and turns its word into allow or refuse for the
action you are about to take:

  VERIFIED        allows read, act, pay and irreversible
  BROKEN          refuses all four
  COULD NOT LOOK  allows read only; refuses act, pay and irreversible,
                  naming what could not be checked

act, pay and irreversible need --deal and --purpose: without either the answer
is COULD NOT LOOK (refuse, exit 3), so an envelope sealed for one exchange
cannot be replayed into another. read is the only action an unbound check
allows.

Every refusal with --deal writes an evidence pack (the file and envelope
bytes, their sha256, the verdict, the reasons, the UTC time) to
DIR/DEAL-<deal>/gate/<stamp>/.

--envelope names the sidecar (FILE.envelope.json; the handed file is FILE)
or the handed file itself (its sidecar beside it); with --file, --envelope is
the sidecar under any name and --file the handed file. --signer may be
repeated. --deal and --purpose are held against the envelope's binding.
--record-dir defaults to the current directory.

--deal needs --ledger: with an evidence pack written, one `gate.evidence`
row (deal, file sha256, verdict BROKEN or COULD NOT LOOK, reason, the pack's
digest, UTC time) is appended to the hash-chained ledger --ledger names, your
own deal chain, so a later edit of the pack no longer matches the chain. A
row beside the pack could be rewritten along with it, so there is no default.
The pack digest hashes each file with CRLF read as LF, so a line-ending
rewrite of the pack still matches. `deal dispute` ignores the row.

--checks FILE (repeatable) names files of check.verdict.relayed rows (one
JSON object, a list, or JSON lines: a scanner's verdict relayed into your
chain, e.g. mcp-scan); the non-party rule below reads the same files. On a
VERIFIED envelope, any row saying BROKEN for the handed file's sha256 refuses act, pay
and irreversible as checker-broken, naming the checker (exit 1); the verdict
stays VERIFIED. read stays allowed. Rows for another sha256, or saying
VERIFIED or COULD NOT LOOK, are ignored. A FILE that cannot be read refuses
those three actions as checks-unreadable (exit 3). An unsigned row counts: it
can turn allow into refuse, never into allow. Rows the envelope carries in
its signed checks[] (`envelope seal --checks`) are read the same way on a
VERIFIED envelope and combine with --checks; a carried row never counts
toward the non-party rule (the envelope's signer is a party).

Allow means the bytes are unchanged since the key you named sealed them and
are labeled for you and in date. It does not say the content is true or safe.

--require-nonparty-check-above AMOUNT: when the deal's amount is over AMOUNT,
a VERIFIED envelope allows act, pay and irreversible only if one --checks
FILE counts: a check.verdict.relayed row naming this file's sha256 and
saying VERIFIED, in a file whose own envelope (FILE.envelope.json, labeled
for you) verifies under a key that is neither the handed envelope's signer
nor the audience (with --checker DID, repeatable, one of those keys). An unsigned row is the
sender's report and never counts; a counting key's BROKEN vetoes. The amount
is the larger of --amount and the deal record's commit total / pay amount
(DIR/DEAL-<deal>/); with neither, those actions are refused (exit 3). read,
and anything at or under AMOUNT, follow the table. This raises the cost of
collusion between the parties; it does not prove the checker independent.

--enforce {warn,block} (default on): block refuses as above. warn computes
the same decision, lets the action through (exit 0) and prints a WARNING line
on stderr, "would refuse in block mode"; the JSON keeps would_exit_code (1 or
3). Warn mode lets the action through; it only records. The mode is
--enforce, else ARCAEON_GATE_MODE=warn|block, else the signed latest.json's
block_after from the check-in cache (warn before both its version and date,
block at or after either; never a fetch), else block: with no signed answer
cached the gate blocks (fail closed). Any other value is bad usage (exit 2).
Every decision carries enforce_mode and enforce_source (flag, env,
latest.json or default).

Prints one line, `allow <action>: ...` or `refuse <action>: ...` (--json:
the whole decision).
Exit codes: 0 allow (and warn mode's let-through), 1 refuse (BROKEN or
checker-broken), 3 refuse (COULD NOT LOOK, checks-unreadable, or no counting
non-party check), 2 bad usage.
Spec and limits: docs/ENVELOPE.md.

packet renders a refusal as one page a dispute process can take: what was
handed (name, sha256, size), by whom, for whom, when, what failed, what was
not checked, the verdict and decision, and the envelope spec's "does not
prove" list word for word. --evidence is an evidence pack directory (a
refusal with a deal id); --decision is the `decide --json` output (so a
refusal without a deal id, which writes no pack, can be rendered too). File names only,
never the directories. Prints markdown (--json: the JSON form, kind
arcaeon.dispute.packet/v1); --out DIR writes dispute-packet.md and
dispute-packet.json there instead.
Exit codes: 0 written, 2 bad usage or nothing to dispute (the gate allowed
the action), 3 the input could not be read as a gate record.

a2a is decide for a file handed over A2A (Agent2Agent): the envelope rides
in the Artifact's (or Message's) metadata under the witness extension URI
https://arcaeon.io/a2a/witness/v1 (docs/A2A.md). --message is the A2A JSON (an
Artifact, Message, Task, artifact update event, or a JSON-RPC body around
one); --file is the artifact's file (default: its one inline raw part; a url
part is never fetched). --artifact picks the artifact when several carry an
envelope. --activated is the A2A-Extensions value the request carried; it is
recorded and changes no verdict. No envelope there, or no file bytes, is
COULD NOT LOOK (read only). Same exit codes as decide.

mcp-after is the Docker MCP Gateway after-interceptor (docs/GATEWAYS.md):
`--interceptor 'after:exec:arcaeon gate mcp-after --config FILE'`. It reads
the tool-call response JSON on stdin, verifies the envelope under
_meta["dev.arcaeon/bundle"] by decide's rule, and prints the JSON back:
passed with _meta["dev.arcaeon/verdict"], or replaced by an isError REFUSED
result. --config is the gateway config (default: $ARCAEON_GATEWAY_CONFIG);
--tool names the tool when the input does not; --action and --enforce
override the config. Exit 0 for any stdin (malformed stdin is a refusal
result); 2 bad arguments or an unreadable config, with a refusal result
printed all the same."""

_SPEC = {"--envelope": "value", "--audience": "value", "--signer": "list",
         "--action": "value", "--deal": "value", "--purpose": "value", "--file": "value",
         "--record-dir": "value", "--ledger": "value", "--checks": "list",
         "--json": "bool",
         "--require-nonparty-check-above": "value", "--amount": "value",
         "--checker": "list", "--enforce": "value"}
_CHECK_GONE = ("--check is now --checks FILE (repeatable): one flag feeds the checker veto "
               "and the non-party check rule; --checker DID pins which keys count")


def _decide_cli(argv: list[str]) -> int:
    if any(a == "--check" or a.startswith("--check=") for a in argv):
        raise E._Usage(_CHECK_GONE)
    pos, o = E._parse(argv, _SPEC)
    if pos:
        raise E._Usage(f"unexpected argument {pos[0]!r}")
    for need in ("--envelope", "--audience", "--signer", "--action"):
        if not o.get(need):
            raise E._Usage(f"decide needs {need}")
    if o["--action"] not in ACTIONS:
        raise E._Usage(f"--action must be one of {', '.join(ACTIONS)}")
    if o.get("--deal") is not None and not o.get("--ledger"):
        raise E._Usage(_NEEDS_LEDGER)
    cap = o.get("--require-nonparty-check-above")
    if cap is None:
        for dep in ("--amount", "--checker"):
            if o.get(dep):
                raise E._Usage(f"{dep} needs --require-nonparty-check-above AMOUNT")
    else:
        for flag in ("--require-nonparty-check-above", "--amount"):
            if o.get(flag) is not None and _decimal(o[flag]) is None:
                raise E._Usage(f"{flag} must be a non-negative amount, got {o[flag]!r}")
    from arcaeon.prove import gate_mode as _gm
    try:
        mode = _gm.resolve(o.get("--enforce"))
    except ValueError as e:
        raise E._Usage(str(e)) from None
    file, env_path = resolve(o["--envelope"], o.get("--file"))
    d = decide(file, envelope=env_path, action=o["--action"], audience=o["--audience"],
               signers=o["--signer"], deal=o.get("--deal"), purpose=o.get("--purpose"),
               record_dir=o.get("--record-dir"), ledger=o.get("--ledger"),
               check_files=o.get("--checks") or (), require_nonparty_check_above=cap,
               amount=o.get("--amount"), checkers=o.get("--checker", []), enforce=mode)
    if o.get("--json"):
        print(json.dumps(d.to_dict(), indent=1, ensure_ascii=False))
    else:
        print(d.reason)
    if d.warning:
        print(f"arcaeon gate: {d.warning}", file=sys.stderr)
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
        if sub == "a2a":
            from arcaeon.prove import a2a_receiver
            return a2a_receiver.cli(rest)
        if sub == "mcp-after":
            from arcaeon.connect import docker_after
            return docker_after.main(rest)
        raise E._Usage(f"unknown subcommand {sub!r} (decide, packet, a2a, mcp-after)")
    except E._Usage as e:
        print(f"arcaeon gate: {e}\n{USAGE}", file=sys.stderr)
        return V.EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
