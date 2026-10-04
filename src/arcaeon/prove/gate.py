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

THE CHAIN ROW (D056). Once the pack is written, one row is appended to a
hash-chained ledger through `arcaeon.record.ledger.Ledger.append`, the same
writer the deal lane's rows go through (no second chain format):

    {"kind": "gate.evidence", "deal", "file_sha256", "verdict", "reason",
     "pack", "pack_digest", "pack_digest_of", "at"}   (+ "ts", "chain")

The ledger is `ledger=` (`--ledger`, e.g. the receiver's own deal tape) or by
default <record_dir>/DEAL-<deal>/gate/ledger.jsonl. `deal dispute` reads only
`deal.*` rows, so this row never enters a deal verdict. The pack digest
(PACK_DIGEST_OF) is sha256 over the UTF-8 text made of one line per regular
file in the pack, `<sha256 hex of its bytes><two spaces><path relative to the
pack, / separated>\n`, sorted by the path's UTF-8 bytes (sha256sum's format;
empty directories add nothing; a symlink or other non-regular entry is
refused). `verify_evidence_pack(pack_dir, row)` recomputes it: VERIFIED when
it matches, BROKEN when the pack changed, COULD NOT LOOK when the pack or the
row cannot be read. It says the pack still matches the row; that the row
itself was not rewritten is the chain's and a witness pin's job.

THE DISPUTE PACKET. `arcaeon gate packet` (arcaeon.prove.dispute_packet)
renders a refusal, from an evidence pack or from a decision's to_dict(), as
one page in markdown and JSON for a marketplace's dispute process.

Stdlib only (verify loads the [sign] backend itself). `decide` raises only on
an unknown action; anything else is an answer.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arcaeon import verdict as V
from arcaeon.prove import envelope as E

__all__ = ["ACTIONS", "ALLOW", "REFUSE", "RULES", "GateDecision", "decide", "resolve",
           "EVIDENCE_KIND", "CHAIN_KIND", "PACK_DIGEST_OF", "pack_digest",
           "verify_evidence_pack", "main"]

ACTIONS = ("read", "act", "pay", "irreversible")
ALLOW, REFUSE = "allow", "refuse"
#: verdict -> the actions it allows. Anything not listed is refused.
RULES = {V.VERIFIED: frozenset(ACTIONS), V.BROKEN: frozenset(),
         V.COULD_NOT_LOOK: frozenset({"read"})}
EVIDENCE_KIND = "arcaeon.gate.evidence/v1"
#: The ledger row kind a refusal's evidence pack is chained under (D056).
CHAIN_KIND = "gate.evidence"
#: Names the pack digest rule (module docstring, docs/VERBS.md `gate`).
PACK_DIGEST_OF = "sha256 over sorted '<sha256>  <relpath>' lines (sha256sum format), v1"
LEDGER_NAME = "ledger.jsonl"
_HEX64 = re.compile(r"[0-9a-f]{64}")

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
        return {"decision": self.decision, "action": self.action, "verdict": self.verdict,
                "reason": self.reason, "reasons": list(self.reasons),
                "could_not_check": dict(self.could_not_check) if self.could_not_check else None,
                "file": self.file, "envelope": self.envelope, "audience": self.audience,
                "deal": self.deal, "purpose": self.purpose, "signers": list(self.signers),
                "at": self.at, "evidence": self.evidence,
                "evidence_error": self.evidence_error,
                "chain_row": dict(self.chain_row) if self.chain_row else None,
                "chain_error": self.chain_error, "exit_code": self.exit_code,
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
          "at": _utc(now), "file": parts["file"], "envelope": parts["envelope"],
          "audience": d.audience, "purpose": d.purpose, "signers": list(signers), "limits": list(d.limits),
          "report": d.report}
    (out / "evidence.json").write_text(json.dumps(ev, indent=1, ensure_ascii=False) + "\n",
                                       encoding="utf-8")
    return out


def pack_digest(pack_dir: str | Path) -> str:
    """The pack digest (PACK_DIGEST_OF): sha256 over one `<sha256>  <relpath>\\n`
    line per regular file under `pack_dir`, sorted by the relpath's UTF-8 bytes.
    Raises ValueError on a symlink or other non-regular entry (the gate never
    writes one), OSError when the pack cannot be read."""
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
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            lines.append((rel.encode("utf-8"), f"{h.hexdigest()}  {rel}\n"))
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
    if row.get("pack_digest_of") not in (None, PACK_DIGEST_OF):
        out["reason"] = f"the row's digest rule {row.get('pack_digest_of')!r} is not one this reads"
        return out
    try:
        now = pack_digest(pack_dir)
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
    row["ts"] = row["at"]                     # as Deal._write: the returned row is the line
    row["chain"] = Ledger(ledger).append(row)
    return row


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


def decide(file: str | Path, *, action: str, audience: str | None,
           signers=(), deal: str | None = None, envelope: str | Path | None = None,
           purpose: str | None = None, record_dir: str | Path | None = None,
           ledger: str | Path | None = None, now: datetime | None = None) -> GateDecision:
    """allow or refuse `action` on `file`, from `envelope.verify`'s verdict.

    `file` is the handed file; `envelope` its sidecar (default: beside it).
    `audience`, `signers`, `deal` and `purpose` go to verify unchanged (a
    wrong one is BROKEN there). On BROKEN with a `deal`, an evidence pack is
    written under `record_dir` (default: the current directory) and one
    gate.evidence row is appended to `ledger` (default: the pack's
    DEAL-<deal>/gate/ledger.jsonl). Raises ValueError on an unknown action;
    otherwise never raises."""
    if action not in ACTIONS:
        raise ValueError(f"action must be one of {ACTIONS}, got {action!r}")
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
    d = GateDecision(decision=ALLOW if allowed else REFUSE, action=action, verdict=verdict,
                     reason=_reason(action, verdict, r, audience, deal), reasons=reasons,
                     could_not_check=cnc, file=str(file), envelope=str(env_path),
                     audience=audience, deal=deal, purpose=purpose, signers=list(signers),
                     at=_utc(now), report=r)
    if verdict == V.BROKEN and deal is not None:
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
            try:
                d.chain_row = _append_chain_row(
                    d, out, Path(ledger) if ledger is not None else out.parent / LEDGER_NAME,
                    now)
            except Exception as e:  # noqa: BLE001  the refusal stands either way
                d.chain_error = f"gate.evidence row not appended ({type(e).__name__}: {e})"
                d.reason += (f" The {CHAIN_KIND} row could not be appended "
                             f"({type(e).__name__}).")
    elif verdict == V.BROKEN:
        d.reason += " No deal id was given, so no evidence pack was written."
    return d


# --- CLI ------------------------------------------------------------------------

USAGE = """usage: arcaeon gate decide --envelope PATH --audience ID --signer DID
                           --action {read,act,pay,irreversible} [--deal ID]
                           [--purpose TEXT] [--file PATH] [--record-dir DIR]
                           [--ledger PATH] [--json]
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

With an evidence pack written, one `gate.evidence` row (deal, file sha256,
verdict, reason, the pack's digest, UTC time) is appended to the hash-chained
ledger --ledger names (default DIR/DEAL-<deal>/gate/ledger.jsonl), so a later
edit of the pack no longer matches the chain. `deal dispute` ignores the row.

Allow means the bytes are unchanged since the key you named sealed them and
are labeled for you and in date. It does not say the content is true or safe.

Prints one line, `allow <action>: ...` or `refuse <action>: ...` (--json:
the whole decision).
Exit codes: 0 allow, 1 refuse (BROKEN), 3 refuse (COULD NOT LOOK), 2 bad
usage. Spec and limits: docs/ENVELOPE.md.

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
         "--record-dir": "value", "--ledger": "value", "--json": "bool"}


def _decide_cli(argv: list[str]) -> int:
    pos, o = E._parse(argv, _SPEC)
    if pos:
        raise E._Usage(f"unexpected argument {pos[0]!r}")
    for need in ("--envelope", "--audience", "--signer", "--action"):
        if not o.get(need):
            raise E._Usage(f"decide needs {need}")
    if o["--action"] not in ACTIONS:
        raise E._Usage(f"--action must be one of {', '.join(ACTIONS)}")
    file, env_path = resolve(o["--envelope"], o.get("--file"))
    d = decide(file, envelope=env_path, action=o["--action"], audience=o["--audience"],
               signers=o["--signer"], deal=o.get("--deal"), purpose=o.get("--purpose"),
               record_dir=o.get("--record-dir"), ledger=o.get("--ledger"))
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
