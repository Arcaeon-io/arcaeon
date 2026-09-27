# SPDX-License-Identifier: MIT
"""arcaeon.record.handshake: two agents countersign any agreement (roadmap N23).

    from arcaeon.record import handshake as H
    offer = H.propose("a.jsonl", {"task": "summarize q3", "fee": "4.00"},
                      agent="agent-a", to="agent-b")
    acceptance = H.accept("b.jsonl", offer, agent="agent-b")
    report = H.verify("a.jsonl", "b.jsonl")      # AGREED TERMS

WHAT IT ANSWERS
---------------
The deal lane (arcaeon.record.deal) records a sale: a buyer and a seller each
write the same commit on their own ledger. A handshake is that commit with the
sale taken out: any two agents, any terms (a JSON object), each side keeping
its own ledger. `verify` lines the two ledgers up and answers in one of four
words:

  AGREED TERMS     the proposal on one ledger and the acceptance on the other
                   carry the same terms (canonical JSON digest). Exit 0.
  DIFFERENT TERMS  both are there and the terms differ; the fields are named.
                   Also: one side proposed again after the other accepted, a
                   row's step_digest no longer matches the body it carries, or
                   the acceptance is not bound to the proposal row it lines up
                   with (field `proposal_hash`: it cites another row, or a
                   position that holds a different row). Exit 1.
  MISSING          one half is not there: a proposal nobody accepted, an
                   acceptance with no proposal, an acceptance written on the
                   proposer's own ledger instead of the other side's, or an
                   acceptance citing a proposal row the ledger does not hold.
                   Exit 1.
  COULD NOT LOOK   a ledger is missing, unreadable, or its chain is broken with
                   the terms still agreeing (an edited ledger is not agreement).
                   Never green. Exit 3.

THE ROWS. Written by `Deal._write`, the one row writer `Deal.commit` writes
through, so the row format is the deal lane's, unchanged:

  kind "deal.handshake.propose"  party "proposer"  deal = handshake id
      shared = {handshake, proposer, to, terms}; step_digest = digest_json(shared)
  kind "deal.handshake.accept"   party "acceptor"  deal = handshake id
      shared = the proposal's shared body, copied, never rebuilt;
      beside it: agent (the acceptor's name), proposal_chain (the proposal
      row's hash, its `chain`) and proposal_row (its position on the
      proposer's ledger), both from the offer and both required: `verify`
      holds the acceptance to exactly that row (KH7R).

Because the rows are deal rows, `arcaeon deal show LEDGER --deal h-...` prints
them. `deal dispute` on a handshake id answers COULD NOT LOOK (a handshake step
is not a sale step); `deal handshake verify` is the check for these.

THE WIRE. `propose` returns an offer (`arcaeon-handshake-proposal/1`) for the
proposer to hand to the other agent any way it likes (the serve routes
`POST /v1/handshake/propose|accept|verify` are one way). `accept` refuses an
offer whose `terms_digest` does not match its own terms, so an offer altered
in transit is never countersigned.

WHAT IT DOES NOT DO
-------------------
It never sends anything: the two agents carry the offer between them. It does
not interpret the terms. It adds no row format and no reserved key. Its two
new words, AGREED TERMS and DIFFERENT TERMS, are held here with their exit
codes (EXIT_BY_WORD) until they join arcaeon.verdict.

REUSED, NOT COPIED. Rows are written by `Deal._write`; ledgers are read and
their chains checked by the deal lane's `_load_side` (reconcile's `_Tape` and
`_cannot_read` under it); field names come from the deal lane's `_diff`.

Stdlib only. Never raises from `verify()`: that is an answer too.
"""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from arcaeon import verdict as _v
from arcaeon.prove.reconcile import LIMITS as _RECONCILE_LIMITS
from arcaeon.record.deal import Deal, _diff, _load_side
from arcaeon.record.row import digest_json
from arcaeon.record.row import loads as _loads

__all__ = ["AGREED_TERMS", "DIFFERENT_TERMS", "MISSING", "COULD_NOT_LOOK", "WORDS",
           "EXIT_BY_WORD", "exit_for", "KIND_PROPOSE", "KIND_ACCEPT", "PROPOSAL_KIND",
           "ACCEPTANCE_KIND", "propose", "accept", "verify", "HandshakeReport", "LIMITS",
           "api_propose", "api_accept", "api_verify", "main"]

AGREED_TERMS = "AGREED TERMS"
DIFFERENT_TERMS = "DIFFERENT TERMS"
MISSING = _v.MISSING
COULD_NOT_LOOK = _v.COULD_NOT_LOOK
#: The four words `verify` answers in, in the order a reader meets them.
WORDS = (AGREED_TERMS, DIFFERENT_TERMS, MISSING, COULD_NOT_LOOK)
#: The one table arcaeon.verdict keeps, for the two words it does not hold yet.
EXIT_BY_WORD = {AGREED_TERMS: _v.EXIT_GOOD, DIFFERENT_TERMS: _v.EXIT_BAD,
                MISSING: _v.EXIT_BAD, COULD_NOT_LOOK: _v.EXIT_COULD_NOT_LOOK}

KIND_PROPOSE = "deal.handshake.propose"
KIND_ACCEPT = "deal.handshake.accept"
PROPOSAL_KIND = "arcaeon-handshake-proposal/1"
ACCEPTANCE_KIND = "arcaeon-handshake-acceptance/1"
REPORT_KIND = "arcaeon-handshake-verify/1"
_NO_DEAL = "\x00handshake-reads-every-row"     # a deal id no row carries

LIMITS = [
    "AGREED TERMS means the two ledgers carry the same terms; two ledgers run by "
    "one party who wants a lie can agree on it.",
    "A step neither side recorded leaves no row; the handshake records what each "
    "side wrote, not what either side then did.",
    "Digests compare content (canonical JSON), not bytes: a meaning-preserving "
    "re-serialization in transit is AGREED TERMS by design.",
    _RECONCILE_LIMITS[3],
    "Times are each writer's own ledger ts. The handshake sends nothing and "
    "interprets no term.",
]


def exit_for(word: str) -> int:
    """This lane's exit code for a word; anything else goes to arcaeon.verdict
    (an unknown word is COULD NOT LOOK there, never green)."""
    return EXIT_BY_WORD.get(word, _v.exit_for(word))


# -- writing -------------------------------------------------------------------

class _Side(Deal):
    """One agent's side of one handshake. The deal writer, reused: `Deal._write`
    is the path `Deal.commit` writes through. Only `party` differs: a handshake
    role instead of buyer / seller."""

    def __init__(self, ledger, role: str, handshake_id: str):
        super().__init__(ledger, "buyer", handshake_id)
        self.party = role


def _name(v: Any, what: str) -> str | None:
    if v is None:
        return None
    if not isinstance(v, str) or not v.strip():
        raise ValueError(f"{what} must be a non-empty string")
    return v


def _position(path: str | Path, chain: str) -> int | None:
    """The 1-indexed position of the last row whose `chain` is `chain`, counted
    as chain_at / verify_file count rows (parseable JSON objects only)."""
    n, at = 0, None
    for raw in Path(path).read_text(encoding="utf-8", errors="replace").split("\n"):
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = _loads(raw)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        n += 1
        if row.get("chain") == chain:
            at = n
    return at


def _is_row_number(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v > 0


def propose(ledger: str | Path, terms: dict, *, agent: str | None = None,
            to: str | None = None, handshake: str | None = None,
            ts: str | None = None) -> dict:
    """Write the proposal on the proposer's own ledger; return the offer to
    hand to the other agent."""
    if not isinstance(terms, dict):
        raise ValueError("terms must be a JSON object")
    agent, to = _name(agent, "agent"), _name(to, "to")
    hid = _name(handshake, "handshake id") or "h-" + secrets.token_hex(6)
    shared = {"handshake": hid, "proposer": agent, "to": to, "terms": terms}
    digest = digest_json(shared)                       # raises ValueError on a bad body
    row = _Side(ledger, "proposer", hid)._write("handshake.propose", shared, None, ts)
    return {"kind": PROPOSAL_KIND, "handshake": hid, "proposer": agent, "to": to,
            "terms": terms, "terms_digest": digest, "proposer_chain": row["chain"],
            "proposer_row": _position(ledger, row["chain"]), "ts": row["ts"]}


def accept(ledger: str | Path, proposal: dict, *, agent: str | None = None,
           ts: str | None = None) -> dict:
    """Countersign an offer on the acceptor's own ledger. Refuses (ValueError)
    an offer that is not well formed, whose terms_digest does not match its
    terms, that names another agent in `to`, or that does not cite the
    proposal row it came from (proposer_chain and proposer_row)."""
    if not isinstance(proposal, dict):
        raise ValueError("the proposal must be a JSON object")
    if proposal.get("kind", PROPOSAL_KIND) != PROPOSAL_KIND:
        raise ValueError(f"the proposal kind must be {PROPOSAL_KIND!r}")
    hid = _name(proposal.get("handshake"), "the proposal's handshake id")
    if hid is None:
        raise ValueError("the proposal carries no handshake id")
    if not isinstance(proposal.get("terms"), dict):
        raise ValueError("the proposal's terms must be a JSON object")
    agent = _name(agent, "agent")
    to = proposal.get("to")
    if to is not None and agent is not None and agent != to:
        raise ValueError(f"the proposal is to {to!r}, not {agent!r}")
    shared = {"handshake": hid, "proposer": proposal.get("proposer"), "to": to,
              "terms": proposal["terms"]}
    digest = digest_json(shared)
    if proposal.get("terms_digest") is not None and proposal["terms_digest"] != digest:
        raise ValueError("the proposal's terms_digest does not match its terms: it was "
                         "changed after it was proposed; nothing was countersigned")
    if not isinstance(proposal.get("proposer_chain"), str) or not proposal["proposer_chain"]:
        raise ValueError("the proposal carries no proposer_chain: an acceptance must cite "
                         "the proposal row it countersigns")
    if not _is_row_number(proposal.get("proposer_row")):
        raise ValueError("the proposal carries no proposer_row: an acceptance must cite "
                         "the proposal row's position on the proposer's ledger")
    private = {"agent": agent if agent is not None else to,
               "proposal_chain": proposal["proposer_chain"],
               "proposal_row": proposal["proposer_row"]}
    row = _Side(ledger, "acceptor", hid)._write("handshake.accept", shared, private, ts)
    return {"kind": ACCEPTANCE_KIND, "handshake": hid, "acceptor": private["agent"],
            "terms_digest": digest, "acceptor_chain": row["chain"],
            "proposer_chain": private["proposal_chain"],
            "proposer_row": private["proposal_row"], "ts": row["ts"]}


# -- the verdict ---------------------------------------------------------------

@dataclass
class HandshakeReport:
    verdict: str
    reason: str = ""
    handshake: str | None = None
    a: str = ""
    b: str = ""
    results: list = field(default_factory=list)
    counts: dict = field(default_factory=dict)
    limits: list = field(default_factory=lambda: list(LIMITS))
    looked_for: str | None = None
    where: str | None = None
    reason_word: str | None = None

    @property
    def exit_code(self) -> int:
        return exit_for(self.verdict)

    @property
    def summary(self) -> str:
        return f"{self.verdict}: {self.reason}" if self.reason else self.verdict

    def __bool__(self) -> bool:
        return self.verdict == AGREED_TERMS

    def to_dict(self) -> dict:
        return {"kind": REPORT_KIND, "verdict": self.verdict, "summary": self.summary,
                "reason": self.reason, "handshake": self.handshake, "a": self.a, "b": self.b,
                "results": [dict(r) for r in self.results], "counts": dict(self.counts),
                "limits": list(self.limits), "exit_code": self.exit_code,
                "looked_for": self.looked_for, "where": self.where,
                "reason_word": self.reason_word}


@dataclass
class _Read:
    name: str
    path: Path
    rows: list = field(default_factory=list)        # (row number, row), handshake rows
    chains: dict = field(default_factory=dict)      # row number -> that row's chain, every row
    cnl: dict | None = None                         # unreadable: the four keys
    broken: str | None = None                       # chain broken: the reason


def _read(name: str, path: str | Path) -> _Read:
    """One ledger, read and chain-checked by the deal lane's own reader."""
    r = _Read(name, Path(path))
    cnl: list = []
    t, _ = _load_side(f"ledger {name}", r.path, _NO_DEAL, cnl, [])
    if t.cnl and not t.broken:
        r.cnl = dict(t.cnl_detail)
        return r
    if t.broken:
        # The chain says this ledger was edited. Its rows are still read so an
        # edit to the terms is named (DIFFERENT TERMS), never hidden behind a
        # COULD NOT LOOK; agreeing terms on it stay COULD NOT LOOK.
        # A line that does not parse is unreadable, not an edit to compare.
        r.broken = t.cnl
        for raw in r.path.read_text(encoding="utf-8", errors="replace").split("\n"):
            if not raw.strip():
                continue
            try:
                row = _loads(raw.strip())
            except ValueError:
                row = None
            if not isinstance(row, dict):
                r.cnl, r.broken = dict(t.cnl_detail), None
                return r
            t.rows.append(row)
    for n, row in enumerate(t.rows, 1):
        if isinstance(row, dict):
            r.chains[n] = row.get("chain")
        if isinstance(row, dict) and row.get("kind") in (KIND_PROPOSE, KIND_ACCEPT):
            r.rows.append((n, row))
    return r


def _of(side: _Read, hid: str, kind: str) -> list:
    return [(n, row) for n, row in side.rows if row.get("deal") == hid
            and row.get("kind") == kind]


def _self_ok(row: dict) -> bool:
    try:
        return isinstance(row.get("shared"), dict) and \
            digest_json(row["shared"]) == row.get("step_digest")
    except ValueError:
        return False


def _binding(P: _Read, np_: int, O: _Read, nq: int, q: dict) -> tuple | None:
    """None when the acceptance cites exactly the proposal row it is lined up
    with (hash and position); else (word, reason)."""
    cited, at = q.get("proposal_chain"), q.get("proposal_row")
    me = f"ledger {O.name} row {nq}"
    if not isinstance(cited, str) or not _is_row_number(at):
        return DIFFERENT_TERMS, (f"{me} does not cite the proposal row it accepts (it needs "
                                 f"proposal_chain and proposal_row)")
    if at not in P.chains:
        return MISSING, (f"{me} cites ledger {P.name} row {at}, and ledger {P.name} holds no "
                         f"row {at}")
    if P.chains[at] != cited:
        return DIFFERENT_TERMS, (f"{me} cites proposal hash {cited} at ledger {P.name} row "
                                 f"{at}, but that row's hash is {P.chains[at]}")
    if at != np_:
        return DIFFERENT_TERMS, (f"{me} cites ledger {P.name} row {at}, not the proposal it "
                                 f"is lined up with (row {np_}): the acceptance belongs to "
                                 f"another proposal")
    return None


def _one(hid: str, a: _Read, b: _Read) -> dict:
    res: dict = {"handshake": hid, "verdict": None, "reason": "", "proposer_ledger": None,
                 "acceptor_ledger": None, "proposer_row": None, "acceptor_row": None,
                 "fields": [], "position": []}
    sides = (a, b)
    props = {s.name: _of(s, hid, KIND_PROPOSE) for s in sides}
    accs = {s.name: _of(s, hid, KIND_ACCEPT) for s in sides}
    pair = next(((p, o) for p in sides for o in sides
                 if p is not o and props[p.name] and accs[o.name]), None)
    if pair is None:
        res["verdict"] = MISSING
        res["position"] += [f"ledger {s.name}: {s.broken}" for s in sides if s.broken]
        if not any(props.values()):
            holder = next(s.name for s in sides if accs[s.name])
            res["reason"] = (f"{hid} is accepted on ledger {holder} and proposed on "
                             f"neither ledger")
        elif not any(accs.values()):
            holder = next(s.name for s in sides if props[s.name])
            res["reason"] = (f"{hid} is proposed on ledger {holder} and never accepted on "
                             f"the other ledger")
        else:
            holder = next(s.name for s in sides if props[s.name])
            res["reason"] = (f"{hid}'s acceptance is on ledger {holder}, the proposer's own; "
                             f"the other ledger holds no acceptance")
        return res
    P, O = pair
    (np_, p), (nq, q) = props[P.name][-1], accs[O.name][-1]
    res.update(proposer_ledger=P.name, acceptor_ledger=O.name, proposer_row=np_,
               acceptor_row=nq, proposer=p.get("shared", {}).get("proposer")
               if isinstance(p.get("shared"), dict) else None, acceptor=q.get("agent"))
    if len(props[P.name]) > 1:
        res["position"].append(f"ledger {P.name} holds {len(props[P.name])} proposals for "
                               f"{hid}; the last (row {np_}) is lined up")
    bind = _binding(P, np_, O, nq, q)
    if bind:
        res["position"].append(bind[1])
    try:
        same = digest_json(p.get("shared")) == digest_json(q.get("shared"))
    except ValueError:
        same = False
    broken = [s for s in (P, O) if s.broken]
    for s in broken:
        res["position"].append(f"ledger {s.name}: {s.broken}")
    if not same:
        res["fields"] = _diff(p.get("shared"), q.get("shared"))
        res["verdict"] = DIFFERENT_TERMS
        res["reason"] = (f"{hid}: ledger {P.name} row {np_} and ledger {O.name} row {nq} "
                         f"differ in {', '.join(res['fields']) or 'their shared body'}")
    elif not (_self_ok(p) and _self_ok(q)):
        bad = f"ledger {P.name} row {np_}" if not _self_ok(p) else f"ledger {O.name} row {nq}"
        res["verdict"] = DIFFERENT_TERMS
        res["fields"] = ["step_digest"]
        res["reason"] = (f"{hid}: {bad} carries a step_digest that does not match the terms "
                         f"it holds; the row was edited after it was written")
    elif bind:
        res["verdict"], res["fields"] = bind[0], ["proposal_hash"]
        res["reason"] = f"{hid}: {bind[1]}"
    elif broken:
        res["verdict"] = COULD_NOT_LOOK
        res["reason"] = (f"{hid}: the terms agree, but ledger {broken[0].name}'s chain is "
                         f"broken; agreement on an edited ledger is not agreement")
        res.update(_v.could_not_look("an intact chain", str(broken[0].path), "unreadable",
                                     res["reason"]))
    else:
        res["verdict"] = AGREED_TERMS
        res["reason"] = (f"{hid}: ledger {P.name} row {np_} and ledger {O.name} row {nq} "
                         f"carry the same terms")
    return res


def verify(a: str | Path, b: str | Path, handshake: str | None = None) -> HandshakeReport:
    """Line up two agents' ledgers. With `handshake`, that one; without, every
    handshake either ledger holds."""
    try:
        return _verify(a, b, handshake)
    except Exception as e:  # noqa: BLE001  a verdict, never a traceback
        why = f"could not finish: {type(e).__name__}"
        return HandshakeReport(COULD_NOT_LOOK, why, handshake, str(a), str(b),
                               looked_for="both ledgers", where=f"{a}, {b}",
                               reason_word="unreadable")


def _verify(a, b, handshake) -> HandshakeReport:
    A, B = _read("a", a), _read("b", b)
    for s in (A, B):
        if s.cnl:
            d = s.cnl
            return HandshakeReport(COULD_NOT_LOOK, d["reason"], handshake, str(a), str(b),
                                   looked_for=d["looked_for"], where=d["where"],
                                   reason_word=d["reason_word"])
    seen: list[str] = []
    for s in (A, B):
        for _, row in s.rows:
            if isinstance(row.get("deal"), str) and row["deal"] not in seen:
                seen.append(row["deal"])
    ids = [handshake] if handshake else seen
    if not ids or (handshake and handshake not in seen):
        what = f"handshake {handshake}" if handshake else "a handshake row"
        why = f"neither ledger holds {what}"
        if A.broken or B.broken:
            why += f" ({A.broken or B.broken})"
        return HandshakeReport(COULD_NOT_LOOK, why, handshake, str(a), str(b),
                               looked_for=what, where=f"{a}, {b}",
                               reason_word="name_not_found")
    results = [_one(h, A, B) for h in ids]
    counts = {w: sum(1 for r in results if r["verdict"] == w) for w in WORDS}
    worst = next(w for w in (DIFFERENT_TERMS, MISSING, COULD_NOT_LOOK, AGREED_TERMS)
                 if counts[w])
    first = next(r for r in results if r["verdict"] == worst)
    rep = HandshakeReport(worst, first["reason"] if len(results) == 1 else
                          f"{counts[worst]} of {len(results)} handshakes: {first['reason']}",
                          handshake or (ids[0] if len(ids) == 1 else None), str(a), str(b),
                          results, counts)
    if worst == COULD_NOT_LOOK:
        rep.looked_for, rep.where = first["looked_for"], first["where"]
        rep.reason_word = first["reason_word"]
    return rep


# -- one JSON shape for the CLI and the HTTP routes ----------------------------

def _usage(msg: str) -> dict:
    return {"exit": _v.EXIT_USAGE, "error": msg}


def api_propose(body: dict) -> dict:
    """{ledger, terms, agent?, to?, handshake?} -> {proposal, exit}."""
    if not isinstance(body, dict) or not isinstance(body.get("ledger"), str) or not body["ledger"]:
        return _usage("missing required field 'ledger'")
    try:
        offer = propose(body["ledger"], body.get("terms"), agent=body.get("agent"),
                        to=body.get("to"), handshake=body.get("handshake"))
    except ValueError as e:
        return _usage(f"handshake propose: {e}")
    except OSError as e:
        return _cannot_write(body["ledger"], e)
    return {"proposal": offer, "exit": _v.EXIT_GOOD}


def api_accept(body: dict) -> dict:
    """{ledger, proposal, agent?} -> {acceptance, exit}."""
    if not isinstance(body, dict) or not isinstance(body.get("ledger"), str) or not body["ledger"]:
        return _usage("missing required field 'ledger'")
    try:
        got = accept(body["ledger"], body.get("proposal"), agent=body.get("agent"))
    except ValueError as e:
        return _usage(f"handshake accept: {e}")
    except OSError as e:
        return _cannot_write(body["ledger"], e)
    return {"acceptance": got, "exit": _v.EXIT_GOOD}


def api_verify(body: dict) -> dict:
    """{a, b, handshake?} -> the report plus exit."""
    if not isinstance(body, dict):
        return _usage("the request body must be a JSON object")
    for k in ("a", "b"):
        if not isinstance(body.get(k), str) or not body[k]:
            return _usage(f"missing required field '{k}'")
    h = body.get("handshake")
    if h is not None and (not isinstance(h, str) or not h):
        return _usage("handshake must be a non-empty string")
    rep = verify(body["a"], body["b"], h)
    return {**rep.to_dict(), "exit": rep.exit_code}


def _cannot_write(ledger: str, e: OSError) -> dict:
    reason = f"could not write the ledger ({e.strerror or type(e).__name__})"
    return {"verdict": COULD_NOT_LOOK, "exit": _v.EXIT_COULD_NOT_LOOK, "reason": reason,
            **_v.could_not_look("a writable ledger", ledger, "unreadable", reason)}


# -- `arcaeon deal handshake` ---------------------------------------------------

USAGE = """usage: arcaeon deal handshake <propose|accept|verify> ...

Two agents countersign any agreement, each on its own ledger.
  propose <ledger> (--terms JSON | --terms-file FILE) [--agent NAME] [--to NAME] [--id ID]
          writes the proposal; prints the offer (JSON) to hand to the other agent
  accept  <ledger> (--proposal JSON | --proposal-file FILE) [--agent NAME]
          countersigns the offer on this ledger; prints the acceptance (JSON)
  verify  <ledger_a> <ledger_b> [--id ID] [--json]

verify exits 0 AGREED TERMS, 1 DIFFERENT TERMS or MISSING, 3 COULD NOT LOOK,
2 bad usage. propose / accept exit 0, 2 on a refused offer, 3 when the ledger
cannot be written."""


def _parser(cmd: str):
    import argparse
    ap = argparse.ArgumentParser(prog=f"arcaeon deal handshake {cmd}")
    if cmd == "verify":
        ap.add_argument("a")
        ap.add_argument("b")
        ap.add_argument("--id")
        ap.add_argument("--json", action="store_true")
        return ap
    ap.add_argument("ledger")
    ap.add_argument("--agent")
    what = "terms" if cmd == "propose" else "proposal"
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument(f"--{what}")
    g.add_argument(f"--{what}-file")
    if cmd == "propose":
        ap.add_argument("--to")
        ap.add_argument("--id")
    return ap


def _json_arg(text: str | None, path: str | None, what: str):
    try:
        raw = Path(path).read_text(encoding="utf-8") if path else text
        return json.loads(raw)
    except OSError as e:
        raise ValueError(f"cannot read the {what} file ({e.strerror or type(e).__name__})")
    except ValueError:
        raise ValueError(f"the {what} is not JSON") from None


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return _v.EXIT_GOOD if argv else _v.EXIT_USAGE
    cmd, rest = argv[0], argv[1:]
    if cmd not in ("propose", "accept", "verify"):
        print(f"arcaeon deal handshake: unknown step {cmd!r}\n\n{USAGE}")
        return _v.EXIT_USAGE
    try:
        a = _parser(cmd).parse_args(rest)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else _v.EXIT_USAGE
    if cmd == "verify":
        res = api_verify({"a": a.a, "b": a.b, "handshake": a.id})
        if a.json:
            print(json.dumps(res, indent=1, ensure_ascii=False))
        else:
            print(res.get("summary", res.get("error", "")))
            for r in res.get("results", []):
                if len(res["results"]) > 1:
                    print(f"  {r['verdict']}: {r['reason']}")
                for p in r.get("position", []):
                    print(f"  {p}")
        return res["exit"]
    try:
        if cmd == "propose":
            body = {"ledger": a.ledger, "agent": a.agent, "to": a.to, "handshake": a.id,
                    "terms": _json_arg(a.terms, a.terms_file, "terms")}
        else:
            body = {"ledger": a.ledger, "agent": a.agent,
                    "proposal": _json_arg(a.proposal, a.proposal_file, "proposal")}
    except ValueError as e:
        print(f"arcaeon deal handshake {cmd}: {e}")
        return _v.EXIT_USAGE
    res = api_propose(body) if cmd == "propose" else api_accept(body)
    if res["exit"] == _v.EXIT_GOOD:
        print(json.dumps(res["proposal" if cmd == "propose" else "acceptance"],
                         ensure_ascii=False))
    else:
        print(res.get("error") or res.get("reason"))
    return res["exit"]
