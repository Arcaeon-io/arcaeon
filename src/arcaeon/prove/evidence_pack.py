# SPDX-License-Identifier: MIT
"""arcaeon.prove.evidence_pack: one folder for one agent and one window.

Spec: memory/EVIDENCE_PACK_SPEC_2026-09-27.md (sections 4 and 7). The pack is
built over `arcaeon.prove.audit.export_bundle`, so `records.jsonl` is the whole
ledger, byte for byte, and `integrity.json` / `witness.json` /
`ARTICLE_12_SUMMARY.md` are exactly what `arcaeon audit export` writes.

What a pack is evidence toward: the logging duties in the EU AI Act. What it
is not: a claim of compliance with them, or a claim that the agent behaved
well. It shows what was written was not changed after it was pinned.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arcaeon import verdict as V

__all__ = ["build_pack", "select_window", "parse_when", "PackUsageError",
           "PACK_SCHEMA", "MANIFEST", "CNL_FILE", "README", "DOES_NOT_SHOW",
           "README_DOES_NOT_SHOW",
           "OPERATOR_AT_T"]

#: The evidence-pack manifest schema. 1 is the first (K053).
PACK_SCHEMA = 1
#: The manifest's file name. Every OTHER file in the pack is hashed in it.
MANIFEST = "manifest.json"
#: Every COULD NOT LOOK the build reached, one entry each; `[]` when none (K054).
CNL_FILE = "could_not_look.json"
#: The one-page reader's note inside the pack (K055).
README = "README.md"
#: The manifest's own hash, beside it (K06xR review 2): `sha256sum -c` format,
#: "<64 hex>  manifest.json". It cannot sit inside the manifest it hashes.
MANIFEST_SHA = "manifest.sha256"
#: With --format aat (K064): the whole records.jsonl as draft-sharif-agent-
#: audit-trail records, and the fields it leaves out.
AAT_FILE = "aat.jsonl"
AAT_GAPS_FILE = "aat_gaps.json"
#: With --deal ID (K065): what arcaeon.record.deal.pack writes, at the top of
#: the pack beside the other files, each hashed in the manifest.
DEAL_FILES = ("verdict.json", "timeline.md", "buyer.deal.jsonl", "seller.deal.jsonl")
#: What a pack does not show, printed verbatim in README.md: the bullets of
#: spec section 6 ("What must not be claimed"), word for word. Kept here, one
#: list, so the page and any test read the same words.
DOES_NOT_SHOW = (
    'Not "Article 12 compliant", "AI Act ready" or "conformant to" either '
    'standard. We say "evidence toward", once, on page one.',
    "Not that the pack proves the agent behaved well. It proves what was "
    "written was not changed after pinning.",
    'Not "independent witness". One witness, we operate it, `independence` '
    "reads `self_asserted` unless proven otherwise.",
    "Not a known `operator_at_t`. It is UNKNOWN until the custody record (P7) "
    "is published and anchored.",
    "Not AAT-conformant. We emit a subset, with a re-derived chain, and list "
    "what is missing.",
    "Not six-month retention by us. Retention is the holder's.",
)
#: The same bullets as a customer reads them in README.md: identical except
#: that the two internal references are spelled out for a stranger (the
#: roadmap code "(P7)" is dropped, since "the custody record" already names
#: it, and "by us" names who "us" is). The constant above stays verbatim.
_README_WORDING = ((" (P7)", ""), ("by us.", "by the operator of the hosted witness."))


def _for_readme(bullet: str) -> str:
    for old, new in _README_WORDING:
        bullet = bullet.replace(old, new)
    return bullet


README_DOES_NOT_SHOW = tuple(_for_readme(b) for b in DOES_NOT_SHOW)
#: Who operated the witness at pin time. UNKNOWN until a custody record
#: is published and anchored (spec section 6): never a guess.
OPERATOR_AT_T = "UNKNOWN"


class PackUsageError(ValueError):
    """The pack could not start on what it was given (exit 2)."""


def _cnl_result(out: Path | None, looked_for: str, where: str, reason_word: str,
                reason: str) -> dict:
    res = {"verdict": V.COULD_NOT_LOOK, "exit": V.EXIT_COULD_NOT_LOOK,
           "out": str(out) if out is not None else None}
    res.update(V.could_not_look(looked_for, where, reason_word, reason))
    return res


def parse_when(text: str | None) -> datetime | None:
    """An ISO 8601 timestamp as an aware datetime (no zone means UTC), or None.
    Raises PackUsageError on text that is not ISO 8601."""
    if text is None or text == "":
        return None
    t = text.strip()
    if t.endswith(("Z", "z")):
        t = t[:-1] + "+00:00"
    try:
        d = datetime.fromisoformat(t)
    except ValueError:
        raise PackUsageError(f"{text!r} is not an ISO 8601 timestamp") from None
    return d if d.tzinfo is not None else d.replace(tzinfo=timezone.utc)


def _lines(raw: bytes) -> list[bytes]:
    """The ledger's lines, split on LF only, in order; line N of the file is
    index N-1. Only the LF split on is removed: a CRLF line keeps its CR, so
    a window row stays byte-identical to its record on a CRLF ledger (the JSON
    parser reads the CR as whitespace)."""
    parts = raw.split(b"\n")
    if parts and parts[-1] == b"":
        parts.pop()
    return parts


def select_window(raw: bytes, *, agent: str | None = None,
                  since: datetime | None = None,
                  until: datetime | None = None) -> tuple[list[dict], list[int]]:
    """The rows of `raw` for one agent and one window.

    `agent` matches a row's `agent` or `system_id`. `since` / `until` are
    inclusive bounds on the row's `ts`. Returns (window, unplaced): `window` is
    one {"line": N, "raw": <the line's exact text>} per selected row, N the
    1-based line number in the ledger; `unplaced` lists the line numbers of
    rows for the agent whose `ts` could not be read while a time bound was
    set (left out of the window, and named, never guessed into it). Lines
    that are not a JSON object are never in the window.
    """
    window: list[dict] = []
    unplaced: list[int] = []
    for n, line in enumerate(_lines(raw), start=1):
        try:
            text = line.decode("utf-8")
            row = json.loads(text)
        except (UnicodeDecodeError, ValueError):
            continue
        if not isinstance(row, dict):
            continue
        if agent is not None and agent not in (row.get("agent"), row.get("system_id")):
            continue
        if since is not None or until is not None:
            try:
                ts = parse_when(row.get("ts")) if isinstance(row.get("ts"), str) else None
            except PackUsageError:
                ts = None
            if ts is None:
                unplaced.append(n)
                continue
            if (since is not None and ts < since) or (until is not None and ts > until):
                continue
        window.append({"line": n, "raw": text})
    return window, unplaced


def build_pack(ledger: str | Path, out: str | Path, *,
               system_id: str = "", provider: str = "",
               witness: Any = None, witness_namespace: str | None = None,
               agent: str | None = None, since: str | None = None,
               until: str | None = None, formats: tuple[str, ...] = (),
               deal: str | None = None, deal_buyer: str | Path | None = None,
               deal_seller: str | Path | None = None) -> dict:
    """Build an evidence pack from `ledger` into the empty folder `out`.

    Returns a result dict with `verdict` (one arcaeon.verdict word), an integer
    `exit` and `out`. Raises PackUsageError when `out` is a non-empty folder or
    a file (a pack never writes over an older pack's files), and on a
    `since` / `until` that is not ISO 8601 or runs backwards.

    `agent`, `since`, `until` select the window (see select_window) written to
    `window.jsonl`. An empty window is COULD NOT LOOK, `reason_word: "empty"`:
    the pack was built, and it holds nothing for that agent and window.

    `formats` may name "aat": the whole records.jsonl is then also written as
    aat.jsonl (the agent-audit-trail subset, with its own JCS chain beside our
    original `chain`) plus aat_gaps.json, both hashed in the manifest and
    recomputed from records.jsonl by `evidence-pack verify`.

    `deal` folds one deal's dispute in (roadmap N3) through
    arcaeon.record.deal.pack: verdict.json, timeline.md and each side's deal
    rows, listed in the manifest's `deal` block with the dispute verdict. The
    two tapes are `deal_buyer` and `deal_seller`; the one left out is this
    pack's ledger. The dispute is one more check: MATCHED counts as VERIFIED,
    COULD NOT LOOK as COULD NOT LOOK (never exit 0), any other word as BROKEN.
    """
    from arcaeon.prove.audit import export_bundle

    ledger = Path(ledger)
    out = Path(out)
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise PackUsageError(f"{out} exists and is not an empty folder; "
                             "a pack is written into a new or empty folder")
    if deal is not None:
        if not isinstance(deal, str) or not deal:
            raise PackUsageError("--deal needs a deal id")
        if deal_buyer is None and deal_seller is None:
            raise PackUsageError("--deal needs the other side's tape: --buyer B or "
                                 "--seller S (the one left out is --ledger)")
    elif deal_buyer is not None or deal_seller is not None:
        raise PackUsageError("--buyer / --seller are only read with --deal")
    unknown = sorted(set(formats) - {"aat"})
    if unknown:
        raise PackUsageError(f"unknown --format {unknown}; the one extra format is aat")
    t_from, t_to = parse_when(since), parse_when(until)
    if t_from is not None and t_to is not None and t_from > t_to:
        raise PackUsageError(f"--from {since!r} is after --to {until!r}")
    if not ledger.is_file():
        return _cnl_result(None, "a ledger file", str(ledger), "missing",
                           "the ledger named was not found, so there is nothing to pack")

    export_bundle(ledger, out, system_id=system_id, provider=provider,
                  witness=witness, witness_namespace=witness_namespace)
    raw = (out / "records.jsonl").read_bytes()
    window, unplaced = select_window(raw, agent=agent, since=t_from, until=t_to)
    with (out / "window.jsonl").open("wb") as fh:
        for w in window:
            fh.write((json.dumps(w, ensure_ascii=False) + "\n").encode("utf-8"))

    integrity = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
    word = integrity.get("verdict") or V.COULD_NOT_LOOK
    if word not in V.EXIT_BY_WORD:
        word = V.COULD_NOT_LOOK
    res = {"verdict": word, "exit": V.EXIT_BY_WORD[word], "out": str(out),
           "finding": integrity.get("finding"),
           "window": {"agent": agent, "from": since, "to": until,
                      "rows": len(window),
                      "first_line": window[0]["line"] if window else None,
                      "last_line": window[-1]["line"] if window else None,
                      "unplaced_lines": unplaced}}
    if not window and word != V.BROKEN:
        # A BROKEN chain outranks an empty window: a bad finding is never
        # softened into a could-not-look.
        res.update({"verdict": V.COULD_NOT_LOOK, "exit": V.EXIT_COULD_NOT_LOOK})
        res.update(V.could_not_look(
            f"rows for agent {agent!r} from {since!r} to {until!r}", "records.jsonl",
            "empty", "no row in the ledger matches that agent and window"))
    checks = _checks(integrity, window, unplaced, agent, since, until)
    aat = None
    if "aat" in formats:
        from arcaeon.prove.aat_export import (AAT_CHAIN_ALGORITHM, WHICH_CHAIN,
                                              export_aat)
        ex = export_aat(out / "records.jsonl", out / AAT_FILE)
        aat = {"file": AAT_FILE, "gaps_file": AAT_GAPS_FILE,
               "source": "records.jsonl", "records": ex["records"],
               "algorithm": AAT_CHAIN_ALGORITHM, "head": ex["aat_chain"]["head"],
               "gaps": ex["gaps"], "which_chain": WHICH_CHAIN}
    deal_block = None
    if deal is not None:
        deal_block, deal_check = _fold_deal(out, ledger, deal, deal_buyer, deal_seller)
        checks.append(deal_check)
        res["deal"] = deal_block
        dw = deal_check["verdict"]
        if dw == V.BROKEN and res["verdict"] != V.BROKEN:
            res.update({"verdict": V.BROKEN, "exit": V.EXIT_BAD,
                        "finding": deal_check["finding"]})
            for k in ("looked_for", "where", "reason_word", "reason"):
                res.pop(k, None)
        elif dw == V.COULD_NOT_LOOK and res["verdict"] == V.VERIFIED:
            res.update({"verdict": V.COULD_NOT_LOOK, "exit": V.EXIT_COULD_NOT_LOOK,
                        **{k: deal_check[k] for k in ("looked_for", "where",
                                                      "reason_word", "reason")}})
    _write_cnl(out, checks)
    _write_readme(out, res, window, system_id=system_id, provider=provider)
    audit_manifest = json.loads((out / MANIFEST).read_text(encoding="utf-8"))
    _write_manifest(out, res, integrity, audit_manifest, window, unplaced, checks,
                    aat=aat, deal=deal_block)
    res["files"] = sorted(p.name for p in out.iterdir() if p.is_file())
    return res


def _fold_deal(out: Path, ledger: Path, deal_id: str, buyer, seller) -> tuple[dict, dict]:
    """Write one deal's pack into `out` and return (manifest block, check)."""
    from arcaeon.record.deal import pack as deal_pack

    buyer = Path(buyer) if buyer is not None else ledger
    seller = Path(seller) if seller is not None else ledger
    report, _ = deal_pack(deal_id, buyer, seller, out)
    d = report.to_dict()
    word = d["verdict"]
    code = V.exit_for(word)
    block = {"id": deal_id, "files": list(DEAL_FILES), "verdict": word,
             "summary": d["summary"], "exit_code": code,
             "buyer_tape": buyer.name, "seller_tape": seller.name,
             "pack_ledger_is": ("buyer" if buyer == ledger else
                                "seller" if seller == ledger else None),
             "counts": d.get("counts") or {}}
    check = {"check": f"deal {deal_id} dispute", "dispute_verdict": word}
    if code == V.EXIT_GOOD:
        check["verdict"] = V.VERIFIED
    elif code == V.EXIT_COULD_NOT_LOOK:
        rw = d.get("reason_word")
        check.update({"verdict": V.COULD_NOT_LOOK, **V.could_not_look(
            d.get("looked_for") or f"both tapes of deal {deal_id}",
            d.get("where") or "verdict.json",
            rw if rw in V.REASON_WORDS else "unreadable",
            f"the deal dispute could not reach a verdict: {d['summary']}")})
    else:
        check.update({"verdict": V.BROKEN, "finding": f"deal {deal_id}: {d['summary']}"})
    return block, check


def _sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _pins(witness_block: dict) -> list[dict]:
    """Every pin reference the export consulted: namespace, rows, chain, and
    whatever locator the pin itself carried (as_of, received_at, and for a
    remote pin its public commit). Empty when no pin was consulted."""
    ns = witness_block.get("namespace")
    if not ns or witness_block.get("witness_rows") is None:
        return []
    ref = {"namespace": ns, "rows": witness_block.get("witness_rows"),
           "chain": witness_block.get("witness_chain"),
           "verdict": witness_block.get("verdict")}
    pin = witness_block.get("pin")
    if isinstance(pin, dict):
        for k in ("as_of", "received_at", "commit", "commit_url", "raw_record_url"):
            if pin.get(k) is not None:
                ref[k] = pin[k]
    return [ref]


def _word(w: Any) -> str:
    return w if w in V.EXIT_BY_WORD else V.COULD_NOT_LOOK


def _checks(integrity: dict, window: list[dict], unplaced: list[int],
            agent: str | None, since: str | None, until: str | None) -> list[dict]:
    """The checks this build ran, each with its verdict word. A COULD NOT LOOK
    check also carries `looked_for`, `where`, `reason_word` and `reason`
    (arcaeon.verdict.could_not_look), so could_not_look.json and the manifest
    counts are read off one list and can never disagree."""
    chain_word = _word(integrity.get("verdict"))
    chain = {"check": "records chain and witness cross-check", "verdict": chain_word,
             "finding": integrity.get("finding")}
    if chain_word == V.COULD_NOT_LOOK:
        rw = integrity.get("reason_word")
        chain.update(V.could_not_look(
            integrity.get("looked_for") or "an intact, checkable chain",
            integrity.get("where") or "records.jsonl",
            rw if rw in V.REASON_WORDS else "unreadable",
            f"the records check could not reach a verdict (finding "
            f"{integrity.get('finding')!r}); integrity.json has the detail"))
    checks = [chain]
    win = {"check": "window has rows",
           "verdict": V.VERIFIED if window else V.COULD_NOT_LOOK}
    if not window:
        win.update(V.could_not_look(
            f"rows for agent {agent!r} from {since!r} to {until!r}", "records.jsonl",
            "empty", "no row in the ledger matches that agent and window"))
    checks.append(win)
    if unplaced:
        # Rows for the agent whose `ts` could not be read while a time bound
        # was set: left out of the window, and named here, never guessed in.
        checks.append({"check": "every agent row placed in or out of the window",
                       "verdict": V.COULD_NOT_LOOK,
                       **V.could_not_look(
                           f"a readable ts on ledger lines {unplaced}", "records.jsonl",
                           "unreadable",
                           "these rows match the agent but their time could not be "
                           "read, so they are not in window.jsonl")})
    return checks


_CNL_KEYS = ("check", "looked_for", "where", "reason_word", "reason")


def _write_cnl(out: Path, checks: list[dict]) -> list[dict]:
    """Write could_not_look.json: one entry per COULD NOT LOOK check, `[]`
    when there are none. Written before the manifest, so it is hashed there."""
    entries = [{k: c[k] for k in _CNL_KEYS} for c in checks
               if c["verdict"] == V.COULD_NOT_LOOK]
    (out / CNL_FILE).write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    return entries


_VERDICT_WORDS = {
    V.VERIFIED: "VERIFIED. The records chain checked out from its first row to its "
                "last, and every check this build ran reached an answer.",
    V.BROKEN: "BROKEN. The records chain does not check out: at least one row was "
              "changed, removed or reordered after it was written. integrity.json "
              "names the first break.",
    V.COULD_NOT_LOOK: "COULD NOT LOOK. At least one check could not reach an answer, "
                      "so this pack shows nothing either way on it. could_not_look.json "
                      "says what was looked for, where, and why.",
}


def _write_readme(out: Path, res: dict, window: list[dict], *,
                  system_id: str = "", provider: str = "") -> str:
    """Write README.md, one page: the agent, the window, the verdict in words,
    what the pack does not show, and the two commands to check it. Written
    before the manifest, so it is hashed there."""
    w = res["window"]
    seen: list[str] = []
    for r in window:
        try:
            row = json.loads(r["raw"])
        except ValueError:
            continue
        for k in ("agent", "system_id"):
            v = row.get(k)
            if isinstance(v, str) and v and v not in seen:
                seen.append(v)
    agent_line = (f"`{w['agent']}` (matched on a row's `agent` or `system_id`)"
                  if w["agent"] else "every agent in the ledger (no --agent given)")
    lines = [
        "# Evidence pack",
        "",
        "This folder is evidence toward the logging duties in the EU AI Act for one "
        "agent and one window of time. It shows what was written, and that it was "
        "not changed after it was written or pinned.",
        "",
        "## The agent",
        "",
        f"- Agent: {agent_line}",
        f"- Names seen in the window's rows: "
        f"{', '.join('`' + n + '`' for n in seen) if seen else 'none'}",
    ]
    if system_id:
        lines.append(f"- System id given at build: `{system_id}`")
    if provider:
        lines.append(f"- Provider given at build: {provider}")
    rows = w["rows"]
    span = (f"ledger lines {w['first_line']} to {w['last_line']}" if rows else "no lines")
    lines += [
        "",
        "## The window",
        "",
        f"- From: {w['from'] or 'the first row'}",
        f"- To: {w['to'] or 'the last row'}",
        f"- Rows: {rows} ({span}); each is in window.jsonl with its ledger line number",
    ]
    if w.get("unplaced_lines"):
        lines.append(f"- Rows whose time could not be read, left out: lines "
                     f"{w['unplaced_lines']}")
    dl = res.get("deal")
    if dl:
        lines += [
            "",
            "## The deal",
            "",
            f"- Deal `{dl['id']}`, buyer tape {dl['buyer_tape']}, seller tape "
            f"{dl['seller_tape']}",
            f"- Dispute: {dl['summary']}",
            f"- Files: {', '.join(dl['files'])} (timeline.md is for a person)",
        ]
    verdict_text = _VERDICT_WORDS.get(res["verdict"], _VERDICT_WORDS[V.COULD_NOT_LOOK])
    if dl and res["verdict"] == V.BROKEN and str(res.get("finding", "")).startswith("deal "):
        verdict_text = (f"BROKEN. The two tapes of deal {dl['id']} do not agree: "
                        f"{dl['summary']}. timeline.md and verdict.json say where.")
    lines += [
        "",
        "## The verdict",
        "",
        verdict_text,
        "",
        "## What this pack does not show",
        "",
    ]
    lines += [f"- {b}" for b in README_DOES_NOT_SHOW]
    lines += [
        "",
        "## How to check it yourself",
        "",
        "Rehash every file against manifest.json and rerun the chain:",
        "",
        "```text",
        "arcaeon evidence-pack verify .",
        "```",
        "",
        "Check the records chain on its own, with nothing from this pack but the file:",
        "",
        "```text",
        "arcaeon verify records.jsonl",
        "```",
        "",
    ]
    text = "\n".join(lines)
    # bytes, so the page is LF on every OS and hashes the same everywhere
    (out / README).write_bytes(text.encode("utf-8"))
    return text


def _write_manifest(out: Path, res: dict, integrity: dict, audit_manifest: dict,
                    window: list[dict], unplaced: list[int],
                    checks: list[dict], *, aat: dict | None = None,
                    deal: dict | None = None) -> dict:
    """Write manifest.json LAST, over every other file in the pack.

    The three counts are of the checks this build ran (the records chain with
    its witness cross-check, and the window having rows), side by side. There
    is deliberately no rate: one BROKEN beside ten VERIFIED is not "91%".
    """
    from arcaeon import __version__
    from arcaeon.record.ledger import Ledger

    head = Ledger(out / "records.jsonl").head()
    wb = integrity.get("witness") or {}
    counts = {"verified": sum(c["verdict"] == V.VERIFIED for c in checks),
              "broken": sum(c["verdict"] == V.BROKEN for c in checks),
              "could_not_look": sum(c["verdict"] == V.COULD_NOT_LOOK for c in checks)}
    files = {p.name: _sha256_file(p)
             for p in sorted(out.iterdir()) if p.is_file() and p.name != MANIFEST}
    manifest = {
        "pack_schema": PACK_SCHEMA,
        "tool": f"arcaeon/{__version__}",
        "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verdict": res["verdict"], "exit": res["exit"],
        "files": files,
        "chain_head": {"chain": head.chain, "rows": head.rows, "ok": head.ok,
                       "first_break": head.first_break},
        "window": {"agent": res["window"]["agent"], "from": res["window"]["from"],
                   "to": res["window"]["to"], "rows": len(window),
                   "first_line": res["window"]["first_line"],
                   "last_line": res["window"]["last_line"],
                   "lines": [w["line"] for w in window],
                   "unplaced_lines": unplaced},
        "pins": _pins(wb),
        "witness": {"kind": wb.get("kind"), "identifier": wb.get("identifier"),
                    "independence": wb.get("independence"),
                    "independence_source": wb.get("independence_source")},
        "operator_at_t": OPERATOR_AT_T,
        "operator_at_t_note": ("who operated the witness when each pin was taken is "
                               "not known until a custody record is published and "
                               "anchored"),
        "checks": checks,
        "counts": counts,
        "audit_export": audit_manifest,
    }
    if aat is not None:
        manifest["aat"] = aat
    if deal is not None:
        manifest["deal"] = deal
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    # The manifest's own hash, written after it. It catches an edit to the
    # manifest alone; a rewriter who also recomputes this line is caught only
    # by a pin, which is why the pins step exists.
    (out / MANIFEST_SHA).write_bytes(
        f"{_sha256_file(out / MANIFEST)}  {MANIFEST}\n".encode("ascii"))
    return manifest
