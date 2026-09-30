# SPDX-License-Identifier: MIT
"""`arcaeon evidence-pack verify PACK --second-reader`: every claim, recomputed.

    arcaeon evidence-pack verify PACK|PACK.zip --second-reader [--witness PINS]
                                 [--json OUT.json] [--markdown OUT.md]

A second reader that is a program, not a model. Three runs of a language
model as the second reader of an evidence pack (2026-09-29) showed the same
two faults: it said VERIFIED for a digest it had not computed, and it called a
chain head VERIFIED by reading the stored `chain` field of the last row, which
a tamper that edits a row's content leaves alone. This module is the reader
those runs asked for: every claim the pack makes is recomputed from the bytes,
and each row prints the recomputed value beside the claimed one.

Each row carries one of three words:

- VERIFIED: recomputed, and equal to the claim.
- MISMATCH: recomputed, and not equal. The overall verdict becomes BROKEN.
- COULD NOT LOOK: the bytes are not in the pack, or the claim needs the
  witness itself (a local pin without `witness`, a remote pin always).

and names the algorithm that recomputed it (`sha256`, the ledger's chain
link, a count, a tally, a re-selection, the verify step that re-derives it).

The overall verdict is the worst of the rows and of `verify_pack` run on the
same pack with the same witness: BROKEN outranks COULD NOT LOOK, which
outranks VERIFIED. So a pack `evidence-pack verify` calls BROKEN is never
less than BROKEN here (a listed file that is gone is COULD NOT LOOK on its own
row, since its bytes are not present, and BROKEN overall, as OA1 has it).
Exit codes as every verb: 0 VERIFIED, 1 BROKEN, 2 bad usage, 3 COULD NOT LOOK.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from arcaeon import verdict as V

__all__ = ["Row", "Report", "second_reader", "main", "VERIFIED", "MISMATCH",
           "COULD_NOT_LOOK", "ROW_WORDS", "ALG_SHA256", "ALG_CHAIN"]

VERIFIED = V.VERIFIED
MISMATCH = "MISMATCH"
COULD_NOT_LOOK = V.COULD_NOT_LOOK
ROW_WORDS = (VERIFIED, MISMATCH, COULD_NOT_LOOK)

ALG_SHA256 = "sha256"
ALG_CHAIN = "sha256 chain link (first 32 hex of sha256(prev + row JSON, keys sorted))"
ALG_COUNT = "count"
ALG_TALLY = "tally of `event`"
ALG_TS = "first and last `ts`"
ALG_SELECT = "window re-selected by agent and bounds"
ALG_WITNESS = "the pin file's own chain, then the exact pin"
ALG_REMOTE = "the public witness (network)"
ALG_BYTES = "byte equality with records.jsonl"
ALG_STEP = "the verify step that re-derives it"
ALG_LIST = "set difference"

_BRACKET = re.compile(r" \[(bytes|order|asserted)(?:; falsifier: .*)?\]$")


@dataclass
class Row:
    """One claim the pack makes, the value recomputed from the bytes, and the word."""
    n: int
    kind: str
    claim: str
    where: str
    claimed: Any
    recomputed: Any
    verdict: str
    algorithm: str
    how: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Report:
    """The claim table and the verdict it adds up to."""
    pack: str
    verdict: str
    exit: int
    witness: str | None
    rows: list[Row] = field(default_factory=list)
    counts: dict = field(default_factory=dict)
    pack_verify: dict = field(default_factory=dict)
    note: str = ("every row is recomputed from the pack's bytes; nothing is VERIFIED "
                 "because the pack says so")

    # --- the machine form ---------------------------------------------------
    def to_dict(self) -> dict:
        return {"second_reader": 1, "pack": self.pack, "verdict": self.verdict,
                "exit": self.exit, "witness": self.witness, "counts": dict(self.counts),
                "pack_verify": dict(self.pack_verify), "note": self.note,
                "rows": [r.to_dict() for r in self.rows]}

    @classmethod
    def from_dict(cls, d: dict) -> "Report":
        return cls(pack=d["pack"], verdict=d["verdict"], exit=d["exit"],
                   witness=d.get("witness"), rows=[Row(**r) for r in d.get("rows", [])],
                   counts=dict(d.get("counts") or {}),
                   pack_verify=dict(d.get("pack_verify") or {}),
                   note=d.get("note", cls.note))

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n"

    # --- the human forms ----------------------------------------------------
    def _lines(self, cell) -> list[list[str]]:
        return [[str(r.n), cell(r.claim), cell(r.where), cell(_show(r.claimed)),
                 cell(_show(r.recomputed)), r.verdict, cell(r.algorithm), cell(r.how)]
                for r in self.rows]

    def _summary(self) -> str:
        c = self.counts
        return (f"{self.verdict}: second reader, {len(self.rows)} claims: "
                f"{c.get(VERIFIED, 0)} VERIFIED, {c.get(MISMATCH, 0)} MISMATCH, "
                f"{c.get(COULD_NOT_LOOK, 0)} COULD NOT LOOK "
                f"(evidence-pack verify: {self.pack_verify.get('verdict')})")

    def to_markdown(self) -> str:
        def cell(s: str) -> str:
            return str(s).replace("|", "\\|").replace("\n", " ")

        head = ["#", "Claim", "Where the pack makes it", "Claimed", "Recomputed",
                "Verdict", "Algorithm", "How"]
        out = [f"Second reader: `{cell(self.pack)}`", "",
               "| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
        for line in self._lines(cell):
            line[3], line[4] = f"`{line[3]}`", f"`{line[4]}`"
            out.append("| " + " | ".join(line) + " |")
        out += ["", self._summary(), ""]
        return "\n".join(out)

    def to_table(self) -> str:
        head = ["#", "Claim", "Where", "Claimed", "Recomputed", "Verdict", "Algorithm"]
        body = [line[:7] for line in self._lines(str)]
        width = [max(len(x[i]) for x in [head, *body]) for i in range(len(head))]
        fmt = lambda xs: "  ".join(x.ljust(w) for x, w in zip(xs, width)).rstrip()
        out = [fmt(head), fmt(["-" * w for w in width])]
        for r, line in zip(self.rows, body):
            out.append(fmt(line))
            if r.verdict != VERIFIED:
                out.append(" " * (width[0] + 2) + f"how: {r.how}")
        out.append(self._summary())
        return "\n".join(out) + "\n"


def _show(v: Any) -> str:
    if v is None:
        return "(not looked at)"
    if isinstance(v, (dict, list)):
        return json.dumps(v, sort_keys=True, ensure_ascii=False)
    return str(v)


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _load(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None


def _fold_chain(raw: bytes) -> tuple[list[str | None], str | None]:
    """The chain recomputed from each row's content, ignoring every stored
    link: one value per parseable row. Reading the stored `chain` field is
    not recomputing it; this is. Returns (links, why it stopped or None)."""
    from arcaeon.prove.evidence_pack import _lines
    from arcaeon.record.row import GENESIS, chain

    links: list[str | None] = []
    prev = GENESIS
    for n, line in enumerate(_lines(raw), start=1):
        try:
            obj = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return links, f"line {n} is not JSON"
        if not isinstance(obj, dict):
            return links, f"line {n} is not a JSON object"
        prev = chain(prev, obj)
        links.append(prev)
    return links, None


class _Table:
    def __init__(self) -> None:
        self.rows: list[Row] = []

    def add(self, kind, claim, where, claimed, recomputed, algorithm, how,
            word: str | None = None) -> None:
        if word is None:
            if recomputed is None:
                word = COULD_NOT_LOOK
            else:
                word = VERIFIED if recomputed == claimed else MISMATCH
        self.rows.append(Row(n=len(self.rows) + 1, kind=kind, claim=claim, where=where,
                             claimed=claimed, recomputed=recomputed, verdict=word,
                             algorithm=algorithm, how=how))


def _rows_for(pack: Path, manifest: dict, verify_res: dict, witness) -> list[Row]:
    from arcaeon.prove import audit as A
    from arcaeon.prove import evidence_pack_verify as EV
    from arcaeon.prove.evidence_pack import PackUsageError, parse_when, select_window
    from arcaeon.record.ledger import verify_file

    t = _Table()
    steps = {c.get("check"): c for c in verify_res.get("checks") or []}

    # 1. the manifest's own bytes, against manifest.sha256
    side = pack / EV.MANIFEST_SHA
    claimed = None
    if side.is_file():
        try:
            want, _, name = side.read_text(encoding="ascii").strip().partition("  ")
            claimed = want if name == EV.MANIFEST else None
        except (OSError, UnicodeDecodeError):
            claimed = None
    t.add("file", "manifest.json hashes to the value beside it", "manifest.sha256",
          claimed, _sha((pack / EV.MANIFEST).read_bytes()) if claimed else None,
          ALG_SHA256, "sha256 of manifest.json's bytes" if claimed else
          "manifest.sha256 is not in the pack or not '<hex>  manifest.json'")

    # 2. every file the manifest lists
    listed = manifest.get("files") if isinstance(manifest.get("files"), dict) else {}
    for name in sorted(listed):
        p = pack / name
        present = Path(name).name == name and p.is_file()
        t.add("file", f"{name} hashes to the listed value", f"manifest.json files[{name}]",
              listed[name], _sha(p.read_bytes()) if present else None, ALG_SHA256,
              f"sha256 of the {p.stat().st_size} bytes of {name}" if present else
              f"{name} is listed and its bytes are not in the pack")
    on_disk = sorted(q.relative_to(pack).as_posix() for q in pack.rglob("*") if q.is_file()
                     and q.relative_to(pack).as_posix() not in (EV.MANIFEST, EV.MANIFEST_SHA))
    t.add("file", "the pack holds no file the manifest does not list", "manifest.json files",
          [], sorted(set(on_disk) - set(listed)), ALG_LIST,
          "every file in the folder, minus the listed ones")

    records = pack / "records.jsonl"
    raw = records.read_bytes() if records.is_file() else None
    vr = verify_file(records) if raw is not None else None
    links, stop = _fold_chain(raw) if raw is not None else ([], None)

    # 3. the chain head: recomputed from the rows' content, not read off them
    head = manifest.get("chain_head") if isinstance(manifest.get("chain_head"), dict) else {}
    if raw is None:
        t.add("chain", "the records chain ends at this head", "manifest.json chain_head.chain",
              head.get("chain"), None, ALG_CHAIN, "records.jsonl is not in the pack")
        t.add("chain", "the records hold this many rows", "manifest.json chain_head.rows",
              head.get("rows"), None, ALG_COUNT, "records.jsonl is not in the pack")
    else:
        got = links[-1] if links and stop is None else None
        if vr.ok is None:
            t.add("chain", "the records chain ends at this head",
                  "manifest.json chain_head.chain", head.get("chain"), got, ALG_CHAIN,
                  f"the chain check was bounded ({vr.verified_scope}): not every link "
                  "was recomputed", word=COULD_NOT_LOOK)
        else:
            how = "each link recomputed from its row's content, starting at genesis"
            if vr.ok is False:
                how += f"; the stored links break at {vr.first_break}"
                got = got if got is not None else f"unrecomputable: {stop}"
            t.add("chain", "the records chain ends at this head",
                  "manifest.json chain_head.chain", head.get("chain"), got, ALG_CHAIN, how,
                  word=None if vr.ok else MISMATCH)
        t.add("chain", "the records hold this many rows", "manifest.json chain_head.rows",
              head.get("rows"), vr.rows, ALG_COUNT, "rows of records.jsonl counted")

    # 4. integrity.json's own claims about the records
    integ = _load(pack / "integrity.json")
    if isinstance(integ, dict):
        t.add("integrity", "records.jsonl hashes to this value",
              "integrity.json records_sha256", integ.get("records_sha256"),
              _sha(raw) if raw is not None else None, ALG_SHA256,
              "sha256 of records.jsonl's bytes" if raw is not None else
              "records.jsonl is not in the pack")
        t.add("integrity", "the records hold this many rows", "integrity.json rows",
              integ.get("rows"), vr.rows if vr is not None else None, ALG_COUNT,
              "rows of records.jsonl counted" if vr is not None else
              "records.jsonl is not in the pack")
    else:
        t.add("integrity", "integrity.json states the records hash", "integrity.json",
              None, None, ALG_SHA256, "integrity.json is not in the pack or not JSON")

    # 5. the window, re-selected from the records with the manifest's bounds
    w = manifest.get("window") if isinstance(manifest.get("window"), dict) else {}
    sel = None
    if raw is not None:
        try:
            agent = w.get("agent")
            if agent is not None and not isinstance(agent, str):
                raise PackUsageError("agent is not a string")
            sel, _ = select_window(raw, agent=agent, since=parse_when(w.get("from")),
                                   until=parse_when(w.get("to")))
        except (PackUsageError, TypeError, AttributeError):
            sel = None
    why = ("records.jsonl selected again by the manifest's agent, from and to" if sel is not None
           else "records.jsonl is not in the pack, or the manifest's window is unreadable")
    t.add("window", "the window holds this many rows", "manifest.json window.rows",
          w.get("rows"), len(sel) if sel is not None else None, ALG_SELECT, why)
    t.add("window", "the window is these ledger lines", "manifest.json window.lines",
          w.get("lines"), [x["line"] for x in sel] if sel is not None else None, ALG_SELECT, why)
    ws = steps.get("window rows equal their records lines") or {}
    t.add("window", "every window.jsonl row is its records.jsonl line, byte for byte",
          "window.jsonl", [], ws.get("differ_lines") if ws.get("verdict") != COULD_NOT_LOOK
          and "differ_lines" in ws else None, ALG_BYTES,
          "ledger lines whose window row differs" if "differ_lines" in ws else
          ws.get("reason") or "window.jsonl or records.jsonl is not in the pack")

    # 6. the export block, re-derived from the records
    ae = manifest.get("audit_export") if isinstance(manifest.get("audit_export"), dict) else {}
    if raw is not None:
        rows, unreadable = A._read_rows(raw)
        s = A._summ(rows)
        derived = {"record_count": (len(rows), ALG_COUNT),
                   "unreadable_lines": (unreadable, ALG_COUNT),
                   "period_covered": ({"from": s["first_ts"], "to": s["last_ts"]}, ALG_TS),
                   "event_counts": (s["counts"], ALG_TALLY)}
    else:
        derived = {k: (None, a) for k, a in (("record_count", ALG_COUNT),
                                             ("unreadable_lines", ALG_COUNT),
                                             ("period_covered", ALG_TS),
                                             ("event_counts", ALG_TALLY))}
    for k, (got, alg) in derived.items():
        t.add("export", f"the export's {k.replace('_', ' ')}",
              f"manifest.json audit_export.{k}", ae.get(k), got, alg,
              "re-derived from records.jsonl" if raw is not None else
              "records.jsonl is not in the pack")

    # 7. pins: first the records at the pinned row (recomputed), then the witness
    wb = integ.get("witness") if isinstance(integ, dict) and isinstance(
        integ.get("witness"), dict) else {}
    pins = manifest.get("pins") if isinstance(manifest.get("pins"), list) else []
    for x in pins:
        if not isinstance(x, dict):
            continue
        ns, rows_at, ch = x.get("namespace"), x.get("rows"), x.get("chain")
        at = (links[rows_at - 1] if isinstance(rows_at, int) and 0 < rows_at <= len(links)
              and stop is None else None)
        t.add("chain", f"the records reach the pinned chain at row {rows_at}",
              f"manifest.json pins[{ns}]", ch, at, ALG_CHAIN,
              f"links 1 to {rows_at} recomputed from the rows' content" if at else
              "records.jsonl is not in the pack or has fewer rows")
        if EV._is_remote(wb, x):
            r = EV._check_remote(x, False)
            alg = ALG_REMOTE
        else:
            r = EV._check_local(pack, x, witness)
            alg = ALG_WITNESS
        claimed = {"namespace": ns, "rows": rows_at, "chain": ch}
        if r["verdict"] == V.VERIFIED:
            t.add("pin", f"the witness holds the pin for {ns!r}", f"manifest.json pins[{ns}]",
                  claimed, claimed, alg, f"the pin file {witness} holds this exact pin")
        elif r["verdict"] == V.BROKEN:
            t.add("pin", f"the witness holds the pin for {ns!r}", f"manifest.json pins[{ns}]",
                  claimed, {"latest_rows": r.get("pin_file_latest_rows")}, alg,
                  r.get("finding", ""), word=MISMATCH)
        else:
            t.add("pin", f"the witness holds the pin for {ns!r}", f"manifest.json pins[{ns}]",
                  claimed, None, alg, r.get("reason", ""))

    # 8. what the verify steps re-derive and no single value holds
    for name, claim in (("build-time findings",
                         "could_not_look.json and the counts are what the checks found"),
                        ("re-derived fields and prose",
                         "README.md, ARTICLE_12_SUMMARY.md, integrity.json, independence "
                         "and built_at re-derive from the records"),
                        ("aat export", "aat.jsonl is the export recomputed from the records"),
                        ("mandate rows", "mandate_rows.json rebuilds from the records"),
                        ("second-read receipt", "the included receipt verifies")):
        c = steps.get(name)
        if c is None or "note" in c and name in ("aat export", "mandate rows",
                                                 "second-read receipt"):
            continue  # not in this pack
        word = {V.VERIFIED: VERIFIED, V.BROKEN: MISMATCH}.get(c["verdict"], COULD_NOT_LOOK)
        t.add("rederived", claim, name, V.VERIFIED, c["verdict"], ALG_STEP,
              c.get("finding") or c.get("reason") or "re-derived and equal", word=word)

    # 9. page one's bearer twin, when the pack has one (pack schema 2)
    twin = _load(pack / "README.json")
    readme = pack / "README.md"
    if isinstance(twin, dict) and isinstance(twin.get("sentences"), list):
        page = readme.read_text(encoding="utf-8").split("\n") if readme.is_file() else None
        for s in twin["sentences"]:
            if not isinstance(s, dict):
                continue
            ln = s.get("line")
            text = page[ln - 1] if page and isinstance(ln, int) and 0 < ln <= len(page) else None
            m = _BRACKET.search(text) if text is not None else None
            body = text[:m.start()] if m else text
            t.add("sentence", f"README.md line {ln} is sentence {s.get('id')}",
                  f"README.json sentences[{s.get('id')}]", s.get("sha256"),
                  _sha(body.encode("utf-8")) if body is not None else None, ALG_SHA256,
                  "sha256 of the line without its bracket" if body is not None else
                  "README.md is not in the pack or has no such line")
            t.add("sentence", f"sentence {s.get('id')} is borne by [{s.get('class')}]",
                  f"README.json sentences[{s.get('id')}].class", s.get("class"),
                  m.group(1) if m else (None if text is None else "no bracket"),
                  "the bracket on the line", "read off README.md's own line")
    return t.rows


def _combine(rows: list[Row], verify_word: str) -> str:
    words = [r.verdict for r in rows]
    if MISMATCH in words or verify_word == V.BROKEN:
        return V.BROKEN
    if COULD_NOT_LOOK in words or verify_word != V.VERIFIED or not rows:
        return V.COULD_NOT_LOOK
    return V.VERIFIED


def _report(pack_label: str, folder: Path | None, verify_res: dict, witness) -> Report:
    manifest = _load(folder / "manifest.json") if folder is not None else None
    rows = _rows_for(folder, manifest, verify_res, witness) if isinstance(manifest, dict) \
        else []
    word = _combine(rows, verify_res.get("verdict", V.COULD_NOT_LOOK))
    pv = {"verdict": verify_res.get("verdict"), "exit": verify_res.get("exit")}
    for k in ("finding", "reason_word", "reason"):
        if verify_res.get(k):
            pv[k] = verify_res[k]
    return Report(pack=pack_label, verdict=word, exit=V.EXIT_BY_WORD[word],
                  witness=str(witness) if witness is not None else None, rows=rows,
                  counts={w: sum(r.verdict == w for r in rows) for w in ROW_WORDS},
                  pack_verify=pv)


def second_reader(pack_path: str | Path, witness: str | Path | None = None) -> Report:
    """Recompute every claim the pack at `pack_path` (a folder or the .zip
    `evidence-pack --zip` writes) makes, from its bytes. `witness` is the
    local pin file its local pins are checked against; without it a local pin
    row is COULD NOT LOOK. Never raises on a damaged or absent pack."""
    from arcaeon.prove.evidence_pack_verify import ZIP_MAX_BYTES, verify_pack

    pack = Path(pack_path)
    res = verify_pack(pack, witness=witness)
    zip_failed = any(c.get("check") == "pack zip" for c in res.get("checks") or [])
    if pack.is_file() and not zip_failed:
        # the zip passed verify's entry checks; read it once more for the rows
        with tempfile.TemporaryDirectory(prefix="arcaeon-sr-") as tmp:
            folder = Path(tmp)
            with zipfile.ZipFile(pack) as zf:
                for i in zf.infolist():
                    with zf.open(i) as src:
                        (folder / i.filename).write_bytes(src.read(ZIP_MAX_BYTES + 1))
            return _report(str(pack), folder, res, witness)
    return _report(str(pack), pack if pack.is_dir() else None, res, witness)


def _parser(prog: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=prog, description=(
        "The second reader: recompute every claim an evidence pack makes from its "
        "bytes, and print each recomputed value beside the claimed one."))
    p.add_argument("pack", help="the evidence pack folder, or the .zip --zip wrote")
    p.add_argument("--second-reader", action="store_true", required=True,
                   help="print the claim table")
    p.add_argument("--witness", default=None,
                   help="the local pin file to check the pack's local pins against")
    p.add_argument("--json", dest="json_out", default=None, metavar="PATH",
                   help="also write the report as JSON to PATH")
    p.add_argument("--markdown", dest="md_out", default=None, metavar="PATH",
                   help="also write the claim table as Markdown to PATH")
    return p


def main(argv: list[str] | None = None, *,
         prog: str = "arcaeon evidence-pack verify") -> int:
    a = _parser(prog).parse_args(argv)
    rep = second_reader(a.pack, witness=a.witness)
    sys.stdout.write(rep.to_table())
    for path, text in ((a.json_out, rep.to_json), (a.md_out, rep.to_markdown)):
        if path is None:
            continue
        try:
            Path(path).write_text(text(), encoding="utf-8", newline="\n")
        except OSError as e:
            print(f"{prog}: could not write {path}: {e}", file=sys.stderr)
            return V.EXIT_USAGE
    return rep.exit


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
