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
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arcaeon import verdict as V

__all__ = ["build_pack", "select_window", "parse_when", "PackUsageError",
           "PACK_SCHEMA", "MANIFEST", "CNL_FILE", "README", "DOES_NOT_SHOW",
           "README_DOES_NOT_SHOW",
           "OPERATOR_AT_T", "OPERATOR_AT_T_NOTE", "PROSE_HASH_ONLY", "render_readme",
           "newest_ts", "rederived_independence", "BEARER_FILE", "BEARER_CLASSES",
           "BEARER_ALLOWED", "BEARER_SCHEMA", "render_page_one", "render_bearer",
           "page_one_sentences", "sentence_sha256"]

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
#: With --mandate FILE (K066): the mandate file's bytes, copied verbatim, and
#: the mandate rows section read off the window (counts, the file's sha256,
#: the outside rows verbatim). verify re-derives the section from the two.
MANDATE_COPY = "mandate_file.json"
MANDATE_ROWS = "mandate_rows.json"
#: With --readings RECEIPT (K067): a second-read comparison receipt, its
#: bytes copied verbatim, and (with --readings-ledger) the ledger it was
#: issued into. Build and verify both run `receipt verify` on the copy.
READINGS_RECEIPT = "readings_receipt.json"
READINGS_LEDGER = "readings_receipt.ledger.jsonl"
#: With --zip (K068): every entry at the zip's top level, sorted by name,
#: stored (not deflated, so no zlib version changes a byte), each with this
#: fixed time and mode, so two builds of the same input, stated at the same
#: build time, are byte-identical.
ZIP_DATE_TIME = (1980, 1, 1, 0, 0, 0)
_ZIP_MODE = 0o100644 << 16
_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
#: The mandate gate's row events that carry a per-call verdict (proxy.py).
_MANDATE_VERDICT_EVTS = ("mandate_outside", "mandate_could_not_look",
                         "mandate_cap_exceeded")
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
OPERATOR_AT_T_NOTE = ("who operated the witness when each pin was taken is "
                      "not known until a custody record is published and "
                      "anchored")
#: What verify reports for a prose file it cannot re-derive (K06xR3): the
#: manifest's `prose` group names each one, so a reader knows its words were
#: checked against a hash the holder could also have rewritten, and no more.
PROSE_HASH_ONLY = "not re-derived, hash only"
#: Prose files verify re-renders and compares word for word (K06xR3).
REDERIVED_PROSE = ("README.md", "ARTICLE_12_SUMMARY.md")
#: The bearer class of each sentence on page one: what carries it.
#: `bytes`: a hash over frozen content proves it (the manifest hashes, the
#: chain). `order`: only a commitment made before the act proves it (the
#: witness pin, built_at against the pin time). `asserted`: no field carries
#: it (the operator's statement of the window and the system, the
#: completeness of the could-not-look list, that any row is true). Weakest
#: last: a line holding two sentences carries the weaker one's class.
BEARER_CLASSES = ("bytes", "order", "asserted")
#: The machine-readable twin of README.md: each sentence id, the sha256 of
#: its text (the line without its bracket), its line and its class.
BEARER_FILE = "README.json"
BEARER_SCHEMA = 1
#: Every sentence id page one can print and the classes it may carry. Fixed
#: here, never read from a pack: a pack whose twin says otherwise is BROKEN.
#: No `bytes` sentence names a pin or an operator's statement.
BEARER_ALLOWED: dict[str, tuple[str, ...]] = {
    "intro.scope": ("asserted",),
    "intro.chain": ("bytes",),
    "intro.pin": ("order",),
    "intro.no_pin": ("order",),
    "legend": ("asserted",),
    "agent.selected": ("asserted",),
    "agent.names_seen": ("bytes",),
    "agent.system_id": ("asserted",),
    "agent.provider": ("asserted",),
    "window.from": ("asserted",),
    "window.to": ("asserted",),
    "window.rows": ("bytes",),
    "window.unplaced": ("bytes",),
    "deal.tapes": ("asserted",),
    "deal.dispute": ("bytes",),
    "deal.files": ("bytes",),
    "mandate.file": ("bytes",),
    "mandate.counts": ("bytes",),
    "mandate.rows": ("bytes",),
    "readings.receipt": ("bytes",),
    "readings.verify": ("bytes",),
    "readings.caveat": ("asserted",),
    "verdict": ("bytes",),
    "dns.compliance": ("asserted",),
    "dns.behaved": ("asserted",),
    "dns.independence": ("asserted",),
    "dns.operator": ("asserted",),
    "dns.aat": ("asserted",),
    "dns.retention": ("asserted",),
    "check.rehash": ("bytes",),
    "check.records": ("bytes",),
}
#: The does-not-show bullets' sentence ids, in the order of DOES_NOT_SHOW.
_DNS_IDS = ("dns.compliance", "dns.behaved", "dns.independence", "dns.operator",
            "dns.aat", "dns.retention")


def rederived_independence(kind: Any) -> tuple[str, str]:
    """(independence, independence_source) for a witness of `kind`, as the
    pack states them and verify re-derives them (K06xR3). No signed witness
    attestation exists yet, so nothing a witness says about itself makes it
    independent: every witness reads `self_asserted`, and no witness `none`."""
    if kind in (None, "none"):
        return "none", "no_witness"
    if kind == "local_file":
        return "self_asserted", "established_by_type"
    return "self_asserted", "conservative_default"


def newest_ts(raw: bytes) -> datetime | None:
    """The newest readable `ts` on any row of `raw`, or None when no row has
    one. A pack cannot have been built before its newest record (K06xR3)."""
    newest = None
    for line in _lines(raw):
        try:
            row = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            continue
        if not isinstance(row, dict) or not isinstance(row.get("ts"), str):
            continue
        try:
            ts = parse_when(row["ts"])
        except PackUsageError:
            continue
        if ts is not None and (newest is None or ts > newest):
            newest = ts
    return newest


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
               deal_seller: str | Path | None = None,
               mandate: str | Path | None = None,
               readings: str | Path | None = None,
               readings_ledger: str | Path | None = None,
               built_at: str | None = None, zip_out: bool = False) -> dict:
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

    `mandate` names the mandate file the gate judged the window against
    (K066). Its bytes are copied to mandate_file.json and mandate_rows.json
    holds, for the window: the inside / outside / could-not-look counts, the
    file's sha256, and the outside and could-not-look rows verbatim. An
    inside call is counted, not rowed, so its count is read off session_end
    rows; a gated session whose session_end is not in the window leaves that
    count short, which is COULD NOT LOOK "bounded". A file whose sha256 no
    mandate_loaded / mandate_changed row in the window names is COULD NOT
    LOOK: the counts cannot be tied to it.

    `readings` names a second-read comparison receipt (K067), copied to
    readings_receipt.json; `readings_ledger` the ledger it was issued into,
    copied beside it so the receipt's row can be found again. `receipt
    verify` runs on the copy at build and again on every pack verify: a
    receipt that fails it is BROKEN, one that cannot be read COULD NOT LOOK.
    Without `readings_ledger` the ledger tie is not checked, as with
    `arcaeon receipt verify` run without --ledger, and the manifest says so.

    `built_at` ("YYYY-MM-DDTHH:MM:SSZ") is the build time the pack states,
    in the manifest and in every file export_bundle stamps; None means the
    clock. `zip_out` also writes `<out>.zip` beside the folder (K068): sorted
    entries, fixed times, stored, so two builds of the same input with the
    same `built_at` are byte-identical. `evidence-pack verify` accepts the
    zip. The result carries `zip` and `zip_sha256`.
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
    if readings_ledger is not None and readings is None:
        raise PackUsageError("--readings-ledger is only read with --readings")
    if witness_namespace and witness is None:
        # verify re-renders the summary from the pack, and a namespace with no
        # witness leaves nothing in the pack to re-render it from (K06xR3)
        raise PackUsageError("--namespace is only read with --witness")
    if built_at is not None and not (isinstance(built_at, str)
                                     and _STAMP.fullmatch(built_at)):
        raise PackUsageError(f"--built-at {built_at!r} is not YYYY-MM-DDTHH:MM:SSZ")
    zip_path = out.parent / (out.name + ".zip")
    if zip_out and zip_path.exists():
        raise PackUsageError(f"{zip_path} exists; a pack never writes over an older "
                             "pack's zip")
    unknown = sorted(set(formats) - {"aat"})
    if unknown:
        raise PackUsageError(f"unknown --format {unknown}; the one extra format is aat")
    t_from, t_to = parse_when(since), parse_when(until)
    if t_from is not None and t_to is not None and t_from > t_to:
        raise PackUsageError(f"--from {since!r} is after --to {until!r}")
    if not ledger.is_file():
        return _cnl_result(None, "a ledger file", str(ledger), "missing",
                           "the ledger named was not found, so there is nothing to pack")
    if built_at is not None:
        newest = newest_ts(ledger.read_bytes())
        if newest is not None and newest.replace(microsecond=0) > parse_when(built_at):
            raise PackUsageError(f"--built-at {built_at} is before the ledger's newest "
                                 f"record ({newest.isoformat()}); a pack cannot be built "
                                 "before what it holds")

    export_bundle(ledger, out, system_id=system_id, provider=provider,
                  witness=witness, witness_namespace=witness_namespace,
                  generated_at=built_at)
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
        _fold_check(res, deal_check)
    mandate_block = None
    if mandate is not None:
        mandate_block, m_checks = _fold_mandate(out, Path(mandate), window)
        res["mandate"] = mandate_block
        for c in m_checks:
            checks.append(c)
            _fold_check(res, c)
    readings_block = None
    if readings is not None:
        readings_block, r_check = _fold_readings(out, Path(readings),
                                                 None if readings_ledger is None
                                                 else Path(readings_ledger))
        res["readings"] = readings_block
        checks.append(r_check)
        _fold_check(res, r_check)
    _write_cnl(out, checks)
    page, twin = render_page_one(res, window, system_id=system_id, provider=provider)
    (out / README).write_bytes(page.encode("utf-8"))
    (out / BEARER_FILE).write_bytes(twin.encode("utf-8"))
    audit_manifest = json.loads((out / MANIFEST).read_text(encoding="utf-8"))
    _write_manifest(out, res, integrity, audit_manifest, window, unplaced, checks,
                    aat=aat, deal=deal_block, mandate=mandate_block,
                    readings=readings_block, built_at=built_at)
    res["files"] = sorted(p.name for p in out.iterdir() if p.is_file())
    if zip_out:
        res["zip"] = str(zip_path)
        res["zip_sha256"] = write_zip(out, zip_path)
    return res


def write_zip(folder: Path, zip_path: Path) -> str:
    """Write the pack folder's files into `zip_path`, deterministically, and
    return the zip's sha256. Top-level files only: a pack is flat."""
    names = sorted(p.name for p in folder.iterdir() if p.is_file())
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED) as zf:
        for name in names:
            info = zipfile.ZipInfo(name, date_time=ZIP_DATE_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3      # the same on every OS
            info.external_attr = _ZIP_MODE
            zf.writestr(info, (folder / name).read_bytes())
    return hashlib.sha256(zip_path.read_bytes()).hexdigest()


def _fold_check(res: dict, check: dict) -> None:
    """Fold one extra check's verdict into the build result: a BROKEN check
    makes the pack BROKEN (its finding named), a COULD NOT LOOK one turns a
    VERIFIED pack COULD NOT LOOK (never exit 0). A BROKEN pack stays BROKEN."""
    w = check["verdict"]
    if w == V.BROKEN and res["verdict"] != V.BROKEN:
        res.update({"verdict": V.BROKEN, "exit": V.EXIT_BAD,
                    "finding": check["finding"]})
        for k in ("looked_for", "where", "reason_word", "reason"):
            res.pop(k, None)
    elif w == V.COULD_NOT_LOOK and res["verdict"] == V.VERIFIED:
        res.update({"verdict": V.COULD_NOT_LOOK, "exit": V.EXIT_COULD_NOT_LOOK,
                    **{k: check[k] for k in ("looked_for", "where",
                                             "reason_word", "reason")}})


def _is_count(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def mandate_section(records_raw: bytes, window_lines: list[int], *,
                    mandate_name: str | None, mandate_bytes: bytes | None) -> dict:
    """The mandate rows section for the window, from the records alone (K066).

    One function for build and verify, so the file verify re-derives is the
    file the build wrote. `window_lines` are the window's 1-based ledger
    lines; `mandate_bytes` the mandate file's bytes (None when it could not
    be read). Counts: outside and could-not-look are the gate's rows with
    that verdict; inside is the sum of `mandate_inside` on the window's
    session_end rows, since an inside call is counted, not rowed.
    """
    lines = _lines(records_raw)
    counts = {"inside": 0, "outside": 0, "could_not_look": 0}
    outside, cnl, loaded, changed, named = [], [], [], [], []
    gated, ended = [], []
    for n in window_lines:
        if not isinstance(n, int) or not 1 <= n <= len(lines):
            continue
        text = lines[n - 1].decode("utf-8", errors="replace")
        try:
            row = json.loads(text)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        evt, session = row.get("evt"), row.get("session")
        if evt == "session_end":
            if _is_count(row.get("mandate_inside")):
                counts["inside"] += row["mandate_inside"]
                ended.append(session)
            continue
        if evt == "mandate_loaded":
            loaded.append(n)
            if isinstance(row.get("mandate_file_sha256"), str):
                named.append(row["mandate_file_sha256"])
        elif evt == "mandate_changed":
            changed.append(n)
            if isinstance(row.get("to_sha256"), str):
                named.append(row["to_sha256"])
        elif evt in _MANDATE_VERDICT_EVTS and row.get("verdict") in ("outside",
                                                                      "could_not_look"):
            key = row["verdict"]
            counts[key] += 1
            (outside if key == "outside" else cnl).append({"line": n, "raw": text})
        else:
            continue
        if session not in gated:
            gated.append(session)
    sha = hashlib.sha256(mandate_bytes).hexdigest() if mandate_bytes is not None else None
    uniq: list[str] = []
    for x in named:
        if x not in uniq:
            uniq.append(x)
    return {
        "mandate_file": mandate_name,
        "copy": MANDATE_COPY if mandate_bytes is not None else None,
        "mandate_file_sha256": sha,
        "window_rows": len(window_lines),
        "counts": counts,
        "inside_counted_from": ("the mandate_inside field of the window's session_end "
                                "rows (an inside call is counted, not rowed)"),
        "sessions_without_end": [x for x in gated if x not in ended],
        "named_sha256": uniq,
        "loaded_lines": loaded,
        "changed_lines": changed,
        "file_is_named": (sha in uniq) if sha is not None else None,
        "outside_rows": outside,
        "could_not_look_rows": cnl,
    }


def mandate_checks(section: dict) -> list[dict]:
    """The checks a mandate section stands for (K066): which file, and
    whether the inside count is whole. Build and verify both read them off
    the section, so a pack cannot drop one without verify saying so."""
    if section["mandate_file_sha256"] is None:
        return [{"check": "mandate file read", "verdict": V.COULD_NOT_LOOK,
                 **V.could_not_look(f"the mandate file {section['mandate_file']!r}",
                                    str(section["mandate_file"]), "missing",
                                    "the mandate file named with --mandate could not be "
                                    "read, so no count can be tied to it")}]
    checks = []
    tie: dict = {"check": "mandate file is the one the gate loaded"}
    if not section["named_sha256"]:
        tie.update({"verdict": V.COULD_NOT_LOOK, **V.could_not_look(
            "a mandate_loaded or mandate_changed row naming a file sha256",
            "window.jsonl", "missing",
            "no row in the window names which mandate file the gate loaded, so the "
            "counts cannot be tied to this file")})
    elif not section["file_is_named"]:
        tie.update({"verdict": V.COULD_NOT_LOOK, **V.could_not_look(
            f"the mandate file sha256 {section['mandate_file_sha256']}", "window.jsonl",
            "name_not_found",
            f"the window's rows name {section['named_sha256']}, not this file, so the "
            "counts are not counts against it")})
    else:
        tie["verdict"] = V.VERIFIED
    checks.append(tie)
    if section["sessions_without_end"]:
        checks.append({"check": "mandate inside count", "verdict": V.COULD_NOT_LOOK,
                       **V.could_not_look(
                           f"session_end rows for sessions {section['sessions_without_end']}",
                           MANDATE_ROWS, "bounded",
                           "an inside call is counted only on its session's session_end "
                           "row, and these gated sessions end outside the window, so "
                           "the inside count is short by an unknown number")})
    return checks


def mandate_rows_bytes(section: dict) -> bytes:
    """mandate_rows.json's exact bytes (LF, UTF-8), so verify can compare."""
    return (json.dumps(section, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def mandate_block(section: dict) -> dict:
    """The manifest's `mandate` block, read off the section."""
    return {"file": MANDATE_ROWS, "copy": section["copy"],
            "mandate_file": section["mandate_file"],
            "mandate_file_sha256": section["mandate_file_sha256"],
            "counts": section["counts"]}


def _fold_mandate(out: Path, path: Path, window: list[dict]) -> tuple[dict, list[dict]]:
    """Write mandate_file.json and mandate_rows.json; return (block, checks)."""
    try:
        data = path.read_bytes() if path.is_file() else None
    except OSError:
        data = None
    if data is not None:
        (out / MANDATE_COPY).write_bytes(data)
    section = mandate_section((out / "records.jsonl").read_bytes(),
                              [w["line"] for w in window],
                              mandate_name=path.name, mandate_bytes=data)
    (out / MANDATE_ROWS).write_bytes(mandate_rows_bytes(section))
    return mandate_block(section), mandate_checks(section)


def readings_check(pack: Path, *, with_ledger: bool) -> tuple[dict, dict]:
    """Run `receipt verify` on the pack's copy of the receipt (K067).

    Returns (summary, check). One function for build and verify, so both
    reach the same word the same way: ok is VERIFIED, not ok BROKEN with the
    verifier's notes as the finding, unreadable COULD NOT LOOK."""
    from arcaeon.record.receipt.core import loads_strict, verify_receipt

    check_name = "second-read receipt verify"
    rp = pack / READINGS_RECEIPT
    lp = pack / READINGS_LEDGER if with_ledger else None
    try:
        text = rp.read_bytes().decode("utf-8")
        receipt = loads_strict(text)
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return ({"kind": None, "body_digest": None, "ok": None, "ledger_status": None},
                {"check": check_name, "verdict": V.COULD_NOT_LOOK, **V.could_not_look(
                    "a second-read comparison receipt", READINGS_RECEIPT, "unreadable",
                    f"the receipt could not be read as strict JSON ({e})")})
    vr = verify_receipt(receipt, ledger_path=lp, source_text=text)
    summary = {"kind": receipt.get("kind") if isinstance(receipt, dict) else None,
               "body_digest": (receipt.get("body_digest")
                               if isinstance(receipt, dict) else None),
               "ok": bool(vr["ok"]), "body_digest_ok": bool(vr["body_digest_ok"]),
               "ledger_status": vr["ledger"]["status"]}
    check = {"check": check_name, "ledger_status": summary["ledger_status"]}
    if vr["ok"]:
        check["verdict"] = V.VERIFIED
    else:
        check.update({"verdict": V.BROKEN, "finding": (
            f"{READINGS_RECEIPT} fails receipt verify: "
            f"{'; '.join(vr['notes']) or 'ledger ' + str(summary['ledger_status'])}")})
    return summary, check


def _fold_readings(out: Path, receipt: Path, ledger: Path | None) -> tuple[dict, dict]:
    """Copy the receipt (and its ledger) in; return (manifest block, check)."""
    block = {"receipt": READINGS_RECEIPT, "source": receipt.name,
             "ledger": READINGS_LEDGER if ledger is not None else None}
    if not receipt.is_file():
        block.update({"kind": None, "body_digest": None, "ok": None,
                      "ledger_status": None})
        return block, {"check": "second-read receipt verify",
                       "verdict": V.COULD_NOT_LOOK, **V.could_not_look(
                           "a second-read comparison receipt", str(receipt), "missing",
                           "the receipt named with --readings was not found")}
    (out / READINGS_RECEIPT).write_bytes(receipt.read_bytes())
    if ledger is not None:
        if not ledger.is_file():
            block.update({"kind": None, "body_digest": None, "ok": None,
                          "ledger_status": None, "ledger": None})
            return block, {"check": "second-read receipt verify",
                           "verdict": V.COULD_NOT_LOOK, **V.could_not_look(
                               "the ledger the receipt was issued into", str(ledger),
                               "missing",
                               "the ledger named with --readings-ledger was not found, "
                               "so the receipt's row could not be looked for")}
        (out / READINGS_LEDGER).write_bytes(ledger.read_bytes())
    summary, check = readings_check(out, with_ledger=ledger is not None)
    block.update(summary)
    if ledger is None:
        block["ledger_note"] = ("no --readings-ledger given: the receipt's body digest "
                                "was checked, its ledger row was not")
    return block, check


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


def sentence_sha256(text: str) -> str:
    """The sha256 of one page-one sentence: its line without the bracket."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def page_one_sentences(res: dict, window: list[dict], *,
                       system_id: str = "", provider: str = "") -> list:
    """Page one as a list: a plain string for a heading, a blank or a code
    line, an (id, text) pair for a sentence. The sentence's class is read off
    BEARER_ALLOWED, never chosen here."""
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
    lines: list = [
        "# Evidence pack",
        "",
        ("intro.scope", "This folder is evidence toward the logging duties in the EU AI "
                        "Act for one agent and one window of time."),
        ("intro.chain", "It shows what was written and that every row hashes to the "
                        "next."),
        ("intro.pin", "With a pin, it also shows the rows up to the pinned head are the "
                      "ones that existed at pin time."),
        ("intro.no_pin", "Without a pin, a full rewrite by the holder still checks out."),
        "",
        ("legend", "Each line ends in what bears it: [bytes] is a hash over frozen "
                   "content, [order] is a commitment made before the act, [asserted] "
                   "is the builder's word and no field in the pack carries it."),
        "",
        "## The agent",
        "",
        ("agent.selected", f"- Agent: {agent_line}"),
        ("agent.names_seen", f"- Names seen in the window's rows: "
                             f"{', '.join('`' + n + '`' for n in seen) if seen else 'none'}"),
    ]
    if system_id:
        lines.append(("agent.system_id", f"- System id given at build: `{system_id}`"))
    if provider:
        lines.append(("agent.provider", f"- Provider given at build: {provider}"))
    rows = w["rows"]
    span = (f"ledger lines {w['first_line']} to {w['last_line']}" if rows else "no lines")
    lines += [
        "",
        "## The window",
        "",
        ("window.from", f"- From: {w['from'] or 'the first row'}"),
        ("window.to", f"- To: {w['to'] or 'the last row'}"),
        ("window.rows", f"- Rows: {rows} ({span}); each is in window.jsonl with its "
                        "ledger line number"),
    ]
    if w.get("unplaced_lines"):
        lines.append(("window.unplaced", f"- Rows whose time could not be read, left "
                                         f"out: lines {w['unplaced_lines']}"))
    dl = res.get("deal")
    if dl:
        lines += [
            "",
            "## The deal",
            "",
            ("deal.tapes", f"- Deal `{dl['id']}`, buyer tape {dl['buyer_tape']}, seller "
                           f"tape {dl['seller_tape']}"),
            ("deal.dispute", f"- Dispute: {dl['summary']}"),
            ("deal.files", f"- Files: {', '.join(dl['files'])} (timeline.md is for a "
                           "person)"),
        ]
    mb = res.get("mandate")
    if mb:
        c = mb["counts"]
        lines += [
            "",
            "## The mandate",
            "",
            ("mandate.file", f"- Mandate file: {mb['mandate_file']}, sha256 "
                             f"{mb['mandate_file_sha256'] or 'not read'}"),
            ("mandate.counts", f"- Calls in the window: {c['inside']} inside, "
                               f"{c['outside']} outside, {c['could_not_look']} the gate "
                               "could not judge"),
            ("mandate.rows", f"- The outside rows, verbatim: {MANDATE_ROWS}"),
        ]
    rb = res.get("readings")
    if rb:
        lines += [
            "",
            "## The second read",
            "",
            ("readings.receipt", f"- Comparison receipt: {READINGS_RECEIPT} (from "
                                 f"{rb['source']}), kind {rb.get('kind') or 'not read'}"),
            ("readings.verify", f"- receipt verify: "
                                f"{'passes' if rb.get('ok') else 'does not pass'}; ledger "
                                f"{rb.get('ledger_status') or 'not read'}"),
            ("readings.caveat", "- Two readers agreeing measures how a sentence reads, "
                                "not whether a claim is true."),
        ]
    verdict_text = _VERDICT_WORDS.get(res["verdict"], _VERDICT_WORDS[V.COULD_NOT_LOOK])
    if dl and res["verdict"] == V.BROKEN and str(res.get("finding", "")).startswith("deal "):
        verdict_text = (f"BROKEN. The two tapes of deal {dl['id']} do not agree: "
                        f"{dl['summary']}. timeline.md and verdict.json say where.")
    lines += [
        "",
        "## The verdict",
        "",
        ("verdict", verdict_text),
        "",
        "## What this pack does not show",
        "",
    ]
    lines += [(i, f"- {b}") for i, b in zip(_DNS_IDS, README_DOES_NOT_SHOW)]
    lines += [
        "",
        "## How to check it yourself",
        "",
        ("check.rehash", "Rehash every file against manifest.json and rerun the chain:"),
        "",
        "```text",
        "arcaeon evidence-pack verify .",
        "```",
        "",
        ("check.records", "Check the records chain on its own, with nothing from this "
                          "pack but the file:"),
        "",
        "```text",
        "arcaeon verify records.jsonl",
        "```",
        "",
    ]
    return lines


def render_page_one(res: dict, window: list[dict], *,
                    system_id: str = "", provider: str = "") -> tuple[str, str]:
    """(README.md, README.json): page one with each sentence's bracket at the
    end of its line, and its twin listing each sentence id, the sha256 of its
    text, its line and its class. One function for build and verify."""
    out: list[str] = []
    sentences: list[dict] = []
    for item in page_one_sentences(res, window, system_id=system_id, provider=provider):
        if isinstance(item, str):
            out.append(item)
            continue
        sid, text = item
        cls = BEARER_ALLOWED[sid][0]
        out.append(f"{text} [{cls}]")
        sentences.append({"id": sid, "line": len(out), "sha256": sentence_sha256(text),
                          "class": cls})
    counts = {c: sum(x["class"] == c for x in sentences) for c in BEARER_CLASSES}
    twin = {"bearer_schema": BEARER_SCHEMA, "page": README,
            "classes": list(BEARER_CLASSES), "counts": counts, "sentences": sentences}
    return "\n".join(out), json.dumps(twin, indent=2) + "\n"


def render_readme(res: dict, window: list[dict], *,
                  system_id: str = "", provider: str = "") -> str:
    """README.md's text, one page: the agent, the window, the verdict in
    words, what the pack does not show, and the two commands to check it.
    Every sentence ends in its bearer class, [bytes], [order] or [asserted].
    Written before the manifest, so it is hashed there, as bytes, so the page
    is LF on every OS. One function for build and verify: verify re-renders
    it from the records and compares it word for word (K06xR3)."""
    return render_page_one(res, window, system_id=system_id, provider=provider)[0]


def render_bearer(res: dict, window: list[dict], *,
                  system_id: str = "", provider: str = "") -> str:
    """README.json's text: the bearer twin of page one."""
    return render_page_one(res, window, system_id=system_id, provider=provider)[1]


def _write_manifest(out: Path, res: dict, integrity: dict, audit_manifest: dict,
                    window: list[dict], unplaced: list[int],
                    checks: list[dict], *, aat: dict | None = None,
                    deal: dict | None = None, mandate: dict | None = None,
                    readings: dict | None = None,
                    built_at: str | None = None) -> dict:
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
        "built_at": built_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
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
        # independence is re-derived, never copied from what a witness says of
        # itself: no signed attestation exists yet, so it reads self_asserted
        # (K06xR3). integrity.json keeps the export's own label and caveat.
        "witness": dict(zip(("kind", "identifier", "independence",
                             "independence_source"),
                            (wb.get("kind"), wb.get("identifier"),
                             *rederived_independence(wb.get("kind"))))),
        "operator_at_t": OPERATOR_AT_T,
        "operator_at_t_note": OPERATOR_AT_T_NOTE,
        # prose the pack writes that verify cannot re-derive: hash only, and
        # labelled so (README.md and ARTICLE_12_SUMMARY.md are re-rendered)
        "prose": {name: PROSE_HASH_ONLY for name in sorted(files)
                  if name.endswith(".md") and name not in REDERIVED_PROSE},
        "checks": checks,
        "counts": counts,
        "audit_export": audit_manifest,
    }
    if aat is not None:
        manifest["aat"] = aat
    if deal is not None:
        manifest["deal"] = deal
    if mandate is not None:
        manifest["mandate"] = mandate
    if readings is not None:
        manifest["readings"] = readings
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    # The manifest's own hash, written after it. It catches an edit to the
    # manifest alone. A pin binds the records; every other field is re-derived
    # from the records and the pin at verify, never trusted; prose that cannot
    # be re-derived is hash-only and labelled (the manifest's `prose` group).
    (out / MANIFEST_SHA).write_bytes(
        f"{_sha256_file(out / MANIFEST)}  {MANIFEST}\n".encode("ascii"))
    return manifest
