# SPDX-License-Identifier: MIT
"""arcaeon.prove.readings_cli: the `arcaeon second-read` verb.

    arcaeon second-read criterion FILE --ledger L [--supersedes SHA] [--json]
    arcaeon second-read compare A B [--json]
    arcaeon second-read submit --ledger L --reader-id X --provider P --claim-id C
                               (--claim-file F | --claim-sha256 SHA) --reading WORD
                               [--criterion-sha256 SHA | --criterion-file F]
                               [--model M] [--near-match-id ID]
                               [--rationale-file F [--keep-text]] [--json]
    arcaeon second-read ask --claims FILE --reader SPEC --ledger L
                            [--base-url URL] [--key-env VAR] [--reader-id ID]
                            [--criterion-sha256 SHA | --criterion-file F]
                            [--keep-text] [--timeout S] [--send] [--json]

`compare` lines up two readings ledgers (see `arcaeon.prove.readings_compare`)
and prints a human first line such as

    compared 24 claims: 3 disagreed of 24 read

or, with `--json`, the whole comparison object plus nothing else.

Exit codes (the arcaeon table): COMPARED 0 (the comparison completed; a
disagreement is filed, not failed), MISSING 1, BROKEN 1, COULD NOT LOOK 3,
bad usage 2. Nothing printed here says a claim holds: two readers agreeing
measures how ambiguous the sentence was for them.

`submit` is the interop door: another agent (or a person) files its OWN
reading of a claim into a readings ledger, without us calling any model. The
row is an ordinary `arcaeon-reading/1` row, chained like any other; its
`prompt_sha256` and `reader.endpoint_host` are null (no prompt of ours was
sent, no endpoint of ours was called). The reading cites a criterion frozen
earlier in the ledger: the one named by `--criterion-sha256`, or the one whose
text is in `--criterion-file` (frozen first if the ledger lacks it), or, with
neither, the ledger's latest criterion row. Submit exit codes: 0 the row was
filed, 2 bad usage, 3 COULD NOT LOOK (no such criterion in that ledger,
`reason_word: "name_not_found"`). "Filed" says the row was written, never
that the reading is right.

`ask` batches a claims file (JSONL, one `{"claim_id", "claim"}` object per
line, optional `near_match_id`) through ONE reader (`--reader`, a preset spec
such as `ollama:qwen2.5-coder:3b`, see `arcaeon.prove.readers.PRESETS`).
Sending a claim to a model is a disclosure, so without `--send` nothing is
sent: `ask` prints the endpoint host, the claim count and the first prompt as
it would be sent, and makes no request. With `--send`, each call has a 30 s
timeout (`--timeout`) and one retry at most. A call that still fails writes
NO reading for that claim (never a guessed one); the claim is listed under
`could_not_look` with its `reason_word` (`network` when the request never
completed). Ask exit codes: 0 every claim got a reading, or a dry run; 2 bad
usage; 3 one or more claims COULD NOT LOOK. The ledger holds readings, not
findings: a written reading is what that model answered, nothing more.

Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from arcaeon import verdict as _v

__all__ = ["main", "compare_main", "human_lines", "SUBCOMMANDS", "SUBMIT_FORMAT", "submit",
           "submit_main", "ASK_FORMAT", "ask", "ask_main", "load_claims", "ASK_RETRIES"]

_PROG = "arcaeon second-read"


def human_lines(res: dict) -> list[str]:
    """The human rendering of a compare result, first line first."""
    s = res.get("summary") or {}
    word = res.get("verdict")
    claims = res.get("claims") or []
    lines: list[str] = []
    if s.get("read") is None:
        lines.append(f"{word}: {res.get('reason') or s.get('counts_reason') or 'no reason given'}")
        lines.append(f"counts not computed: {s.get('counts_reason')}")
        return lines
    lines.append(f"compared {len(claims)} claims: {s['disagreed']} disagreed of {s['read']} read")
    if word == _v.COMPARED:
        lines.append("COMPARED: both ledgers were read and lined up")
    else:
        lines.append(f"{word}: {res.get('reason') or _missing_reason(s)}")
    if s.get("not_yet_informative"):
        lines.append(f"not yet informative: fewer than 20 claims read ({s['read']})")
    if res.get("independence"):
        lines.append(f"readers: {res['independence']}")
    for c in claims:
        st = c.get("status")
        a, b = c.get("a") or {}, c.get("b") or {}
        if st == "DISAGREED":
            lines.append(
                f"  DISAGREED {c['claim_id']}: a={a.get('reading')} ({a.get('reader_id')}, "
                f"near {a.get('near_match_id')}) b={b.get('reading')} ({b.get('reader_id')}, "
                f"near {b.get('near_match_id')})")
        elif st == _v.MISSING:
            lines.append(f"  MISSING {c['claim_id']}: not read in ledger {c.get('side')}")
        elif st == _v.COULD_NOT_LOOK:
            lines.append(f"  COULD NOT LOOK {c['claim_id']}: {c.get('reason')}")
    lines.append("agreement says nothing about whether a claim holds")
    return lines


def _missing_reason(s: dict) -> str:
    return f"{s.get('missing')} claim(s) read on one side only"


def compare_main(argv: list[str] | None = None) -> int:
    """`second-read compare A B [--json]`."""
    p = argparse.ArgumentParser(prog=f"{_PROG} compare",
                                description="line up two readings ledgers, claim by claim")
    p.add_argument("a", help="the first readings ledger")
    p.add_argument("b", help="the second readings ledger")
    p.add_argument("--json", action="store_true", help="print the comparison object as JSON")
    args = p.parse_args(argv)
    from arcaeon.prove.readings_compare import compare
    res = compare(args.a, args.b)
    if args.json:
        print(json.dumps(res, ensure_ascii=False, sort_keys=True))
    else:
        print("\n".join(human_lines(res)))
    return res["exit"]


#: The result shape of one submit.
SUBMIT_FORMAT = "arcaeon-reading-submit/1"


def _latest_criterion(path: Path) -> str | None:
    from arcaeon.record.ledger import Ledger
    if not path.exists():
        return None
    last = None
    for r in Ledger(path):
        if isinstance(r, dict) and r.get("evt") == "criterion":
            last = r.get("criterion_sha256")
    return last


def _usage_res(msg: str) -> dict:
    return {"format": SUBMIT_FORMAT, "written": False, "error": msg, "exit": _v.EXIT_USAGE}


def _no_criterion(looked_for: str, where: str, reason: str) -> dict:
    return {"format": SUBMIT_FORMAT, "written": False, "exit": _v.EXIT_COULD_NOT_LOOK,
            **_v.could_not_look(looked_for, where, "name_not_found", reason)}


def submit(ledger, *, reader_id: str, provider: str, claim_id: str, reading: str,
           claim_text: str | None = None, claim_sha256: str | None = None,
           criterion_sha256: str | None = None, criterion_text: str | None = None,
           model: str | None = None, near_match_id: str | None = None,
           rationale: str | None = None, keep_text: bool = False) -> dict:
    """File one reading that a caller took itself. Returns the result dict
    (`exit` 0 filed, 2 bad usage, 3 COULD NOT LOOK); never raises on bad input."""
    from arcaeon.prove import readings as R
    path = Path(ledger)
    for name, val in (("reader_id", reader_id), ("provider", provider), ("claim_id", claim_id)):
        if not isinstance(val, str) or not val.strip():
            return _usage_res(f"{name} must be a non-empty string")
    if model is not None and not isinstance(model, str):
        return _usage_res("model must be a string")
    if claim_text is None and claim_sha256 is None:
        return _usage_res("give the claim text or its claim_sha256")
    if criterion_text is not None:
        if not isinstance(criterion_text, str) or not R.normalize_criterion(criterion_text):
            return _usage_res("criterion text is empty")
        sha = R.sha256_text(R.normalize_criterion(criterion_text))
        if criterion_sha256 is not None and criterion_sha256 != sha:
            return _usage_res("criterion_sha256 does not match the sha256 of the criterion text")
        criterion_sha256 = sha
    if criterion_sha256 is None:
        criterion_sha256 = _latest_criterion(path)
        if criterion_sha256 is None:
            return _no_criterion("a criterion row", str(path),
                                 f"{path} has no frozen criterion; freeze one first "
                                 "(second-read criterion FILE --ledger L)")
    reader = {"id": reader_id, "provider": provider, "model": model, "endpoint_host": None}
    frozen_now = False
    try:
        row = R.build_reading(claim_id=claim_id, claim_text=claim_text, claim_sha256=claim_sha256,
                              criterion_sha256=criterion_sha256, reader=reader, reading=reading,
                              near_match_id=near_match_id, rationale=rationale,
                              keep_text=keep_text, prompt_sha256=None)
        if criterion_text is not None and criterion_sha256 not in R._criteria_in(path):
            R.freeze_criterion(path, criterion_text)
            frozen_now = True
        chain = R.write_reading(path, row)
    except R.UnknownCriterionError:
        return _no_criterion(f"criterion {criterion_sha256}", str(path),
                             f"criterion {str(criterion_sha256)[:12]}... is not frozen in {path}")
    except R.ReadingError as e:
        return _usage_res(str(e))
    return {"format": SUBMIT_FORMAT, "written": True, "ledger": str(path), "chain": chain,
            "claim_id": row["claim_id"], "claim_sha256": row["claim_sha256"],
            "criterion_sha256": row["criterion_sha256"], "criterion_frozen_now": frozen_now,
            "reader": row["reader"], "reading": row["reading"],
            "near_match_id": row.get("near_match_id"), "exit": _v.EXIT_GOOD}


def _read_text(fname: str, what: str) -> str:
    try:
        return Path(fname).read_text(encoding="utf-8")
    except OSError as e:
        raise ValueError(f"cannot read {what} {fname} [{type(e).__name__}]") from None


def submit_main(argv: list[str] | None = None) -> int:
    """`second-read submit ...`: file a reading this caller took itself."""
    p = argparse.ArgumentParser(prog=f"{_PROG} submit",
                                description="file your own reading of one claim into a readings ledger")
    p.add_argument("--ledger", required=True, help="the readings ledger to append to")
    p.add_argument("--reader-id", required=True, help="who read it (your stable reader id)")
    p.add_argument("--provider", required=True, help="the reader's provider, as you assert it")
    p.add_argument("--claim-id", required=True, help="the claim's id")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--claim-file", help="a file holding the claim text, read exactly as it is")
    g.add_argument("--claim-sha256", help="the claim text's sha256, when the text is not shared")
    p.add_argument("--reading", required=True, help="yes, no or undetermined")
    c = p.add_mutually_exclusive_group()
    c.add_argument("--criterion-sha256", help="the frozen criterion this reading cites")
    c.add_argument("--criterion-file", help="the criterion text (frozen first if new here)")
    p.add_argument("--model", default=None, help="the model, if a model read it")
    p.add_argument("--near-match-id", default=None, help="the id this claim almost matched")
    p.add_argument("--rationale-file", default=None, help="the reader's rationale (digest kept)")
    p.add_argument("--keep-text", action="store_true", help="keep the rationale text in the row")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    args = p.parse_args(argv)
    try:
        claim_text = _read_text(args.claim_file, "claim file") if args.claim_file else None
        crit = _read_text(args.criterion_file, "criterion file") if args.criterion_file else None
        rat = _read_text(args.rationale_file, "rationale file") if args.rationale_file else None
    except ValueError as e:
        print(f"{_PROG} submit: {e}", file=sys.stderr)
        return _v.EXIT_USAGE
    res = submit(args.ledger, reader_id=args.reader_id, provider=args.provider,
                 claim_id=args.claim_id, reading=args.reading, claim_text=claim_text,
                 claim_sha256=args.claim_sha256, criterion_sha256=args.criterion_sha256,
                 criterion_text=crit, model=args.model, near_match_id=args.near_match_id,
                 rationale=rat, keep_text=args.keep_text)
    if args.json:
        print(json.dumps(res, ensure_ascii=False, sort_keys=True))
    elif res["written"]:
        print(f"reading filed: claim {res['claim_id']} read {res['reading']!r} by "
              f"{res['reader']['id']} (chain {res['chain'][:16]})")
    else:
        print(f"{_PROG} submit: {res.get('reason') or res.get('error')}", file=sys.stderr)
    return res["exit"]


#: The result shape of one ask.
ASK_FORMAT = "arcaeon-reading-ask/1"
#: Retries per claim after a failed call (the batch rule: one at most).
ASK_RETRIES = 1


def load_claims(path) -> list[dict]:
    """Read a claims JSONL file: `[{"claim_id", "claim", "near_match_id"?}]`.
    Raises ValueError naming the line on anything off."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise ValueError(f"cannot read claims file {path} [{type(e).__name__}]") from None
    out, seen = [], set()
    for i, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
        except ValueError:
            raise ValueError(f"{path} line {i} is not JSON") from None
        if not isinstance(obj, dict):
            raise ValueError(f"{path} line {i} is not a JSON object")
        cid, claim, near = obj.get("claim_id"), obj.get("claim"), obj.get("near_match_id")
        if not isinstance(cid, str) or not cid.strip():
            raise ValueError(f"{path} line {i}: claim_id must be a non-empty string")
        if not isinstance(claim, str):
            raise ValueError(f"{path} line {i}: claim must be a string")
        if near is not None and (not isinstance(near, str) or not near):
            raise ValueError(f"{path} line {i}: near_match_id must be a non-empty string")
        if cid in seen:
            raise ValueError(f"{path} line {i}: claim_id {cid!r} appears twice")
        seen.add(cid)
        out.append({"claim_id": cid, "claim": claim, "near_match_id": near})
    if not out:
        raise ValueError(f"{path} holds no claims")
    return out


def _criterion_text_in(path: Path, sha: str | None) -> tuple[str, str] | None:
    """(sha, text) of the named criterion, or of the latest one; None if absent."""
    from arcaeon.record.ledger import Ledger
    if not path.exists():
        return None
    found = None
    for r in Ledger(path):
        if isinstance(r, dict) and r.get("evt") == "criterion" and isinstance(r.get("text"), str):
            if sha is None or r.get("criterion_sha256") == sha:
                found = (r.get("criterion_sha256"), r["text"])
    return found


def ask(claims: list[dict], reader, ledger, *, criterion_text: str, send: bool = False,
        keep_text: bool = False, retries: int = ASK_RETRIES) -> dict:
    """Put each claim to one reader; write one reading per answered claim.

    Without `send` nothing is sent and nothing is written (the dry run). A
    claim whose call fails `retries + 1` times gets no reading and is listed
    under `could_not_look`.
    """
    from arcaeon.prove import readings as R
    from arcaeon.prove.readers import ReaderCallError, build_prompt
    path = Path(ledger)
    crit = R.normalize_criterion(criterion_text)
    base = {"format": ASK_FORMAT, "reader": reader.reader_info, "ledger": str(path),
            "criterion_sha256": R.sha256_text(crit), "claims": len(claims)}
    if not send:
        return {**base, "sent": False, "requests": 0, "endpoint_host": reader.endpoint_host,
                "first_prompt": build_prompt(crit, claims[0]["claim"]),
                "note": "dry run: nothing was sent; add --send to put these claims to the reader",
                "exit": _v.EXIT_GOOD}
    if base["criterion_sha256"] not in R._criteria_in(path):
        R.freeze_criterion(path, crit)
    written, cnl, requests = [], [], 0
    for c in claims:
        err = None
        for _attempt in range(1 + max(0, int(retries))):
            requests += 1
            try:
                row = reader.read(claim_id=c["claim_id"], claim_text=c["claim"],
                                  criterion_text=crit, near_match_id=c["near_match_id"],
                                  keep_text=keep_text)
            except ReaderCallError as e:
                err = e
                continue
            R.write_reading(path, row)
            written.append({"claim_id": c["claim_id"], "reading": row["reading"]})
            err = None
            break
        if err is not None:
            cnl.append({"claim_id": c["claim_id"], **_v.could_not_look(
                f"a reading of claim {c['claim_id']}", reader.endpoint_host,
                getattr(err, "reason_word", "network"),
                f"{err} (after {1 + max(0, int(retries))} tries); no reading was written")})
    return {**base, "sent": True, "requests": requests, "written": written,
            "could_not_look": cnl,
            "counts": {"claims": len(claims), "written": len(written), "could_not_look": len(cnl)},
            "exit": _v.EXIT_COULD_NOT_LOOK if cnl else _v.EXIT_GOOD}


def ask_main(argv: list[str] | None = None) -> int:
    """`second-read ask ...`: batch a claims file through one reader."""
    from arcaeon.prove import readings as R
    from arcaeon.prove.readers import DEFAULT_TIMEOUT, ReaderError, reader_from_spec
    p = argparse.ArgumentParser(prog=f"{_PROG} ask",
                                description="put every claim in a file to one reader "
                                            "(dry run unless --send)")
    p.add_argument("--claims", required=True, help='JSONL: {"claim_id", "claim"} per line')
    p.add_argument("--reader", required=True, help="a reader spec, e.g. ollama:qwen2.5-coder:3b")
    p.add_argument("--ledger", required=True, help="the readings ledger to append to")
    p.add_argument("--base-url", default=None, help="the endpoint, for openai_compat:")
    p.add_argument("--key-env", default=None, help="the environment variable holding the key")
    p.add_argument("--reader-id", default=None, help="the reader id to record")
    c = p.add_mutually_exclusive_group()
    c.add_argument("--criterion-sha256", help="a criterion frozen in the ledger")
    c.add_argument("--criterion-file", help="the criterion text (frozen first if new here)")
    p.add_argument("--keep-text", action="store_true", help="keep each answer's text in its row")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="seconds per call")
    p.add_argument("--send", action="store_true",
                   help="actually send the claims (a disclosure to that endpoint)")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    args = p.parse_args(argv)
    try:
        claims = load_claims(args.claims)
        reader = reader_from_spec(args.reader, base_url=args.base_url, key_env=args.key_env,
                                  reader_id=args.reader_id, timeout=args.timeout)
        if args.criterion_file:
            crit = _read_text(args.criterion_file, "criterion file")
            if not R.normalize_criterion(crit):
                raise ValueError("criterion file is empty")
        else:
            found = _criterion_text_in(Path(args.ledger), args.criterion_sha256)
            if found is None:
                raise ValueError(f"no criterion {'named ' + args.criterion_sha256 + ' ' if args.criterion_sha256 else ''}"
                                 f"is frozen in {args.ledger}; give --criterion-file")
            crit = found[1]
        if args.send and reader.key_env:
            reader._key()  # an unset key variable is bad usage, before any request
    except (ValueError, ReaderError) as e:
        print(f"{_PROG} ask: {e}", file=sys.stderr)
        return _v.EXIT_USAGE
    try:
        res = ask(claims, reader, args.ledger, criterion_text=crit, send=args.send,
                  keep_text=args.keep_text)
    except ReaderError as e:
        print(f"{_PROG} ask: {e}", file=sys.stderr)
        return _v.EXIT_USAGE
    if args.json:
        print(json.dumps(res, ensure_ascii=False, sort_keys=True))
    elif not res["sent"]:
        print(f"dry run: nothing sent. would send {res['claims']} claims to "
              f"{res['endpoint_host']} ({res['reader']['id']}); add --send to send")
        print("first claim as it would be sent:")
        print(res["first_prompt"])
    else:
        k = res["counts"]
        print(f"asked {k['claims']} claims of {res['reader']['id']}: {k['written']} readings "
              f"written, {k['could_not_look']} could not look")
        for item in res["could_not_look"]:
            print(f"  COULD NOT LOOK {item['claim_id']}: {item['reason']}")
        print("a reading is what that reader answered, not a finding about the claim")
    return res["exit"]


def _criterion(argv):
    from arcaeon.prove.readings import criterion_main
    return criterion_main(argv)


#: subcommand -> (handler(argv) -> exit code, one-line help)
SUBCOMMANDS = {
    "criterion": (_criterion, "freeze a criterion sentence into a readings ledger"),
    "compare": (compare_main, "line up two readings ledgers: COMPARED / MISSING / BROKEN / COULD NOT LOOK"),
    "submit": (submit_main, "file your own reading of one claim (the door for any AI or person)"),
    "ask": (ask_main, "put a claims file to one reader, one reading per claim (dry run unless --send)"),
}


def _usage() -> str:
    width = max(len(k) for k in SUBCOMMANDS)
    rows = [f"  {k.ljust(width)}  {v[1]}" for k, v in SUBCOMMANDS.items()]
    return (f"usage: {_PROG} <subcommand> [args...]\n\nsubcommands:\n" + "\n".join(rows)
            + "\n\nexit 0 COMPARED, 1 MISSING or BROKEN, 2 bad usage, 3 COULD NOT LOOK")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(_usage(), file=sys.stdout if argv else sys.stderr)
        return _v.EXIT_GOOD if argv else _v.EXIT_USAGE
    sub, rest = argv[0], argv[1:]
    if sub not in SUBCOMMANDS:
        print(f"{_PROG}: unknown subcommand {sub!r}\n{_usage()}", file=sys.stderr)
        return _v.EXIT_USAGE
    try:
        return SUBCOMMANDS[sub][0](rest)
    except SystemExit as e:  # argparse: --help is 0, bad usage is 2
        return e.code if isinstance(e.code, int) else (_v.EXIT_GOOD if e.code is None else _v.EXIT_USAGE)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
