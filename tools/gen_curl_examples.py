# SPDX-License-Identifier: MIT
"""Generate clients/curl/EXAMPLES.md from the OpenAPI document (KH1).

    py tools/gen_curl_examples.py            write clients/curl/EXAMPLES.md
    py tools/gen_curl_examples.py --check    exit 1 if EXAMPLES.md has drifted
    py tools/gen_curl_examples.py --print    print it instead of writing

The method, path, summary and whether the token is sent come from
docs/openapi.json (the same bytes `arcaeon schema --format openapi` prints).
The sample bodies live here, and every one is checked against the route's
request schema before anything is written: a field the schema does not
declare, or a required field left out, stops the tool (exit 2). Every free
route (`x-arcaeon-tier: free`) gets exactly one example; a free route with no
sample, or a sample for a route that is not free or not in the document,
stops it too. The paid route is named, never exampled: an example would spend.

The examples run in order in an empty served directory: earlier steps write
the files later ones read. tests/heavy/test_kh1_three_languages.py runs every
one against a loopback `arcaeon serve` and checks the answer each claims.
Stdlib only; the output is deterministic (same document, same bytes).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OPENAPI = REPO / "docs" / "openapi.json"
OUT = REPO / "clients" / "curl" / "EXAMPLES.md"

TAPE = "arcaeon-tape/1"
MANDATE = {"who": "demo-agent", "allowed_acts": ["search_*", "place_order"],
           "forbidden_acts": ["delete_*"],
           "spend_cap": {"amount": "60.00", "currency": "USD"}}
CRITERION = "Is the claim stated in the refund policy text?"
CLAIM = "Refunds are accepted within 30 days of purchase."


def _tape_row(side: str) -> dict:
    return {"evt": "tape_call", "tape": TAPE, "side": side, "idx": 1, "tool": "search",
            "req": "sha256:req-1", "resp": "sha256:resp-1"}


def _reading(ledger: str, reader: str) -> dict:
    return {"ledger": ledger, "reader_id": reader, "provider": "local", "claim_id": "c1",
            "claim": CLAIM, "criterion": CRITERION, "reading": "yes"}


#: The walk, in order. Kinds:
#:   ("file", name, text, note)               write a file the API cannot make
#:   ("setup", operationId, body, note)       a call that makes an input
#:   ("example", operationId, body, answers)  THE example for that route
#:   ("cli", argv, note)                      an `arcaeon` command (no route makes it)
#:   ("python", code, note)                   a one-line helper, no jq needed
#: A GET example has body None. A body that is a string starting with "@" is
#: sent from that file (curl -d @file). `answers` is (verdict or None, exit).
STEPS: list[tuple] = [
    ("file", "mandate.json", json.dumps(MANDATE, indent=1) + "\n",
     "a mandate for the mandate check (no route writes one)"),
    ("setup", "log", {"ledger": "tape_agent.jsonl", "row": _tape_row("agent")},
     "the agent side's tape: one call"),
    ("setup", "log", {"ledger": "tape_tool.jsonl", "row": _tape_row("tool")},
     "the tool side's tape: the same call"),
    ("setup", "readings", _reading("readings_a.jsonl", "reader-a"),
     "the first reader's reading of one claim"),
    ("example", "health", None, (None, None)),
    ("example", "openapi", None, (None, None)),
    ("example", "index", None, (None, None)),
    ("example", "log", {"ledger": "calls.jsonl",
                        "fields": {"tool": "search", "query": "refund policy"}}, (None, 0)),
    ("example", "verify", {"ledger": "calls.jsonl"}, ("VERIFIED", 0)),
    ("example", "reconcile", {"tape_a": "tape_agent.jsonl", "tape_b": "tape_tool.jsonl"},
     ("MATCHED", 0)),
    ("example", "pin", {"ledger": "calls.jsonl", "witness": "pins.jsonl", "ns": "demo"},
     (None, 0)),
    ("example", "audit_export", {"ledger": "calls.jsonl", "out": "bundle"}, (None, 0)),
    ("example", "audit_verify", {"path": "bundle"}, ("VERIFIED", 0)),
    ("example", "evidence_pack", {"ledger": "calls.jsonl", "out": "pack"}, ("VERIFIED", 0)),
    ("example", "evidence_pack_verify", {"pack": "pack"}, ("VERIFIED", 0)),
    ("example", "export_aat", {"ledger": "calls.jsonl", "out": "calls.aat.jsonl"},
     ("VERIFIED", 0)),
    ("example", "mandate_check",
     {"mandate": "mandate.json",
      "fields": {"name": "place_order", "amount": "19.00", "currency": "USD"}},
     ("inside", 0)),
    ("example", "readings", _reading("readings_b.jsonl", "reader-b"), (None, 0)),
    ("example", "second_read_compare", {"a": "readings_a.jsonl", "b": "readings_b.jsonl"},
     ("COMPARED", 0)),
    ("cli", ["arcaeon", "second-read", "compare", "readings_a.jsonl", "readings_b.jsonl",
             "--receipt", "receipt.json"],
     "issue that comparison as a local receipt (the CLI's --receipt; no route issues one)"),
    ("example", "receipt_verify", {"receipt": "receipt.json"}, ("VERIFIED", 0)),
    ("example", "handshake_propose",
     {"ledger": "agent_a.jsonl",
      "terms": {"task": "summarize the refund policy", "fee": "5.00", "currency": "USD"}},
     (None, 0)),
    ("python",
     "import json; a = json.load(open('proposal_answer.json')); "
     "json.dump({'ledger': 'agent_b.jsonl', 'proposal': a['proposal']}, "
     "open('accept.json', 'w'))",
     "hand the proposal to the other side: wrap it in the accept body"),
    ("example", "handshake_accept", "@accept.json", (None, 0)),
    ("example", "handshake_verify", {"a": "agent_a.jsonl", "b": "agent_b.jsonl"},
     ("AGREED TERMS", 0)),
    ("example", "status", None, (None, 0)),
]

#: The body shape a file-sent example stands for, checked like any other body.
FILE_BODIES = {"@accept.json": {"ledger": "agent_b.jsonl", "proposal": {}}}

#: Where an example saves its answer (curl -o) for a later step to read.
SAVE_AS = {"handshake_propose": "proposal_answer.json"}


class Bad(ValueError):
    pass


def load(path: Path = OPENAPI) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def operations(doc: dict) -> dict:
    """operationId -> (METHOD, path, operation) for every operation in the document."""
    ops = {}
    for path, item in doc["paths"].items():
        for method, op in item.items():
            ops[op["operationId"]] = (method.upper(), path, op)
    return ops


def _schema(doc: dict, op: dict) -> dict | None:
    rb = op.get("requestBody")
    if not rb:
        return None
    ref = rb["content"]["application/json"]["schema"]["$ref"]
    return doc["components"]["schemas"][ref.rsplit("/", 1)[1]]


def _check_body(doc: dict, oid: str, op: dict, body) -> None:
    schema = _schema(doc, op)
    if schema is None:
        if body is not None:
            raise Bad(f"{oid}: the route takes no body, the sample has one")
        return
    if isinstance(body, str):
        if body not in FILE_BODIES:
            raise Bad(f"{oid}: {body} has no declared shape in FILE_BODIES")
        body = FILE_BODIES[body]
    if not isinstance(body, dict):
        raise Bad(f"{oid}: the route takes a JSON object body")
    extra = sorted(set(body) - set(schema.get("properties", {})))
    if extra:
        raise Bad(f"{oid}: the request schema declares no {', '.join(extra)}")
    missing = sorted(set(schema.get("required", [])) - set(body))
    if missing:
        raise Bad(f"{oid}: the sample leaves out required {', '.join(missing)}")


def validate(doc: dict) -> None:
    ops = operations(doc)
    free = {oid for oid, (_, _, op) in ops.items() if op.get("x-arcaeon-tier") == "free"}
    seen: list[str] = []
    for step in STEPS:
        if step[0] not in ("setup", "example"):
            continue
        oid = step[1]
        if oid not in ops:
            raise Bad(f"{oid}: not an operation in the OpenAPI document")
        if oid not in free:
            raise Bad(f"{oid}: not a free route; the examples never spend")
        _check_body(doc, oid, ops[oid][2], step[2])
        if step[0] == "example":
            seen.append(oid)
    dup = sorted({o for o in seen if seen.count(o) > 1})
    if dup:
        raise Bad(f"more than one example for {', '.join(dup)}")
    lacking = sorted(free - set(seen))
    if lacking:
        raise Bad(f"free routes with no example: {', '.join(lacking)}")


def _json(body) -> str:
    text = json.dumps(body, ensure_ascii=True)
    if "'" in text:
        raise Bad("a sample body holds a single quote, which the shell line cannot carry")
    return text


def curl_line(doc: dict, oid: str, body) -> str:
    """The exact shell line for one call, with $ARCAEON and $TOKEN left for the shell."""
    method, path, op = operations(doc)[oid]
    parts = ["curl -s"]
    if op.get("security") != []:
        parts.append('-H "Authorization: Bearer $TOKEN"')
    if method == "POST":
        parts.append('-H "Content-Type: application/json"')
        parts.append(f"-d {body}" if isinstance(body, str) else f"-d '{_json(body)}'")
    if oid in SAVE_AS:
        parts.append(f"-o {SAVE_AS[oid]}")
    parts.append(f'"$ARCAEON{path}"')
    return " ".join(parts)


def python_line(code: str) -> str:
    return f'python -c "{code}"'


def _answers(oid: str, answers) -> str:
    verdict, code = answers
    if oid == "index":
        return "the local dashboard page (HTML), HTTP 200"
    if oid == "health":
        return "a small JSON object saying the server is up, HTTP 200"
    if oid == "openapi":
        return "this API as an OpenAPI 3.1 document, HTTP 200"
    head = f"`\"verdict\": \"{verdict}\"`, " if verdict else ""
    return f"{head}`\"exit\": {code}`, HTTP 200"


def render(doc: dict) -> str:
    validate(doc)
    ops = operations(doc)
    server = doc["servers"][0]["url"]
    paid = sorted(f"`{m} {p}`" for oid, (m, p, op) in ops.items()
                  if op.get("x-arcaeon-tier") != "free")
    n = sum(1 for s in STEPS if s[0] == "example")
    L = [
        "# arcaeon serve with plain curl",
        "",
        "GENERATED by `tools/gen_curl_examples.py` from `docs/openapi.json`; do not edit by",
        "hand (`py tools/gen_curl_examples.py --check` fails on drift). Every example below",
        "is run, in this order, against a loopback server by",
        "`tests/heavy/test_kh1_three_languages.py`, which checks the answer each one names.",
        "",
        f"{n} examples, one per free route. Not exampled, because it spends: "
        f"{', '.join(paid) or 'none'}.",
        "",
        "## Before you start",
        "",
        "Start a server in an empty directory and keep it running; paths in the bodies are",
        "relative to that directory (the server refuses any path outside it). The lines are",
        "POSIX shell: bash, zsh, Git Bash, WSL, macOS. In PowerShell call `curl.exe` and put",
        "each body in a file sent with `--data-binary @body.json`.",
        "",
        "```sh",
        "arcaeon serve --port 0          # prints: listening on http://127.0.0.1:NNNN",
        "# in a second shell, in the same directory:",
        f"ARCAEON=http://127.0.0.1:NNNN   # the address it printed ({server} by default)",
        "TOKEN=$(arcaeon serve --print-token)",
        "```",
        "",
        "Every `/v1` route answers HTTP 200 whenever a verdict was reached, good or bad, with",
        "the verdict and an integer `exit` in the body: 0 good, 1 a bad finding, 2 bad usage,",
        "3 COULD NOT LOOK. A verdict never rides in the HTTP status. 400 is bad usage, 401 a",
        "missing or wrong token, 413 a body over 10 MB.",
        "",
        "## Setup",
        "",
        "Three inputs the examples read and no example makes.",
        "",
    ]
    setup_done = False
    for step in STEPS:
        kind = step[0]
        if kind == "example" and not setup_done:
            L += ["## Examples", ""]
            setup_done = True
        if kind == "file":
            _, name, text, note = step
            L += [f"Write `{name}`: {note}.", "", "```sh", f"cat > {name} <<'EOF'",
                  text.rstrip("\n"), "EOF", "```", ""]
        elif kind == "setup":
            _, oid, body, note = step
            method, path, _ = ops[oid]
            L += [f"`{method} {path}`: {note}.", "", "```sh", curl_line(doc, oid, body),
                  "```", ""]
        elif kind == "cli":
            _, argv, note = step
            L += [f"Then {note}:", "", "```sh", " ".join(argv), "```", ""]
        elif kind == "python":
            _, code, note = step
            L += [f"Then {note}:", "", "```sh", python_line(code), "```", ""]
        elif kind == "example":
            _, oid, body, answers = step
            method, path, op = ops[oid]
            L += [f"### {method} {path}", "", f"{op['summary'][:1].upper()}{op['summary'][1:]}.",
                  "", "```sh", curl_line(doc, oid, body), "```", "",
                  f"Answers: {_answers(oid, answers)}.", ""]
    return "\n".join(L).rstrip("\n") + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="gen_curl_examples",
                                 description="clients/curl/EXAMPLES.md from docs/openapi.json")
    ap.add_argument("--openapi", default=str(OPENAPI), help="the OpenAPI document to read")
    ap.add_argument("--out", default=str(OUT), help="where EXAMPLES.md lives")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true", help="exit 1 if the file has drifted")
    g.add_argument("--print", action="store_true", help="print, do not write")
    a = ap.parse_args(argv)
    try:
        text = render(load(Path(a.openapi)))
    except Bad as e:
        print(f"gen_curl_examples: {e}", file=sys.stderr)
        return 2
    out = Path(a.out)
    if a.print:
        sys.stdout.write(text)
        return 0
    if a.check:
        try:
            have = out.read_bytes().decode("utf-8")
        except OSError:
            have = None
        if have != text:
            print(f"gen_curl_examples: {out} has drifted from the OpenAPI document; "
                  "run `py tools/gen_curl_examples.py`", file=sys.stderr)
            return 1
        return 0
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(text.encode("utf-8"))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
