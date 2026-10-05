"""TE-31 / L2-12, end to end for EVERY registered connector adapter: fixture ->
ingest -> check.verdict.relayed rows -> `envelope seal --checks` (the rows ride
in the signed checks[]) -> `gate decide`; and the same rows through `gate
decide --checks FILE` give the same decision.

The adapters are discovered, not listed: every module under arcaeon.connector
is imported, the registry's lazy loader is run, and the test is parametrized
over whatever registered itself. A guard fails when an adapter class in the
arcaeon package is not registered, when the registry's own loader does not
reach it, or when it has no fixture folder in tests/fixtures/<name>/ (name
with - read as _). So an adapter folded in later (with its fixtures) is
covered without touching this file.

How rows are keyed. The gate keys a row by its `subject.sha256` (TE-31's
input_sha256): the sha256 of the bytes the checker judged. No adapter derives
that from its own input bytes (the payload's own digest is
`vendor_payload_digest`, raw-bytes scheme, which the gate never reads); each
takes it from the vendor's report, or has none. So each row is pointed at a
throwaway handed file: subject = {name, sha256 of that file}, everything else
exactly as the adapter wrote it.

One row per word. For each of BROKEN, COULD NOT LOOK and VERIFIED the first
row the adapter's fixtures give with that relayed_verdict is used (INGEST_KW
holds the switches some adapters need, e.g. OPA's allow / deny paths). An
adapter folded in later whose fixtures lack a word gets that row derived from
one of its own rows (the word swapped), so it is still covered; the adapters
on this base must produce all three words for real (KNOWN).

Throwaway Ed25519 key made in-test; HOME in tmp_path; no network."""
from __future__ import annotations

import base64
import copy
import importlib
import json
import os
import pkgutil
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

import arcaeon.connector as connector_pkg
from arcaeon import verdict as V
from arcaeon.connector import core
from arcaeon.prove import envelope as E
from arcaeon.prove import gate as G

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
AUD = "receiver-1"
DEAL, PURPOSE = "d-e2e", "delivery"
#: switches an adapter's ingest needs before it can say every word
INGEST_KW = {"opa": {"allow_paths": ("authz/allow",), "deny_paths": ("authz/deny",)},
             "lakera-guard": {"policy_mode": "enforce"}}
#: the adapters on this base: every word must come from a real fixture row
KNOWN = {"cedar", "e2b", "hiddenlayer", "kyverno", "lakera-guard", "mcp-scan", "mockscan",
         "opa", "prisma-airs", "reported", "snyk-agent-scan"}
#: sentinelone is left out on purpose: an alert export never says VERIFIED (a missing
#: alert is not a clean machine), so its VERIFIED row is always derived.


def _import_all() -> None:
    for m in pkgutil.iter_modules(connector_pkg.__path__):
        importlib.import_module(f"{connector_pkg.__name__}.{m.name}")
    core.adapter_for("")                         # the registry's own lazy loader


_import_all()


def _adapter_classes() -> list[type]:
    out, todo = [], list(core.VendorAdapter.__subclasses__())
    while todo:
        c = todo.pop()
        todo.extend(c.__subclasses__())
        if c.__module__.startswith("arcaeon.") and getattr(c, "name", ""):
            out.append(c)
    return out


REGISTRY = dict(sorted(core._ADAPTERS.items()))


def _fixture_dir(name: str) -> Path | None:
    for d in (FIXTURES / name, FIXTURES / name.replace("-", "_")):
        if d.is_dir():
            return d
    return None


def _ingest(adapter, raw: bytes, kw: dict) -> list:
    mod = sys.modules[type(adapter).__module__]
    if adapter.one_row_per_payload or not hasattr(mod, "ingest"):
        return [core.import_verdict(adapter, raw, received_at="2026-10-05T12:00:00Z")]
    return list(mod.ingest(raw, received_at="2026-10-05T12:00:00Z", **kw))


def _rows_for(name: str) -> list:
    adapter, d = REGISTRY[name], _fixture_dir(name)
    rows = []
    for f in sorted(d.glob("*.json")):
        raw = f.read_bytes()
        for kw in ({}, INGEST_KW.get(name)):
            if kw is None:
                continue
            rows += [r for r in _ingest(adapter, raw, kw)
                     if isinstance(r, dict) and r.get("kind") == core.ROW_KIND
                     and (r.get("vendor") or {}).get("name") == name]
    return rows


def _pick(name: str) -> tuple[dict, list]:
    """{word: row} and the words derived (not found in a fixture)."""
    rows = _rows_for(name)
    picked, derived = {}, []
    for word in core.OUR_WORDS:
        hit = next((r for r in rows if r.get("relayed_verdict") == word), None)
        if hit is None and rows:
            hit = copy.deepcopy(rows[0])
            hit["relayed_verdict"] = word
            hit.pop("could_not_look", None)
            derived.append(word)
        picked[word] = copy.deepcopy(hit)
    return picked, derived


# --- the guard: every adapter is in the registry and has fixtures -----------------------

def test_registry_is_not_empty_and_holds_every_adapter_class():
    assert len(REGISTRY) >= len(KNOWN)
    names = {c.name for c in _adapter_classes()}
    assert names <= set(REGISTRY), f"adapter classes never registered: {names - set(REGISTRY)}"
    assert KNOWN <= set(REGISTRY)


def test_the_registry_loader_reaches_every_adapter_module():
    """adapter_for's lazy import list, in a fresh interpreter, finds every
    adapter the package holds (a new module not wired in would be invisible to
    the gate's readers and to recheck)."""
    code = ("import json; from arcaeon.connector import core; core.adapter_for('');"
            "print(json.dumps(sorted(core._ADAPTERS)))")
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         env=env, timeout=120, check=True).stdout
    assert set(json.loads(out)) == set(REGISTRY)


@pytest.mark.parametrize("name", list(REGISTRY))
def test_every_adapter_has_fixtures_that_give_rows(name):
    d = _fixture_dir(name)
    assert d is not None, f"no tests/fixtures/{name.replace('-', '_')}/ for adapter {name!r}"
    assert _rows_for(name), f"{name}: no fixture in {d.name}/ gives a {core.ROW_KIND} row"
    picked, derived = _pick(name)
    if name in KNOWN:
        assert not derived, f"{name}: fixtures give no {derived} row"


# --- end to end -------------------------------------------------------------------------

def _key(tmp: Path) -> Path:
    k = tmp / "seal.key"
    k.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"), encoding="ascii")
    return k


def _handed(tmp: Path, sub: str, body: bytes) -> Path:
    f = tmp / sub / "deliverable.bin"
    f.parent.mkdir(parents=True)
    f.write_bytes(body)
    return f


def _point(row: dict, f: Path) -> dict:
    import hashlib
    row = copy.deepcopy(row)
    row["subject"] = {"name": f.name, "sha256": hashlib.sha256(f.read_bytes()).hexdigest()}
    return row


def _write_rows(tmp: Path, name: str, rows) -> Path:
    p = tmp / name
    p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8", newline="\n")
    return p


def _seal_cli(f: Path, key: Path, checks=(), capsys=None) -> str:
    argv = ["seal", str(f), "--label", "e2e", "--audience", AUD, "--deal", DEAL,
            "--purpose", PURPOSE, "--not-after", "7d", "--key", str(key)]
    for c in checks:
        argv += ["--checks", str(c)]
    assert E.main(argv) == V.EXIT_GOOD
    out = json.loads(capsys.readouterr().out)
    assert out.get("carried_checks", 0) == len(checks) and out["signed"]
    return out["signer"]


def _gate_cli(f: Path, did: str, tmp: Path, action: str, capsys, checks=(), cap=None):
    argv = ["decide", "--envelope", str(E.envelope_path(f)), "--audience", AUD,
            "--signer", did, "--action", action, "--deal", DEAL, "--purpose", PURPOSE,
            "--ledger", str(tmp / "tape.jsonl"), "--record-dir", str(tmp / "rec"), "--json"]
    for c in checks:
        argv += ["--checks", str(c)]
    if cap is not None:
        argv += ["--require-nonparty-check-above", cap, "--amount", "5000"]
    rc = G.main(argv)
    return rc, json.loads(capsys.readouterr().out)


def _shape(rc: int, out: dict) -> tuple:
    c = out.get("checks") or {}
    nc = out.get("nonparty_check") or {}
    return (rc, out["decision"], out["verdict"], c.get("veto") or nc.get("veto"),
            [b["checker"] for b in c.get("broken", [])])


@pytest.mark.parametrize("name", list(REGISTRY))
def test_adapter_rows_ride_the_envelope_and_the_gate_reads_them(name, tmp_path, monkeypatch,
                                                                capsys):
    monkeypatch.chdir(tmp_path)
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(tmp_path / "home"))
    picked, _ = _pick(name)
    key = _key(tmp_path)
    want = {V.BROKEN: (V.EXIT_BAD, "refuse", V.VERIFIED, G.CHECKER_BROKEN, [name]),
            V.COULD_NOT_LOOK: (V.EXIT_GOOD, "allow", V.VERIFIED, None, []),
            V.VERIFIED: (V.EXIT_GOOD, "allow", V.VERIFIED, None, [])}
    for word, row in picked.items():
        w = word.replace(" ", "_")
        body = f"{name} {word} deliverable\n".encode("utf-8")
        # A: the rows carried in the envelope's checks[]
        fa = _handed(tmp_path, f"{w}-carried", body)
        rows = _write_rows(tmp_path, f"{w}.jsonl", [_point(row, fa)])
        did = _seal_cli(fa, key, [rows], capsys)
        sealed = json.loads(base64.b64decode(json.loads(
            E.envelope_path(fa).read_text(encoding="utf-8"))["dsseEnvelope"]["payload"]))
        assert sealed["predicate"]["checks"][0]["vendor"]["name"] == name
        carried = _shape(*_gate_cli(fa, did, tmp_path, "pay", capsys))
        # B: the same rows as --checks FILE on an envelope that carries none
        fb = _handed(tmp_path, f"{w}-file", body)
        assert _seal_cli(fb, key, (), capsys) == did
        given = _shape(*_gate_cli(fb, did, tmp_path, "pay", capsys, checks=[rows]))
        assert carried == want[word], (name, word, carried)
        assert given == carried, (name, word, given, carried)
        # read is never vetoed by a checker
        assert _gate_cli(fa, did, tmp_path, "read", capsys)[0] == V.EXIT_GOOD
        if word == V.VERIFIED:
            # a VERIFIED relayed row is the sender's report: it never counts toward
            # the non-party rule, carried or given, so over the cap both refuse
            a = _shape(*_gate_cli(fa, did, tmp_path, "pay", capsys, cap="100"))
            b = _shape(*_gate_cli(fb, did, tmp_path, "pay", capsys, checks=[rows], cap="100"))
            assert a == b and a[:4] == (V.EXIT_COULD_NOT_LOOK, "refuse", V.VERIFIED,
                                        G.NONPARTY_VETO)
