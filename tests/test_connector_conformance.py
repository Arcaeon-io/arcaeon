# SPDX-License-Identifier: MIT
"""One conformance suite every registered connector adapter must pass.

The adapter set is discovered from the registry in arcaeon.connector.core (what
`adapter_for` resolves), never typed by hand here. A guard test checks that set
against the modules docs/CONNECTOR_ADAPTER.md names under "One base class", so an
adapter that is registered but not documented, or documented but not registered,
fails this file.

Per adapter, from its fixture dir tests/fixtures/<module>/ (or a minimal valid
input when it has none):

- shape: every row has the keys the doc says every row carries;
- three words: every relayed_verdict is VERIFIED, BROKEN or COULD NOT LOOK;
- signed_by_vendor on EVERY row, a bool, and False (no adapter documents a
  signed path: a vendor signature is only ever CLAIMED, never checked);
- the rollup / standing_verdict never says VERIFIED (doc: relayed, unsigned rows
  never make our own VERIFIED);
- hostile input never raises: it yields rows (COULD NOT LOOK) instead;
- core.import_verdict(adapter, hostile) gives one row that conforms too.
"""
from __future__ import annotations

import importlib
import json
import re
from pathlib import Path

import pytest

from arcaeon.connector import core
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
DOC = ROOT / "docs" / "CONNECTOR_ADAPTER.md"
AT = "2026-10-05T12:00:00Z"
OUR_WORDS = (VERIFIED, BROKEN, COULD_NOT_LOOK)

# ------------------------------------------------------------------ discovery


def _discover() -> dict:
    """name -> adapter, from core's registry. adapter_for on a name no adapter
    holds makes core import every built-in adapter (they register themselves).
    Only adapters defined in the arcaeon package count: another test may register
    a throwaway adapter (the doc's examplegate) into the same process."""
    core.adapter_for("")
    return {n: a for n, a in sorted(core._ADAPTERS.items())
            if type(a).__module__.startswith("arcaeon.")}


ADAPTERS = _discover()
NAMES = sorted(ADAPTERS)


def _doc_modules() -> list:
    text = DOC.read_text(encoding="utf-8")
    m = re.search(r"^## One base class\n(.*?)^## ", text, re.S | re.M)
    assert m, "docs/CONNECTOR_ADAPTER.md has no 'One base class' section"
    return sorted(set(re.findall(r"`(arcaeon\.(?:connector|prove)\.\w+)`", m.group(1))))


def _doc_names() -> set:
    names = set()
    for mod_name in _doc_modules():
        mod = importlib.import_module(mod_name)
        for v in vars(mod).values():
            if isinstance(v, core.VendorAdapter) and type(v).__module__ == mod_name:
                names.add(v.name)
    return names


# ------------------------------------------------------------------ per-adapter table
#
# Entry signatures differ, so each adapter gets a small row here:
#   module   the module that defines it; its fixture dir is tests/fixtures/<module tail>
#   ingest   how one payload becomes rows. mockscan is one row per payload, read by
#            core.import_verdict; every other adapter writes many rows and has its own
#            `ingest(raw, *, received_at=..., <its own options>)`.
#   kwargs   the adapter's options, set so the fixtures can map (OPA needs declared
#            paths, Snyk a score cut-off, Lakera a policy mode).
#   rollup   the name of its one-word-over-rows function, or None if it has none.
#   extra    keys the doc says EVERY row of this adapter carries, beyond the base row.
#   minimal  inputs to use when it has no fixture dir.
#   rules    mapping.rule values beyond the four the doc gives every row, when the
#            adapter's own doc section names them (reported: digest_mismatch).
#
# A registered adapter missing from this table fails test_every_adapter_has_an_entry.

_STD = ("signed_by_vendor", "standing", "input_sha256")

TABLE = {
    "mockscan": dict(
        module="arcaeon.connector.mockscan", ingest="import_verdict", kwargs={}, rollup=None,
        extra=("signed_by_vendor",),
        minimal=[
            b'{"scanner": "mockscan", "scan_id": "ms-1", "result": "pass",'
            b' "target": {"name": "a.pdf", "sha256": "' + b"ab" * 32 + b'"}}',
            b'{"scanner": "mockscan", "scan_id": "ms-2", "result": "fail"}',
            b'{"scanner": "mockscan", "result": "error",'
            b' "signature": {"alg": "ed25519", "sig": "' + b"A" * 88 + b'"}}',
        ]),
    "mcp-scan": dict(
        module="arcaeon.prove.mcp_scan", ingest="ingest", kwargs={}, rollup=None,
        extra=("signed_by_vendor",)),
    "opa": dict(
        module="arcaeon.connector.opa", ingest="ingest",
        kwargs={"allow_paths": ("authz/allow",), "deny_paths": ("authz/deny",)},
        rollup=None, extra=("signed_by_vendor",)),
    "snyk-agent-scan": dict(
        module="arcaeon.connector.snyk_agent_scan", ingest="ingest",
        kwargs={"broken_at_score": 500}, rollup="standing_verdict",
        extra=_STD + ("vendor_request_id", "finding")),
    "lakera-guard": dict(
        module="arcaeon.connector.lakera_guard", ingest="ingest",
        kwargs={"policy_mode": "enforce"}, rollup="standing_verdict",
        extra=_STD + ("request_sha256", "vendor_request_id", "finding")),
    "prisma-airs": dict(
        module="arcaeon.connector.prisma_airs", ingest="ingest", kwargs={},
        rollup="standing_verdict",
        extra=_STD + ("vendor_request_id", "ids", "refetch", "finding")),
    "kyverno": dict(
        module="arcaeon.connector.kyverno", ingest="ingest", kwargs={}, rollup="rollup",
        extra=_STD),
    "cedar": dict(
        module="arcaeon.connector.cedar", ingest="ingest", kwargs={}, rollup="rollup",
        extra=_STD),
    "reported": dict(
        module="arcaeon.connector.reported", ingest="ingest", kwargs={}, rollup="rollup",
        extra=("signed_by_vendor", "standing"), rules=("digest_mismatch",)),
    "hiddenlayer": dict(
        module="arcaeon.connector.hiddenlayer", ingest="ingest", kwargs={},
        rollup="standing_verdict", extra=_STD + ("vendor_request_id", "at", "alert")),
    "sentinelone": dict(
        module="arcaeon.connector.sentinelone", ingest="ingest", kwargs={},
        rollup="standing_verdict", extra=_STD + ("vendor_request_id", "at", "detection")),
    "e2b": dict(
        module="arcaeon.connector.e2b", ingest="ingest", kwargs={},
        rollup="standing_verdict", extra=_STD + ("run",)),
}

#: The keys docs/CONNECTOR_ADAPTER.md ("What a relayed row says") puts on every
#: row, plus signed_by_vendor, which the base row now always carries.
BASE_KEYS = ("kind", "relayed", "checked_by_us", "vendor", "vendor_id", "vendor_word",
             "relayed_verdict", "mapping", "subject", "attestation",
             "vendor_payload_digest", "vendor_payload_bytes", "received_at",
             "signed_by_vendor")
MAPPING_RULES = ("table", "unknown_word", "not_a_word", "not_read")
_HEX = re.compile(r"[0-9a-f]{64}")


def _entry(name):
    return TABLE.get(name) or dict(module=type(ADAPTERS[name]).__module__,
                                   ingest="import_verdict", kwargs={}, rollup=None, extra=())


def _rows(name, raw):
    e = _entry(name)
    if e["ingest"] == "import_verdict":
        return [core.import_verdict(ADAPTERS[name], raw, received_at=AT)]
    mod = importlib.import_module(e["module"])
    return mod.ingest(raw, received_at=AT, **e["kwargs"])


def _fixtures(name):
    e = _entry(name)
    d = FIXTURES / e["module"].rsplit(".", 1)[1]
    files = sorted(p for p in d.glob("*") if p.suffix in (".json", ".gz")) if d.is_dir() else []
    if files:
        return [(p.name, p.read_bytes()) for p in files]
    return [(f"minimal-{i}", b) for i, b in enumerate(e.get("minimal") or [b"{}"])]


def _conform(name, rows, where, *, own_keys=True):
    """own_keys=False for a core.import_verdict row: the adapter's own ingest keys
    are not on it, only the base row's."""
    assert isinstance(rows, list) and rows, f"{name} {where}: no rows"
    extra = _entry(name)["extra"] if own_keys else ()
    for i, r in enumerate(rows):
        at = f"{name} {where} row {i}"
        assert isinstance(r, dict), at
        missing = [k for k in BASE_KEYS + tuple(extra) if k not in r]
        assert not missing, f"{at}: missing {missing}"
        assert "verdict" not in r, f"{at}: a bare verdict key"
        assert r["kind"] == core.ROW_KIND, at
        assert r["relayed"] is True and r["checked_by_us"] is False, at
        assert r["relayed_verdict"] in OUR_WORDS, f"{at}: {r['relayed_verdict']!r}"
        assert isinstance(r["vendor"], dict) and r["vendor"].get("name") == name, at
        rules = MAPPING_RULES + (tuple(_entry(name).get("rules", ())) if own_keys else ())
        assert isinstance(r["mapping"], dict) and r["mapping"].get("rule") in rules, (
            f"{at}: mapping {r['mapping']!r}")
        att = r["attestation"]
        assert isinstance(att, dict) and att.get("checked_by_us") is False, at
        assert att.get("status") in (core.ATTESTATION_CLAIMED, core.ATTESTATION_NONE), at
        assert type(r["signed_by_vendor"]) is bool and r["signed_by_vendor"] is False, at
        if r["relayed_verdict"] == COULD_NOT_LOOK and r["mapping"]["rule"] != "table":
            assert isinstance(r.get("could_not_look"), dict), f"{at}: COULD NOT LOOK, no reason"
        if "standing" in extra:
            assert r["standing"] == "reported_by_sender", at
        if "input_sha256" in extra:
            v = r["input_sha256"]
            assert v is None or (isinstance(v, str) and _HEX.fullmatch(v)), at
        json.dumps(r, allow_nan=False)  # a row must be writable to the chain


# ------------------------------------------------------------------ hostile inputs

_NINE_MIB = 9 << 20
HOSTILE = {
    "empty": b"",
    "not-json": b"not json",
    "bom-bytes": b"\xff\xfe",
    "nine-mib": b'{"x": "' + b"a" * _NINE_MIB + b'"}',
    "open-10000": b"[" * 10000,
    "nested-10000": b"[" * 10000 + b"]" * 10000,
    "obj-nested-50": b'{"a":' * 50 + b"1" + b"}" * 50,
    "null": b"null",
    "number": b"42",
    "string": b'"pass"',
    "true": b"true",
    "empty-list": b"[]",
    "empty-object": b"{}",
    "10000-empty-objects": b"[" + b",".join([b"{}"] * 10000) + b"]",
    "duplicate-key": b'{"a": 1, "a": 2}',
    "nan": b'{"a": NaN}',
    "lone-surrogate": b'{"a": "\\ud800"}',
    "not-bytes-none": None,
    "not-bytes-int": 7,
}

_WRONG = (None, 0, -1, 1e308, "x", "", True, [], {}, [None], {"": None})


def _mutations(raw):
    """Wrong-type fields: each top-level key (or each key of each top-level list
    item) swapped for each wrong-typed value in turn."""
    try:
        doc = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001 - a gz fixture has no fields to mutate
        return
    if isinstance(doc, dict):
        for k in list(doc):
            for w in _WRONG:
                yield f"{k}={w!r}", json.dumps({**doc, k: w}).encode()
    elif isinstance(doc, list):
        for i, item in enumerate(doc[:4]):
            if isinstance(item, dict):
                for k in list(item):
                    for w in _WRONG:
                        new = list(doc)
                        new[i] = {**item, k: w}
                        yield f"[{i}].{k}={w!r}", json.dumps(new).encode()
            for w in _WRONG:
                new = list(doc)
                new[i] = w
                yield f"[{i}]={w!r}", json.dumps(new).encode()


# ------------------------------------------------------------------ the guard


def test_the_registry_is_not_empty():
    assert NAMES, "no adapter registered"


def test_the_registry_equals_the_doc_one_base_class_list():
    assert set(NAMES) == _doc_names(), (
        "docs/CONNECTOR_ADAPTER.md 'One base class' and the registry disagree")


def test_every_adapter_has_an_entry():
    assert set(NAMES) == set(TABLE), "add the new adapter to TABLE in this file"


# ------------------------------------------------------------------ per adapter

FIXTURE_CASES = [(n, f, b) for n in NAMES for f, b in _fixtures(n)]


@pytest.mark.parametrize("name,fixture,raw", FIXTURE_CASES,
                         ids=[f"{n}-{f}" for n, f, _ in FIXTURE_CASES])
def test_fixture_rows_conform(name, fixture, raw):
    _conform(name, _rows(name, raw), fixture)


@pytest.mark.parametrize("name", NAMES)
def test_rollup_is_never_verified(name):
    e = _entry(name)
    if not e["rollup"]:
        pytest.skip(f"{name} documents no rollup")
    fn = getattr(importlib.import_module(e["module"]), e["rollup"])
    rows = [r for _, b in _fixtures(name) for r in _rows(name, b)]
    forged = []
    for r in rows:  # every row forged to a relayed VERIFIED: still never our VERIFIED
        f = dict(r, relayed_verdict=VERIFIED, signed_by_vendor=True, vendor_word="pass")
        forged.append(f)
    for got in (fn(rows), fn(forged), fn([]), fn(None), fn([{"junk": 1}])):
        assert isinstance(got, dict)
        assert got["relayed_verdict"] in (BROKEN, COULD_NOT_LOOK)
        assert got.get("signed_by_vendor") is False


#: The one rollup shape (core.rollup_rows; docs/CONNECTOR_ADAPTER.md "The rollup").
ROLLUP_KEYS = {"relayed_verdict", "counts", "rows", "not_ours", "signed_by_vendor",
               "standing", "reason"}


@pytest.mark.parametrize("name", NAMES)
def test_rollup_has_one_shape_and_no_bare_verdict(name):
    """Every adapter's rollup is the same shape, built by core.rollup_rows: no bare
    `verdict` key (core.py: "There is deliberately NO bare `verdict` key"), and an
    all-clean relay reads COULD NOT LOOK with the clean count visible."""
    e = _entry(name)
    if not e["rollup"]:
        pytest.skip(f"{name} documents no rollup")
    fn = getattr(importlib.import_module(e["module"]), e["rollup"])
    rows = [r for _, b in _fixtures(name) for r in _rows(name, b)]
    clean = [r for r in rows if r["relayed_verdict"] == VERIFIED]
    for got in (fn(rows), fn(clean), fn([]), fn(None), fn([{"junk": 1}])):
        assert "verdict" not in got
        assert ROLLUP_KEYS <= set(got), sorted(ROLLUP_KEYS - set(got))
        assert set(got["counts"]) == set(OUR_WORDS)
        assert got["rows"] == sum(got["counts"].values())
        assert got["standing"] == "reported_by_sender"
    if clean:
        got = fn(clean)
        assert got["relayed_verdict"] == COULD_NOT_LOOK
        assert got["counts"] == {VERIFIED: len(clean), BROKEN: 0, COULD_NOT_LOOK: 0}
        assert got["reason_word"] == "missing"
    assert fn([])["reason_word"] == "empty"
    assert fn([{"junk": 1}])["not_ours"] == 1


@pytest.mark.parametrize("name,case", [(n, c) for n in NAMES for c in HOSTILE])
def test_hostile_input_never_raises(name, case):
    _conform(name, _rows(name, HOSTILE[case]), case)


@pytest.mark.parametrize("name,fixture,raw", FIXTURE_CASES,
                         ids=[f"{n}-{f}" for n, f, _ in FIXTURE_CASES])
def test_wrong_type_fields_never_raise(name, fixture, raw):
    for label, mutated in _mutations(raw):
        _conform(name, _rows(name, mutated), f"{fixture} {label}")


@pytest.mark.parametrize("name,case", [(n, c) for n in NAMES for c in HOSTILE])
def test_import_verdict_on_hostile_input_conforms(name, case):
    """Every adapter through core.import_verdict, the one-row path: even a
    many-row adapter's refusal row carries signed_by_vendor False."""
    row = core.import_verdict(ADAPTERS[name], HOSTILE[case], received_at=AT)
    _conform(name, [row], f"import_verdict {case}", own_keys=False)
    if name != "mockscan":
        assert row["relayed_verdict"] == COULD_NOT_LOOK


@pytest.mark.parametrize("name,fixture,raw", FIXTURE_CASES,
                         ids=[f"{n}-{f}" for n, f, _ in FIXTURE_CASES])
def test_import_verdict_on_fixture_conforms(name, fixture, raw):
    row = core.import_verdict(ADAPTERS[name], raw, received_at=AT)
    _conform(name, [row], f"import_verdict {fixture}", own_keys=False)
