"""K060: verify step 4, pins: inside the pack, then against the witness itself.

Local pin: checked against the pin file (--witness). Remote pin: read through
arcaeon.remote only with --remote; no network is COULD NOT LOOK "network",
never VERIFIED. The network is patched in every test here.
"""
import hashlib
import json

import pytest

from arcaeon import remote as R
from arcaeon import verdict as V
from arcaeon.prove import evidence_pack_cli
from arcaeon.prove.evidence_pack import build_pack
from arcaeon.prove.evidence_pack_verify import verify_pack
from arcaeon.record.ledger import Ledger
from arcaeon.record.ledger.witness import WitnessStore, publish_head

NS = "acme-ledger"


def _step(res):
    return next(c for c in res["checks"] if c["check"] == "pins")


def _manifest(out):
    return json.loads((out / "manifest.json").read_text(encoding="utf-8"))


def _write_manifest(out, m):
    (out / "manifest.json").write_text(json.dumps(m, indent=2), encoding="utf-8")


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Any real request from these tests is a failure."""
    def refuse(*a, **kw):
        raise AssertionError("network reached in a test")
    monkeypatch.setattr(R, "_request", refuse)


@pytest.fixture
def pins(ledger, tmp_path):
    p = tmp_path / "pins.jsonl"
    publish_head(WitnessStore(p), NS, Ledger(ledger))
    return p


@pytest.fixture
def local_pack(ledger, pins, tmp_path):
    out = tmp_path / "pack"
    res = build_pack(ledger, out, agent="agent-a", witness=str(pins), witness_namespace=NS)
    assert res["exit"] == 0
    return out


class HostedStub:
    """A remote witness client as the export sees one: latest() plus a
    self-declared remote_url descriptor. The pin carries its public commit."""

    def __init__(self, ledger):
        h = Ledger(ledger).head()
        self.pin = {"namespace": NS, "rows": h.rows, "chain": h.chain,
                    "as_of": "2026-09-27T12:00:00Z", "commit": "abc123",
                    "raw_record_url": "https://example.invalid/pins/acme.json"}

    def latest(self, namespace):
        return dict(self.pin) if namespace == NS else None

    def witness_descriptor(self):
        return {"kind": "remote_url", "identifier": "https://witness.example.invalid",
                "independence": "externally_verifiable"}


@pytest.fixture
def remote_pack(ledger, tmp_path):
    out = tmp_path / "rpack"
    build_pack(ledger, out, agent="agent-a", witness=HostedStub(ledger),
               witness_namespace=NS)
    assert _manifest(out)["pins"][0]["commit"] == "abc123"
    return out


# ---- local -----------------------------------------------------------------

def test_local_pin_ok(local_pack, pins):
    res = verify_pack(local_pack, witness=pins)
    st = _step(res)
    assert st["verdict"] == V.VERIFIED and st["pins_checked"] == 1
    assert st["pins"][0]["where"] == "local"
    assert res["verdict"] == V.VERIFIED and res["exit"] == 0


def test_local_pin_ok_via_cli(local_pack, pins):
    assert evidence_pack_cli.main(["verify", str(local_pack), "--witness", str(pins)]) == 0


def test_local_pin_without_pin_file_is_could_not_look(local_pack):
    res = verify_pack(local_pack)
    st = _step(res)
    assert st["verdict"] == V.COULD_NOT_LOOK and st["reason_word"] == "missing"
    assert res["exit"] == 3


def test_local_pin_mismatch_is_broken(local_pack, tmp_path):
    """A pin file that holds a different head for the namespace: BROKEN."""
    other = tmp_path / "other.jsonl"
    lg = Ledger(other)
    lg.append({"ts": "2026-09-01T10:00:00Z", "agent": "z", "event": "x"})
    wrong = tmp_path / "wrong_pins.jsonl"
    publish_head(WitnessStore(wrong), NS, lg)
    res = verify_pack(local_pack, witness=wrong)
    st = _step(res)
    assert st["verdict"] == V.BROKEN and res["exit"] == 1
    assert "holds no pin" in st["finding"]


def test_later_pin_does_not_accuse_an_older_pack(local_pack, ledger, pins):
    lg = Ledger(ledger)
    lg.append({"ts": "2026-09-04T08:00:00Z", "agent": "agent-a", "event": "x"})
    publish_head(WitnessStore(pins), NS, lg)
    st = _step(verify_pack(local_pack, witness=pins))
    assert st["verdict"] == V.VERIFIED
    assert st["pins"][0]["pin_file_latest_rows"] == 5


def test_namespace_absent_from_pin_file_is_could_not_look(local_pack, tmp_path):
    empty = tmp_path / "elsewhere.jsonl"
    lg = Ledger(tmp_path / "x.jsonl")
    lg.append({"a": 1})
    publish_head(WitnessStore(empty), "some-other-ns", lg)
    st = _step(verify_pack(local_pack, witness=empty))
    assert st["verdict"] == V.COULD_NOT_LOOK and st["reason_word"] == "name_not_found"


# ---- inside the pack ---------------------------------------------------------

def test_tail_cut_head_rewritten_pins_dropped_is_broken(local_pack):
    """Cut the tail, fix the hash, rewrite chain_head, drop the pins: the
    window (lines 1 and 3) does not cover line 4, so the pins step catches it."""
    rec = local_pack / "records.jsonl"
    rec.write_bytes(b"".join(rec.read_bytes().splitlines(keepends=True)[:3]))
    head = Ledger(rec).head()
    m = _manifest(local_pack)
    m["chain_head"].update({"chain": head.chain, "rows": head.rows})
    m["pins"] = []
    m["files"]["records.jsonl"] = hashlib.sha256(rec.read_bytes()).hexdigest()
    _write_manifest(local_pack, m)
    res = verify_pack(local_pack)
    assert res["checks"][0]["verdict"] == V.VERIFIED
    assert next(c for c in res["checks"]
                if c["check"] == "records chain and head")["verdict"] == V.VERIFIED
    st = _step(res)
    assert st["verdict"] == V.BROKEN and res["exit"] == 1
    assert "integrity.json's witness block" in st["finding"]
    assert "row count mismatch" in st["finding"]


def test_tail_cut_below_the_pin_is_broken(local_pack):
    rec = local_pack / "records.jsonl"
    rec.write_bytes(b"".join(rec.read_bytes().splitlines(keepends=True)[:3]))
    head = Ledger(rec).head()
    m = _manifest(local_pack)
    m["chain_head"].update({"chain": head.chain, "rows": head.rows})
    m["files"]["records.jsonl"] = hashlib.sha256(rec.read_bytes()).hexdigest()
    _write_manifest(local_pack, m)
    st = _step(verify_pack(local_pack))
    assert st["verdict"] == V.BROKEN
    assert "does not hold the head pinned" in st["finding"]


def test_no_pins_passes_the_step_and_says_so(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out)
    st = _step(verify_pack(out))
    assert st["verdict"] == V.VERIFIED and st["pins_checked"] == 0
    assert "not witnessed" in st["note"]


# ---- remote ------------------------------------------------------------------

def test_remote_pin_ok_patched(remote_pack, monkeypatch):
    calls = []

    def fake_request(method, url, body=None, key=None, timeout=None):
        calls.append((method, url))
        return 200, {"witnessed": True, "is_current_head": True,
                     "raw_record_url": "https://example.invalid/pins/acme.json"}
    monkeypatch.setattr(R, "_request", fake_request)
    res = verify_pack(remote_pack, remote=True)
    st = _step(res)
    assert st["verdict"] == V.VERIFIED and st["pins"][0]["where"] == "remote"
    assert res["exit"] == 0
    assert len(calls) == 1 and calls[0][0] == "GET" and "/api/verify?" in calls[0][1]


def test_remote_pin_unreachable_is_exit_3_network(remote_pack, monkeypatch):
    monkeypatch.setattr(R, "_request",
                        lambda *a, **kw: (0, {"error": "witness unreachable: no route"}))
    res = verify_pack(remote_pack, remote=True)
    st = _step(res)
    assert st["verdict"] == V.COULD_NOT_LOOK and st["reason_word"] == "network"
    assert res["verdict"] == V.COULD_NOT_LOOK and res["exit"] == 3


def test_remote_pin_unread_without_flag_is_network_never_verified(remote_pack):
    # the autouse fixture makes any request fail the test: none is made
    res = verify_pack(remote_pack)
    st = _step(res)
    assert st["verdict"] == V.COULD_NOT_LOOK and st["reason_word"] == "network"
    assert res["exit"] == 3


def test_remote_pin_not_witnessed_is_broken(remote_pack, monkeypatch):
    monkeypatch.setattr(R, "_request", lambda *a, **kw: (200, {"witnessed": False}))
    res = verify_pack(remote_pack, remote=True)
    assert _step(res)["verdict"] == V.BROKEN and res["exit"] == 1


def test_remote_via_cli_unreachable_exit_3(remote_pack, monkeypatch, capsys):
    monkeypatch.setattr(R, "_request", lambda *a, **kw: (0, {"error": "offline"}))
    assert evidence_pack_cli.main(["verify", str(remote_pack), "--remote"]) == 3
    assert "[network]" in capsys.readouterr().out
