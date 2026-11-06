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


class _LatestOnly(WitnessStore):
    """A local pin file whose reader sees only the latest pin per namespace."""

    def history(self, namespace):
        h = super().history(namespace)
        return h[-1:]

    def latest(self, namespace):
        h = super().history(namespace)
        return h[-1] if h else None


def test_repin_after_rewrite_does_not_launder_the_pack(ledger, tmp_path):
    """Review round 6 (M1): pin P1 at 3 rows, rewrite all three rows with
    every chain recomputed and add a 4th, pin P2 at 4 rows (accepted: rows
    grew). A pack built from the rewrite lists P2, and records.jsonl holds
    P2's head, so the named pin matches. P1, still in the pin file, is the
    disproof: the pack is BROKEN. The every-pin result used to be stored as
    `against_latest_pin` and never changed the verdict (exit 0).

    An honest build reads every pin and lists P1 (rewritten), so the pack is
    built through a writer that sees only `latest()` (the documented store
    contract), the way a pack built by an older export, or by hand, lists P2."""
    pins = tmp_path / "p.jsonl"
    lines = ledger.read_bytes().splitlines(keepends=True)
    ledger.write_bytes(b"".join(lines[:3]))
    p1 = publish_head(WitnessStore(pins), NS, Ledger(ledger))
    assert p1["rows"] == 3
    ledger.unlink()
    lg = Ledger(ledger)
    for i in range(4):
        lg.append({"ts": f"2026-09-0{i + 1}T10:00:00Z", "agent": "agent-a",
                   "event": "rewritten", "n": i})
    assert lg.verify().ok is True                      # clean on its own
    p2 = publish_head(WitnessStore(pins), NS, lg)
    assert p2["rows"] == 4 and p2["chain"] != p1["chain"]
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a", witness=_LatestOnly(pins),
               witness_namespace=NS)
    assert [x["rows"] for x in _manifest(out)["pins"]] == [4]
    res = verify_pack(out, witness=pins)
    st = _step(res)
    assert st["verdict"] == V.BROKEN and res["exit"] == 1
    assert st["pins"][0]["against_every_pin"] == "rewritten"
    assert "against_latest_pin" not in st["pins"][0]
    assert "rewritten" in st["finding"] and "earlier pin" in st["finding"]
    # Tamper one payload byte as well: records.jsonl now fails its own chain
    # (the chain step's BROKEN). The pins step still reads every pin off the
    # rows, so the re-pinned rewrite is still named here, not hidden behind
    # "local_broken".
    rec = out / "records.jsonl"
    b = rec.read_bytes()
    i = b.index(b"rewritten")
    rec.write_bytes(b[:i] + b"R" + b[i + 1:])
    st = _step(verify_pack(out, witness=pins))
    assert st["verdict"] == V.BROKEN
    assert st["pins"][0]["against_every_pin"] == "rewritten"


def test_local_pin_ok_reports_every_pin_compared(local_pack, pins):
    st = _step(verify_pack(local_pack, witness=pins))
    pin = st["pins"][0]
    assert pin["against_every_pin"] == "consistent" and pin["pins_compared"] == 1
    assert pin["pins_past_head"] == 0


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


# ---- review round 7: strict pins, the namespace, file order -------------------

def _plant(w, ns, rows, chain, as_of="2026-09-05T00:00:00Z"):
    """Append a correctly chained pin straight to the file, bypassing every
    refusal in WitnessStore.record (a hand edit, or another store)."""
    s = WitnessStore(w)
    rec = {"namespace": ns, "rows": rows, "chain": chain, "as_of": as_of,
           "received_at": None, "prev": s._tail_digest()}
    rec["self"] = s._digest_record(rec)
    with open(w, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


def _rewrite_ledger(ledger, n):
    ledger.unlink()
    lg = Ledger(ledger)
    for i in range(n):
        lg.append({"ts": f"2026-09-0{i + 1}T10:00:00Z", "agent": "agent-a",
                   "event": "rewritten", "n": i})
    assert lg.verify().ok is True                      # clean on its own
    return lg


def test_r7_b2_second_namespace_pack_needs_namespace(ledger, tmp_path):
    """Round-6 review B2: honest pin under prod, rewrite every row, pin the
    rewrite under prod2, export a pack naming prod2. Every pin the pack names
    agrees, and the pack verified. Now: COULD NOT LOOK without --namespace
    (the pack's own listed namespace never settles which is this ledger's),
    BROKEN with --namespace prod."""
    pins = tmp_path / "p.jsonl"
    publish_head(WitnessStore(pins), "prod", Ledger(ledger))
    lg = _rewrite_ledger(ledger, 4)
    publish_head(WitnessStore(pins), "prod2", lg)
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a", witness=str(pins), witness_namespace="prod2")
    assert [x["namespace"] for x in _manifest(out)["pins"]] == ["prod2"]
    res = verify_pack(out, witness=pins)
    st = _step(res)
    assert st["verdict"] == V.COULD_NOT_LOOK and res["exit"] == 3
    assert st["reason_word"] == "name_not_found" and "--namespace" in st["reason"]
    res = verify_pack(out, witness=pins, namespace="prod")
    st = _step(res)
    assert st["verdict"] == V.BROKEN and res["exit"] == 1
    assert "'prod'" in st["finding"] and "rewritten" in st["finding"]
    assert evidence_pack_cli.main(["verify", str(out), "--witness", str(pins)]) == 3
    assert evidence_pack_cli.main(["verify", str(out), "--witness", str(pins),
                                   "--namespace", "prod"]) == 1
    # The pack's own namespace named on purpose verifies, and an absent one
    # compares nothing.
    assert _step(verify_pack(out, witness=pins, namespace="prod2"))["verdict"] == V.VERIFIED
    st = _step(verify_pack(out, witness=pins, namespace="nope"))
    assert st["verdict"] == V.COULD_NOT_LOOK and st["reason_word"] == "name_not_found"


def test_r7_m1_pin_past_head_recorded_before_the_packs_pin_is_truncation(ledger, tmp_path):
    """Round-6 review M1: pins past the pack's head were all left out as
    "the pack is older". A pin past the head that the witness recorded
    BEFORE the pin the pack names means the witness had already seen more
    rows when it took the pack's pin: the pack is a truncation, BROKEN."""
    pins = tmp_path / "p.jsonl"
    publish_head(WitnessStore(pins), NS, Ledger(ledger))              # 4 rows
    lines = ledger.read_bytes().splitlines(keepends=True)
    ledger.write_bytes(b"".join(lines[:3]))                           # cut to 3
    lo = Ledger(ledger).head()
    with pytest.raises(ValueError, match="monotonic"):
        WitnessStore(pins).record(NS, lo)                             # record() refuses
    _plant(pins, NS, lo.rows, lo.chain)                               # a hand edit does not
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a", witness=_LatestOnly(pins), witness_namespace=NS)
    assert [x["rows"] for x in _manifest(out)["pins"]] == [3]
    res = verify_pack(out, witness=pins)
    st = _step(res)
    assert st["verdict"] == V.BROKEN and res["exit"] == 1
    assert st["pins"][0]["against_every_pin"] == "truncated"
    assert "before it pinned the head this pack names" in st["finding"]


@pytest.mark.parametrize("rows,chain", [(4, None), (4, ""), (True, "a" * 32),
                                        (-1, "a" * 32), (4.0, "a" * 32)])
def test_r7_pack_pin_file_with_a_malformed_pin_is_could_not_look(local_pack, pins,
                                                                rows, chain):
    _plant(pins, NS, rows, chain)
    res = verify_pack(local_pack, witness=pins)
    st = _step(res)
    assert st["verdict"] == V.COULD_NOT_LOOK and res["exit"] == 3
    assert st["reason_word"] == "unreadable" and "strict pin rules" in st["reason"]


def test_r7_pack_all_chainless_pin_file_is_could_not_look(ledger, tmp_path):
    """A pack that lists no pin, checked against a pin file whose every pin
    has no chain: nothing was compared, never VERIFIED."""
    out = tmp_path / "pack"
    build_pack(ledger, out)
    pins = tmp_path / "p.jsonl"
    for rows in (2, 4):
        _plant(pins, NS, rows, None)
    res = verify_pack(out, witness=pins, namespace=NS)
    st = _step(res)
    assert st["verdict"] == V.COULD_NOT_LOOK and res["exit"] == 3


# -- review round 8: legacy genesis pins and an empty pin file (unlisted path) --

def _r8_legacy_then_chained(tmp_path):
    """A ledger whose rows 1-3 were written before chaining (no chain) and rows
    4-6 after (chained), pinned honestly at (3, genesis) and at (6, C6)."""
    led = tmp_path / "legacy.jsonl"
    led.write_text("".join(json.dumps({"ts": f"2026-09-0{i + 1}T10:00:00Z",
                                       "agent": "agent-a", "event": "e"}) + "\n"
                           for i in range(3)), encoding="utf-8")
    pins = tmp_path / "r8pins.jsonl"
    store = WitnessStore(pins)
    p3 = publish_head(store, NS, Ledger(led))
    assert (p3["rows"], p3["chain"]) == (3, "genesis")
    lg = Ledger(led)
    for i in range(3, 6):
        lg.append({"ts": f"2026-09-0{i + 1}T10:00:00Z", "agent": "agent-a", "event": "e"})
    p6 = publish_head(store, NS, Ledger(led))
    assert p6["rows"] == 6 and p6["chain"] != "genesis"
    return led, pins


def test_r8_unlisted_pack_legacy_genesis_pin_plus_chained_pin_verifies(tmp_path):
    """Pack lists no pin; the pin file holds (3, genesis) over chainless rows
    and (6, C6) over chained ones, both honest. The genesis pin is not
    comparable, not a problem: VERIFIED with pin 6 compared, not BROKEN."""
    led, pins = _r8_legacy_then_chained(tmp_path)
    out = tmp_path / "pack"
    build_pack(led, out)
    res = verify_pack(out, witness=pins)
    st = _step(res)
    assert st["verdict"] != V.BROKEN, st
    assert st["verdict"] == V.VERIFIED, st
    assert st["pins_compared"] == 1


def test_r8_unlisted_pack_cut_below_a_genesis_pin_is_still_broken(tmp_path):
    """The same honest pins, but the pack holds only 2 of the 3 rows the
    genesis pin saw (and none of pin 6's): truncation, BROKEN."""
    led, pins = _r8_legacy_then_chained(tmp_path)
    lines = led.read_text(encoding="utf-8").splitlines(keepends=True)
    led.write_text("".join(lines[:2]), encoding="utf-8")
    out = tmp_path / "pack"
    build_pack(led, out)
    res = verify_pack(out, witness=pins, namespace=NS)
    st = _step(res)
    assert st["verdict"] == V.BROKEN and res["exit"] == 1, st
    assert "row 3" in st["finding"]


def test_r8_unlisted_pack_empty_pin_file_is_could_not_look(ledger, tmp_path):
    """An empty pin file compared nothing: COULD NOT LOOK, never VERIFIED."""
    out = tmp_path / "pack"
    build_pack(ledger, out)
    pins = tmp_path / "empty.jsonl"
    pins.write_bytes(b"")
    res = verify_pack(out, witness=pins)
    st = _step(res)
    assert st["verdict"] == V.COULD_NOT_LOOK and res["exit"] == 3, st
    assert st["reason_word"] == "empty"
