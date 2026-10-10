# SPDX-License-Identifier: MIT
"""Gaps the 2026-10-10 must-fail pass closed: each test here fails with one or
more planted defects (named in its docstring by mutant id) and passes on the
real code. None of them touches the code under test.

The pass aimed at one failure: a broken, edited or truncated record reading as
verified. Mutant ids and the full table are in the pass's report.
"""
import json

import pytest

from arcaeon.record.adapter import _ledger as adapter_ledger
from arcaeon.record.ledger import Ledger


# --- the adapter's FALLBACK verifier (no arcaeon-ledger importable) -------------
# tests/ledger/test_adapter_fallback_verify.py covers this path, but it imports
# `adapter.arcaeon_adapter`, which does not exist, so it is never collected.

@pytest.fixture
def fallback(monkeypatch):
    monkeypatch.setattr(adapter_ledger, "_HAVE_LEDGER", False)
    return adapter_ledger


def _fallback_log(tmp_path, fallback, n=3):
    log = tmp_path / "seam.jsonl"
    lg = fallback.open_ledger(str(log))
    for i in range(n):
        lg.append({"i": i})
    return log


def test_fallback_empty_seam_log_is_not_a_green(tmp_path, fallback):
    """F01, F06: an empty seam log checked nothing; ok is None and the verdict is falsy."""
    log = tmp_path / "seam.jsonl"
    log.write_text("", encoding="utf-8")
    v = fallback.verify_seam_log(str(log))
    assert v.ok is None and not v and v.verified_scope == "empty"


def test_fallback_one_edited_value_is_a_break(tmp_path, fallback):
    """F02, F04: one value edited after the write is one break, and one break is red."""
    log = _fallback_log(tmp_path, fallback)
    assert fallback.verify_seam_log(str(log)).ok is True
    lines = log.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[1])
    row["i"] = 41
    lines[1] = json.dumps(row)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    v = fallback.verify_seam_log(str(log))
    assert v.ok is False and v.breaks == 1 and v.first_break == "line 2: chain mismatch"


def test_fallback_unparseable_line_is_a_break(tmp_path, fallback):
    """F03: a torn or garbage line is counted as a break, not stepped over."""
    log = _fallback_log(tmp_path, fallback, n=1)
    with log.open("a", encoding="utf-8") as fh:
        fh.write('{"i": 1, "chain": \n')
    v = fallback.verify_seam_log(str(log))
    assert v.ok is False and v.breaks == 1 and "unparseable" in v.first_break


def test_fallback_unreadable_seam_log_is_not_verified(tmp_path, fallback):
    """F05: a path that cannot be read (here a directory) is never ok."""
    v = fallback.verify_seam_log(str(tmp_path))
    assert v.ok is False and not v


# --- verify_file ----------------------------------------------------------------

def test_a_row_the_chain_rule_cannot_hash_is_a_break_not_a_green(tmp_path, monkeypatch):
    """L07: the unhashable-row branch. On CPython 3.13 no file reaches it (every
    line json parses also hashes), so the fault is injected: when the chain rule
    raises on a row, the verdict is red and names the line, never ok."""
    import arcaeon.record.ledger as L
    p = tmp_path / "a.jsonl"
    for i in range(3):
        Ledger(p).append({"op": i})
    real = L._chain

    def chain(prev, obj):
        if obj.get("op") == 1:
            raise TypeError("planted: this row cannot be hashed")
        return real(prev, obj)

    monkeypatch.setattr(L, "_chain", chain)
    r = L.verify_file(p)
    assert r.ok is False and r.breaks == 1
    assert r.first_break == "line 2: unhashable row (TypeError)"


# --- Ledger.head ----------------------------------------------------------------

def test_head_of_a_bounded_log_carries_none_not_a_green(tmp_path):
    """L22: a log whose first row carries no chain verifies bounded (ok=None);
    its head must say the same, never ok=True. It still pins (bounded is not
    broken)."""
    p = tmp_path / "a.jsonl"
    p.write_text(json.dumps({"legacy": "row with no chain"}) + "\n", encoding="utf-8")
    Ledger(p).append({"op": 1})
    h = Ledger(p).head()
    assert h.ok is None and h.rows == 2
    assert "rows=2" in h.as_pin()


def test_head_of_a_path_that_cannot_be_read_is_red_not_a_fresh_genesis(tmp_path):
    """L24: only FileNotFoundError is the never-written state. A path under a
    regular file (stat raises NotADirectoryError) cannot be read; its head is
    red and refuses to pin instead of pinning a fresh genesis."""
    from arcaeon.record.ledger import UnverifiedLedgerError
    f = tmp_path / "a-file"
    f.write_text("not a directory", encoding="utf-8")
    h = Ledger(f / "ledger.jsonl").head()
    assert h.ok is False
    with pytest.raises(UnverifiedLedgerError):
        h.as_pin()


# --- the witness pin file -------------------------------------------------------

def test_witness_refuses_a_pin_one_row_below_its_high_water(tmp_path):
    """W03: a witness never goes backward, not even by one row: cut the last row
    off a pinned log and re-pin, and the pin is refused."""
    from arcaeon.record.ledger import WitnessStore, publish_head
    p, store = tmp_path / "a.jsonl", WitnessStore(tmp_path / "pins.jsonl")
    for i in range(5):
        Ledger(p).append({"op": i})
    publish_head(store, "ns", Ledger(p))
    lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
    p.write_text("".join(lines[:4]), encoding="utf-8")
    with pytest.raises(ValueError, match="monotonic violation"):
        publish_head(store, "ns", Ledger(p))
    assert store.latest("ns")["rows"] == 5


def test_an_edited_only_pin_is_witness_broken_not_consistent(tmp_path):
    """W14: one pin in the file, edited to match a truncated log without
    recomputing its self digest: the witness fails its own chain, so no
    comparison runs and the verdict is witness_broken, never consistent."""
    from arcaeon.record.ledger import (WitnessStore, chain_at, publish_head,
                                       verify_against_witness)
    p, pins = tmp_path / "a.jsonl", tmp_path / "pins.jsonl"
    store = WitnessStore(pins)
    for i in range(5):
        Ledger(p).append({"op": i})
    publish_head(store, "ns", Ledger(p))
    lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
    p.write_text("".join(lines[:3]), encoding="utf-8")       # truncate to 3 rows
    pin = json.loads(pins.read_text(encoding="utf-8"))
    pin.update(rows=3, chain=chain_at(p, 3))                 # edit the pin to agree
    pins.write_text(json.dumps(pin) + "\n", encoding="utf-8")
    v = verify_against_witness(store, "ns", Ledger(p))
    assert v.verdict == "witness_broken" and not v


def test_a_pin_differing_only_in_its_last_hex_char_is_rewritten(tmp_path):
    """W19: the witnessed chain is compared in full. A properly recorded pin whose
    chain differs from the log's only in the final hex character is rewritten."""
    from arcaeon.record.ledger import Head, WitnessStore, verify_against_witness
    p = tmp_path / "a.jsonl"
    for i in range(3):
        Ledger(p).append({"op": i})
    real = Ledger(p).head()
    last = "0" if real.chain[-1] != "0" else "1"
    store = WitnessStore(tmp_path / "pins.jsonl")
    store.record("ns", Head(chain=real.chain[:-1] + last, rows=real.rows, as_of=real.as_of))
    assert store.verify()["ok"] is True
    assert verify_against_witness(store, "ns", Ledger(p)).verdict == "rewritten"


# --- reconcile ------------------------------------------------------------------

def _tape_pair(tmp_path, n=3):
    import arcaeon.prove.reconcile as R
    from arcaeon.record.ledger import digest_json
    paths = {}
    for side in ("agent", "tool"):
        p = tmp_path / f"{side}.tape.jsonl"
        lg = Ledger(p)
        for k in range(1, n + 1):
            lg.append({"evt": "tape_call", "tape": R.TAPE_FORMAT, "side": side,
                       "ns": f"demo-{side}", "idx": k, "tool": "echo",
                       "req": digest_json({"name": "echo", "arguments": {"n": k}}),
                       "resp": digest_json({"result": k}), "status": "ok"})
        paths[side] = p
    return paths["agent"], paths["tool"]


def test_reconcile_pin_head_is_compared_in_full(tmp_path):
    """C15: a pin whose chain differs from the tape's head only in its last hex
    character is ALTERED (head_differs), not an agreeing pin."""
    import arcaeon.prove.reconcile as R
    from arcaeon.record.ledger import chain_at
    a, t = _tape_pair(tmp_path)
    real = chain_at(a, 3)
    pin = tmp_path / "pin.json"
    pin.write_text(json.dumps({"side": "agent", "rows": 3,
                               "chain": real[:-1] + ("0" if real[-1] != "0" else "1")}),
                   encoding="utf-8")
    r = R.reconcile(a, t, pin_path=pin)
    assert r.verdict == R.ALTERED and r.pins_checked[0]["result"] == "head_differs"


def test_reconcile_with_a_missing_pin_file_could_not_look(tmp_path):
    """C17: --pin naming a file that is not there is COULD NOT LOOK (missing),
    never MATCHED over two agreeing tapes."""
    import arcaeon.prove.reconcile as R
    a, t = _tape_pair(tmp_path)
    assert R.reconcile(a, t).verdict == R.MATCHED
    r = R.reconcile(a, t, pin_path=tmp_path / "no-such-pin.json")
    assert r.verdict == R.COULD_NOT_LOOK and r.reason_word == "missing"


def test_reconcile_side_pin_is_held_against_a_tape_emptied_after_the_pin(tmp_path):
    """C19: both tapes emptied after the agent side pinned 3 calls. An empty tape
    names no side, so the agent pin is held against it: MISSING (the pin is the
    proof calls were removed), not COULD NOT LOOK over two empty tapes."""
    import arcaeon.prove.reconcile as R
    from arcaeon.record.ledger import chain_at
    a, t = _tape_pair(tmp_path)
    pin = tmp_path / "pin.json"
    pin.write_text(json.dumps({"side": "agent", "rows": 3, "chain": chain_at(a, 3)}),
                   encoding="utf-8")
    a.write_text("", encoding="utf-8")
    t.write_text("", encoding="utf-8")
    r = R.reconcile(a, t, pin_path=pin)
    assert r.verdict == R.MISSING


def test_reconcile_a_tape_that_mixes_sides_could_not_look(tmp_path):
    """C20: a chained tape whose rows say two different sides is refused (COULD
    NOT LOOK), never lined up as if it were one side's record."""
    import arcaeon.prove.reconcile as R
    a, t = _tape_pair(tmp_path)
    rows = [json.loads(x) for x in a.read_text(encoding="utf-8").splitlines()]
    a.unlink()
    for k, row in enumerate(rows):
        row.pop("chain")
        row.pop("ts")
        if k == 1:
            row["side"] = "tool"
        Ledger(a).append(row)
    r = R.reconcile(a, t)
    assert r.verdict == R.COULD_NOT_LOOK and "mixes sides" in r.reason


def test_reconcile_main_pin_with_no_path_exits_could_not_look(tmp_path, capsys):
    """C21: `reconcile a b --pin` with no path prints COULD_NOT_LOOK and exits 3."""
    import arcaeon.prove.reconcile as R
    a, t = _tape_pair(tmp_path)
    assert R.main([str(a), str(t), "--pin"]) == 3
    assert json.loads(capsys.readouterr().out)["verdict"] == R.COULD_NOT_LOOK


# --- receipts -------------------------------------------------------------------

def _receipt(tmp_path, ledger):
    from arcaeon.record.receipt.core import build_receipt
    return build_receipt("test", {"what": "x"}, [{"name": "c", "status": "pass"}],
                         {"proves": ["p"], "does_not_prove": ["q"]},
                         ledger_path=ledger, namespace="ns", witness=False, anchor=False)


def test_receipt_against_a_bounded_ledger_is_not_ok(tmp_path):
    """K05: the receipt's ledger has an unchained row the chain cannot speak for
    (verify ok=None). The ledger check is not 'consistent' and the receipt is not ok."""
    from arcaeon.record.receipt.core import verify_receipt
    led = tmp_path / "receipts.jsonl"
    led.write_text(json.dumps({"legacy": "no chain"}) + "\n", encoding="utf-8")
    rc = _receipt(tmp_path, led)
    res = verify_receipt(rc, ledger_path=led)
    assert res["body_digest_ok"] is True
    assert res["ledger"]["status"] != "consistent" and res["ok"] is False


def test_receipt_file_with_a_duplicate_key_is_never_ok(tmp_path):
    """K07: the receipt file carries a key twice. Even when the last-wins parse
    recomputes to its digest, verify_receipt(source_text=...) is not ok."""
    from arcaeon.record.receipt.core import verify_receipt
    rc = _receipt(tmp_path, tmp_path / "receipts.jsonl")
    text = json.dumps(rc)
    dup = text.replace('"kind": "test"', '"kind": "other", "kind": "test"', 1)
    assert dup != text
    res = verify_receipt(json.loads(dup), source_text=dup)
    assert res["body_digest_ok"] is True and res.get("duplicate_keys")
    assert res["ok"] is False


def test_attestation_signature_over_anything_but_the_body_digest_is_a_mismatch(tmp_path):
    """K15: a detached signature that says it was made over something other than
    body_digest does not belong to this receipt: mismatch, and not ok."""
    from arcaeon.record.receipt.core import attach_attestation_signature, verify_receipt
    rc = attach_attestation_signature(_receipt(tmp_path, tmp_path / "receipts.jsonl"), "sig")
    assert verify_receipt(rc)["ok"] is True
    rc["attestation_signature"]["signed_over"] = "the issuer's say-so"
    res = verify_receipt(rc)
    assert res["attestation_signature"]["verdict"] == "mismatch" and res["ok"] is False


def test_ots_output_needs_both_a_bitcoin_block_and_success_to_be_attested(tmp_path, monkeypatch):
    """K16: 'bitcoin-attested' needs both a Bitcoin block and success in the
    client's output. A Litecoin attestation is not a Bitcoin one, and a Bitcoin
    block line that ends in failure is a failure; --ots over either is not ok."""
    import subprocess
    from arcaeon.record.receipt import core
    rc = _receipt(tmp_path, tmp_path / "receipts.jsonl")
    rc["anchor"] = {"kind": "opentimestamps", "ots_b64": "AAAA", "status": "pending"}
    monkeypatch.setattr(core, "ots_exe", lambda: tmp_path / "ots")
    for out, want in (("Success! Litecoin block 2650000 attests existence as of 2024-01-01\n",
                       "unknown"),
                      ("Bitcoin block 358391: merkle root does not match, verification failed\n",
                       "failed")):
        monkeypatch.setattr(core, "_run_ots", lambda args, timeout=180, out=out:
                            subprocess.CompletedProcess(args, 0, out, ""))
        assert core.ots_verify(rc)["status"] == want
        assert core.verify_receipt(rc, ots=True)["ok"] is False


def test_witness_pin_disagreeing_with_its_own_block_is_inconsistent(tmp_path, monkeypatch):
    """K19: a pin with no self digest (the hosted shape) whose rows disagree with
    the witness block around it makes the block inconsistent, and the receipt
    not ok."""
    from arcaeon.record.receipt.core import build_receipt, verify_receipt
    monkeypatch.delenv("ARCAEON_WITNESS_URL", raising=False)
    led = tmp_path / "receipts.jsonl"
    rc = build_receipt("test", {"what": "x"}, [{"name": "c", "status": "pass"}],
                       {"proves": ["p"], "does_not_prove": ["q"]},
                       ledger_path=led, namespace="ns", witness=True, anchor=False)
    pin = rc["witness"]["pin"]
    pin.pop("self")
    pin.pop("prev")
    assert verify_receipt(rc, ledger_path=led)["ok"] is True
    pin["rows"] = pin["rows"] + 7
    res = verify_receipt(rc, ledger_path=led)
    assert res["witness"]["verdict"] == "inconsistent" and res["ok"] is False


def test_batch_receipt_with_its_ledger_block_stripped_names_what_is_missing(tmp_path):
    """B05: deleting the ledger block (it sits outside the body digest) never
    raises a verdict: the row is COULD NOT LOOK and names ledger.chain as the
    thing it looked for (name_not_found), not a ledger file that went missing."""
    from arcaeon.record.receipt import verify_batch as VB
    rc = _receipt(tmp_path, tmp_path / "receipts.jsonl")
    del rc["ledger"]
    p = tmp_path / "r.receipt.json"
    p.write_text(json.dumps(rc), encoding="utf-8")
    row = VB.verify_one(p)
    assert row["verdict"] == VB.UNDETERMINED
    assert row["looked_for"] == "ledger.chain" and row["reason_word"] == "name_not_found"


def test_batch_receipt_with_a_foreign_attestation_signature_fails(tmp_path):
    """B08: an attestation signature made over a different body digest does not
    belong to the receipt: the batch row is FAIL, not undetermined."""
    from arcaeon.record.receipt import verify_batch as VB
    from arcaeon.record.receipt.core import attach_attestation_signature
    rc = attach_attestation_signature(_receipt(tmp_path, tmp_path / "receipts.jsonl"), "sig")
    rc["attestation_signature"]["body_digest"] = "sha256:json-c14n:v1:" + "0" * 64
    p = tmp_path / "r.receipt.json"
    p.write_text(json.dumps(rc), encoding="utf-8")
    row = VB.verify_one(p)
    assert row["verdict"] == VB.FAIL and "attestation" in row["reason"]


def test_batch_receipt_with_an_inconsistent_witness_block_fails(tmp_path):
    """B09: a witness block whose rows disagree with the receipt's own ledger
    block is a determined contradiction: the batch row is FAIL."""
    from arcaeon.record.receipt import verify_batch as VB
    rc = _receipt(tmp_path, tmp_path / "receipts.jsonl")
    rc["witness"] = {"kind": "local-file", "namespace": "ns",
                     "rows": rc["ledger"]["rows"] + 1, "chain": rc["ledger"]["chain"]}
    p = tmp_path / "r.receipt.json"
    p.write_text(json.dumps(rc), encoding="utf-8")
    row = VB.verify_one(p)
    assert row["verdict"] == VB.FAIL and "witness" in row["reason"]


# --- signed vet receipts --------------------------------------------------------

def _signed_vet_receipt():
    receipts = pytest.importorskip("arcaeon.prove.vet.receipts")
    if receipts.BACKEND is None:
        pytest.skip("no Ed25519 backend")
    grade = {"source_sha256": "ab" * 32, "verdict": "clean", "checks_run": ["parse"],
             "tool_version": "t", "target": "x.py"}
    return receipts, receipts.sign_grade(grade, bytes(range(32)), nonce="n", ts=1), grade


def test_signed_receipt_with_non_alphabet_bytes_in_its_signature_does_not_verify():
    """S10: signature_b64 is read strictly: a signature carrying a character
    outside the base64 alphabet is refused, not silently cleaned and verified."""
    receipts, rc, grade = _signed_vet_receipt()
    assert receipts.verify_receipt(rc, grade) is True
    sig = rc["signature_b64"]
    rc["signature_b64"] = sig[:10] + "!" + sig[10:]
    d = receipts.verify_receipt_detail(rc, grade)
    assert d["verified"] is False and "base64" in " ".join(d["reasons"])


def test_a_payload_that_cannot_be_canonicalized_never_verifies():
    """S12: a payload carrying a float cannot be put in canonical form, so nothing
    was signed that this verifier can name. Even with a valid signature by the
    named key over the empty message, it does not verify."""
    import base64
    receipts, rc, grade = _signed_vet_receipt()
    seed = bytes(range(32))
    rc["payload"]["score"] = 0.5
    rc["signature_b64"] = base64.b64encode(receipts._sign_bytes(seed, b"")).decode("ascii")
    d = receipts.verify_receipt_detail(rc)
    assert d["verified"] is False and "canonicalizable" in " ".join(d["reasons"])


def test_batch_receipt_whose_anchor_proof_fails_is_fail_not_undetermined(tmp_path, monkeypatch):
    """B11: with --ots, an OpenTimestamps proof that runs and FAILS is a determined
    answer: the batch row is FAIL, not undetermined."""
    from arcaeon.record.receipt import core
    from arcaeon.record.receipt import verify_batch as VB
    rc = _receipt(tmp_path, tmp_path / "receipts.jsonl")
    p = tmp_path / "r.receipt.json"
    p.write_text(json.dumps(rc), encoding="utf-8")
    monkeypatch.setattr(core, "ots_verify", lambda receipt: {"status": "failed", "detail": "bad"})
    row = VB.verify_one(p, ots=True)
    assert row["verdict"] == VB.FAIL and row["reason"] == "anchor verification failed"


# --- the arcaeon front door -----------------------------------------------------

def test_verify_a_ledger_whose_only_line_is_garbage_is_broken_exit_1(tmp_path, capsys):
    """X03: a readable file whose only line does not parse has zero rows, but it
    was read and it is damaged: BROKEN, exit 1, not COULD NOT LOOK."""
    from arcaeon import cli
    p = tmp_path / "a.jsonl"
    p.write_text('{"op": 1, "chain": \n', encoding="utf-8")
    assert cli.main(["verify", str(p)]) == 1
    assert json.loads(capsys.readouterr().out)["verdict"] == "BROKEN"


def test_pin_remote_refuses_a_broken_ledger_and_sends_nothing(tmp_path, monkeypatch, capsys):
    """X07: `pin --remote` over a ledger that does not verify exits 1 and never
    reaches the hosted witness."""
    from arcaeon import cli, remote
    sent = []
    monkeypatch.setattr(remote, "pin", lambda *a, **k: sent.append(a) or {"ok": True})
    monkeypatch.setattr(remote, "key", lambda: "k")
    p = tmp_path / "a.jsonl"
    for i in range(3):
        Ledger(p).append({"op": i})
    p.write_text(p.read_text(encoding="utf-8").replace('"op": 1', '"op": 9'), encoding="utf-8")
    assert cli.main(["pin", str(p), "--remote", "--ns", "arcaeon-x"]) == 1
    assert sent == [] and json.loads(capsys.readouterr().out)["ok"] is False


def test_pin_witness_refuses_a_broken_ledger_exit_1(tmp_path, capsys):
    """X08: `pin --witness` over a ledger that does not verify is refused by
    publish_head; the verb exits 1 and the pin file gains nothing."""
    from arcaeon import cli
    p, w = tmp_path / "a.jsonl", tmp_path / "pins.jsonl"
    for i in range(3):
        Ledger(p).append({"op": i})
    p.write_text(p.read_text(encoding="utf-8").replace('"op": 1', '"op": 9'), encoding="utf-8")
    assert cli.main(["pin", str(p), "--ns", "demo", "--witness", str(w)]) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False
    assert not w.exists() or w.read_text(encoding="utf-8") == ""


def _compaction_row(tmp_path):
    from arcaeon.prove.compact import CompactionReceipt
    r = CompactionReceipt.open(["a", "b", "c"])
    r.record_kept(["a", "summary"])
    return r.seal(tmp_path / "receipts.jsonl", compactor="t", method="m")


def test_compact_a_tampered_receipt_is_broken_exit_1(tmp_path, capsys):
    """X14: `arcaeon compact` on a receipt row whose counts were edited is
    BROKEN, exit 1, never VERIFIED."""
    from arcaeon import cli
    row = _compaction_row(tmp_path)
    row["dropped"]["count"] += 1
    f = tmp_path / "row.json"
    f.write_text(json.dumps(row), encoding="utf-8")
    assert cli.main(["compact", str(f)]) == 1
    assert json.loads(capsys.readouterr().out)["verdict"] == "BROKEN"


def test_compact_with_unreadable_content_could_not_look_exit_3(tmp_path, capsys):
    """X15: a --pre file that is not JSON: nothing was recomputed, COULD NOT
    LOOK, exit 3."""
    from arcaeon import cli
    f = tmp_path / "row.json"
    f.write_text(json.dumps(_compaction_row(tmp_path)), encoding="utf-8")
    pre = tmp_path / "pre.json"
    pre.write_text("not json", encoding="utf-8")
    assert cli.main(["compact", str(f), "--pre", str(pre)]) == 3
    assert json.loads(capsys.readouterr().out)["verdict"] == "COULD NOT LOOK"


def test_pin_refuses_to_append_to_a_pin_file_whose_own_chain_is_broken(tmp_path, capsys):
    """X18: a pin file whose lines are all pin-shaped but whose pin chain breaks
    (a middle pin's rows edited) is refused before a byte is written: COULD NOT
    LOOK, exit 3, the file unchanged."""
    from arcaeon import cli
    p, w = tmp_path / "a.jsonl", tmp_path / "pins.jsonl"
    Ledger(p).append({"op": 0})
    for i in (1, 2):
        Ledger(p).append({"op": i})
        assert cli.main(["pin", str(p), "--ns", "demo", "--witness", str(w)]) == 0
    lines = w.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["rows"] = 1
    w.write_text(json.dumps(first) + "\n" + lines[1] + "\n", encoding="utf-8")
    before = w.read_bytes()
    Ledger(p).append({"op": 3})
    capsys.readouterr()
    assert cli.main(["pin", str(p), "--ns", "demo", "--witness", str(w)]) == 3
    assert w.read_bytes() == before
