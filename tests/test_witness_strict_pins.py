"""Review round 7 on the verify-witness branch (2026-11-06): one strict pin
validator, `arcaeon.record.ledger.witness.strict_pin`, used by every reader
and by `WitnessStore.record`.

Six rounds each closed one hole and the next review found another, because
each reader trusted the pin file's SHAPE its own way. These tests hold the
root: `record()` refuses a pin that fails the rules, and a reader that meets
one in a file treats the whole file as COULD NOT LOOK (exit 3), never
skipping the pin and never counting it as compared.
"""
import json

import pytest

from arcaeon import cli
from arcaeon.record.ledger import Head, Ledger
from arcaeon.record.ledger import witness as W

AS_OF = "2026-11-06T00:00:00Z"


def _log(p, ops):
    for op in ops:
        cli.main(["log", str(p), json.dumps(op)])


def _rewrite(tmp_path, p, ops):
    """A fresh, fully chained ledger of `ops` in place of `p` (verifies alone)."""
    fake = tmp_path / ("rw-%d.jsonl" % len(list(tmp_path.iterdir())))
    _log(fake, ops)
    p.write_bytes(fake.read_bytes())


def _plant(w, ns, rows, chain):
    """Append a correctly chained pin straight to the file, bypassing every
    refusal in record() (a hand edit, or another store): the file verifies."""
    s = W.WitnessStore(str(w))
    rec = {"namespace": ns, "rows": rows, "chain": chain, "as_of": AS_OF,
           "received_at": None, "prev": s._tail_digest()}
    rec["self"] = s._digest_record(rec)
    with open(w, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


# ---- the round-6 B1 attack, exactly -------------------------------------------

def test_r7_b1_record_refuses_chainless_then_float_rows_pin(tmp_path):
    # Head(rows=3, chain=None), then rewrite, then Head(rows=3.0, chain=c3):
    # neither tripped the equivocation or high-water guards before.
    p = tmp_path / "L.jsonl"
    w = tmp_path / "W.jsonl"
    _log(p, [{"op": i} for i in range(3)])
    store = W.WitnessStore(str(w))
    with pytest.raises(ValueError, match="chain"):
        store.record("demo", Head(chain=None, rows=3, as_of=AS_OF))
    _rewrite(tmp_path, p, [{"op": 100 + i} for i in range(3)])
    c3 = Ledger(str(p)).head().chain
    with pytest.raises(ValueError, match="rows"):
        store.record("demo", Head(chain=c3, rows=3.0, as_of=AS_OF))
    assert not w.exists() or w.read_text(encoding="utf-8") == ""   # nothing written


def test_r7_b1_hand_written_pins_are_could_not_look_never_verified(tmp_path, capsys):
    p = tmp_path / "L.jsonl"
    w = tmp_path / "W.jsonl"
    _log(p, [{"op": i} for i in range(3)])
    _plant(w, "demo", 3, None)
    _rewrite(tmp_path, p, [{"op": 100 + i} for i in range(3)])
    _plant(w, "demo", 3.0, Ledger(str(p)).head().chain)
    assert W.WitnessStore(str(w)).verify()["ok"] is True       # the file itself is intact
    capsys.readouterr()
    assert cli.main(["verify", str(p)]) == 0                    # alone: clean
    capsys.readouterr()
    rc = cli.main(["verify", str(p), "--witness", str(w)])
    cap = capsys.readouterr()
    j = json.loads(cap.out)
    assert rc == 3 and j["verdict"] == "COULD NOT LOOK" and j["reason_word"] == "unreadable"
    assert "strict pin rules" in j["since_pin"]["reason"]
    # The library reader agrees: no pin from that file is trusted.
    v = W.verify_against_witness(W.WitnessStore(str(w)), "demo", Ledger(str(p)))
    assert v.verdict == "witness_unreadable" and not v
    # And record() will not build on that history either.
    with pytest.raises(ValueError, match="strict pin rules"):
        W.WitnessStore(str(w)).record("demo", Ledger(str(p)).head())


def test_r7_all_chainless_pin_file_is_could_not_look(tmp_path, capsys):
    # Rows-only checks are not comparisons: a pin file whose every pin has no
    # chain compared nothing, so --witness cannot stand on the ledger's VERIFIED.
    p = tmp_path / "L.jsonl"
    w = tmp_path / "W.jsonl"
    _log(p, [{"op": i} for i in range(4)])
    for rows in (2, 4):
        _plant(w, "demo", rows, None)
    capsys.readouterr()
    assert cli.main(["verify", str(p), "--witness", str(w)]) == 3
    j = json.loads(capsys.readouterr().out)
    assert j["verdict"] == "COULD NOT LOOK"
    assert j["since_pin"].get("earlier_pins_checked", 0) == 0
    v = W.verify_against_witness(W.WitnessStore(str(w)), "demo", Ledger(str(p)))
    assert v.verdict == "witness_unreadable"


# ---- the rules, one by one ------------------------------------------------------

@pytest.mark.parametrize("rows,chain,field", [
    (True, "a" * 32, "rows"),
    (False, "genesis", "rows"),
    (-1, "a" * 32, "rows"),
    (3.0, "a" * 32, "rows"),
    ("3", "a" * 32, "rows"),
    (3, "", "chain"),
    (3, None, "chain"),
    (3, "a" * 31, "chain"),
    (3, "g" * 32, "chain"),
    (3, "GENESIS", "chain"),
])
def test_r7_record_refuses_a_pin_failing_strict_pin(tmp_path, rows, chain, field):
    w = tmp_path / "W.jsonl"
    with pytest.raises(ValueError, match=field):
        W.WitnessStore(str(w)).record("demo", Head(chain=chain, rows=rows, as_of=AS_OF))
    assert not w.exists()


def test_r7_record_refuses_an_empty_namespace(tmp_path):
    with pytest.raises(ValueError, match="namespace"):
        W.WitnessStore(str(tmp_path / "W.jsonl")).record(
            "", Head(chain="a" * 32, rows=1, as_of=AS_OF))


def test_r7_uppercase_chain_is_normalised(tmp_path, capsys):
    p = tmp_path / "L.jsonl"
    w = tmp_path / "W.jsonl"
    _log(p, [{"op": i} for i in range(3)])
    c = Ledger(str(p)).head().chain
    rec = W.WitnessStore(str(w)).record("demo", Head(chain=c.upper(), rows=3, as_of=AS_OF))
    assert rec["chain"] == c
    assert json.loads(w.read_text(encoding="utf-8"))["chain"] == c   # stored lower-case
    assert W.strict_pin({"namespace": "n", "rows": 0, "chain": "AB" * 16})["chain"] == "ab" * 16
    # A hand-written upper-case pin (another store) is read lower-cased: not a rewrite.
    v2 = tmp_path / "V.jsonl"
    _plant(v2, "demo", 3, c.upper())
    capsys.readouterr()
    assert cli.main(["verify", str(p), "--witness", str(v2)]) == 0
    assert json.loads(capsys.readouterr().out)["since_pin"]["chain_matches"] is True
    assert W.verify_against_witness(W.WitnessStore(str(v2)), "demo", Ledger(str(p)))


def test_r7_genesis_and_hex_pins_pass(tmp_path):
    for rec in ({"namespace": "n", "rows": 0, "chain": "genesis"},
                {"namespace": "n", "rows": 5, "chain": "genesis"},
                {"namespace": "n", "rows": 5, "chain": "0123456789abcdef" * 2}):
        assert W.strict_pin(rec) == rec


@pytest.mark.parametrize("rows", [True, -1, 2.0])
def test_r7_hand_written_bad_rows_beside_a_good_pin_is_could_not_look(tmp_path, capsys, rows):
    # One bad pin anywhere in the file: the whole file, never a skip of that pin.
    p = tmp_path / "L.jsonl"
    w = tmp_path / "W.jsonl"
    _log(p, [{"op": i} for i in range(3)])
    assert cli.main(["pin", str(p), "--ns", "demo", "--witness", str(w)]) == 0
    _plant(w, "demo", rows, "b" * 32)
    capsys.readouterr()
    assert cli.main(["verify", str(p), "--witness", str(w)]) == 3
    assert json.loads(capsys.readouterr().out)["reason_word"] == "unreadable"
    # `arcaeon pin` refuses to append to it, and writes nothing.
    before = w.read_bytes()
    assert cli.main(["pin", str(p), "--ns", "demo", "--witness", str(w)]) != 0
    assert w.read_bytes() == before
    capsys.readouterr()


def test_r7_cli_second_namespace_rewrite_needs_ns(tmp_path, capsys):
    # B2's CLI half (already COULD NOT LOOK since round 6; locked here beside
    # the pack half): honest pin under prod, rewrite, pin under prod2.
    p = tmp_path / "L.jsonl"
    w = tmp_path / "W.jsonl"
    _log(p, [{"op": i} for i in range(3)])
    assert cli.main(["pin", str(p), "--ns", "prod", "--witness", str(w)]) == 0
    _rewrite(tmp_path, p, [{"op": 100 + i} for i in range(3)])
    assert cli.main(["pin", str(p), "--ns", "prod2", "--witness", str(w)]) == 0
    capsys.readouterr()
    assert cli.main(["verify", str(p), "--witness", str(w)]) == 3
    capsys.readouterr()
    assert cli.main(["verify", str(p), "--witness", str(w), "--ns", "prod"]) == 1
    capsys.readouterr()


def test_r7_two_heads_message_names_this_pin_file(tmp_path, capsys):
    # m2: the runtime message no longer claims "a witness never holds two
    # heads at one height" of a file that plainly does.
    p = tmp_path / "L.jsonl"
    w = tmp_path / "W.jsonl"
    _log(p, [{"op": i} for i in range(3)])
    assert cli.main(["pin", str(p), "--ns", "demo", "--witness", str(w)]) == 0
    _rewrite(tmp_path, p, [{"op": 100 + i} for i in range(3)])
    _plant(w, "demo", 3, Ledger(str(p)).head().chain)
    capsys.readouterr()
    assert cli.main(["verify", str(p), "--witness", str(w)]) == 1
    err = capsys.readouterr().err
    assert "this pin file holds two heads at one height; a local WitnessStore refuses that" in err
    assert "a witness never holds two heads" not in err
