"""The deal lane (arcaeon.record.deal): a witnessed transaction, both sides.

Numbered to the design's test list (DEAL_LANE_DESIGN_2026-09-24.md, "Tests"):
1 rows, 2 mandate check, 3 honest pair, 4 price changed, 5 not shipped,
6 cancel then ship, 7 wrong mandate digest, 8 broken chain, 9 pins,
10 pack, 11 CLI, 12 import weight, (13 lives in test_chain_end_to_end.py),
plus docs/DEAL.md's worked example, executed line by line.
"""
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

import _arcaeon_chain as C
from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove.reconcile import LIMITS as RECONCILE_LIMITS
from arcaeon.record.deal import STEPS, Deal, dispute, pack
from arcaeon.record.ledger import Ledger, verify_file
from arcaeon.record.ledger.witness import WitnessStore, publish_head
from arcaeon.record.row import digest_json

ROOT = Path(__file__).resolve().parents[1]
ITEMS = [{"sku": "pens-12", "qty": 2, "unit_price": "9.50"}]
WINDOW = dict(not_before="2026-01-01T00:00:00Z", not_after="2099-12-31T00:00:00Z")
VERDICT_WORDS = ("MATCHED", "MISSING", "ALTERED", "COULD NOT LOOK", "COULD_NOT_LOOK",
                 "VERIFIED", "BROKEN")


def _rows(p):
    return C.rows(p)


def _honest(tmp, deal="d-t1", *, seller_total="19.00", seller_md=None, ship=True):
    """A buyer and a seller ledger for one deal: mandate, commit, pay (both),
    optionally a seller ship. Returns (buyer_path, seller_path, buyer_commit)."""
    b, s = tmp / "buyer.jsonl", tmp / "seller.jsonl"
    buyer, seller = Deal(b, "buyer", deal), Deal(s, "seller", deal)
    buyer.mandate(merchant="acme", cap="60.00", currency="USD", **WINDOW)
    bc = buyer.commit(items=ITEMS, total="19.00", currency="USD", seller="acme",
                      ship_to="1 Main St", buyer_ref="po-1")
    seller.commit(items=ITEMS, total=seller_total, currency="USD", seller="acme",
                  ship_to="1 Main St", buyer_ref="po-1",
                  mandate_digest=seller_md or bc["shared"]["mandate_digest"])
    for d in (buyer, seller):
        d.pay(rail="card", reference="ch_1", amount="19.00", currency="USD")
    if ship:
        seller.ship(carrier="ups", tracking="1Z1", at="2026-09-24T15:00:00Z")
    return b, s, bc


# 1 -----------------------------------------------------------------------------

def test_1_each_step_writes_one_row_and_the_chain_verifies(tmp_path):
    p = tmp_path / "buyer.jsonl"
    d = Deal(p, "buyer", "d-one")
    writers = [
        ("mandate", lambda: d.mandate(merchant="acme", cap="60.00", currency="USD", **WINDOW)),
        ("commit", lambda: d.commit(items=ITEMS, total="19.00", currency="USD", seller="acme")),
        ("pay", lambda: d.pay(rail="card", reference="ch_1", amount="19.00", currency="USD")),
        ("ship", lambda: d.ship(carrier="ups", tracking="1Z1")),
        ("deliver", lambda: d.deliver(proof="evt-1")),
        ("cancel", lambda: d.cancel(reason="changed my mind")),
        ("dispute", lambda: d.raise_dispute("not_delivered", "box empty")),
    ]
    assert [w for w, _ in writers] == list(STEPS)
    for n, (step, write) in enumerate(writers, start=1):
        row = write()
        on_disk = _rows(p)
        assert len(on_disk) == n, step
        last = on_disk[-1]
        assert last == row
        assert last["kind"] == f"deal.{step}" and last["party"] == "buyer"
        assert last["deal"] == "d-one"
        assert last["step_digest"] == digest_json(last["shared"])
        vr = verify_file(p)
        assert vr.ok is True and vr.rows == n, (step, vr)


def test_1b_generated_deal_id_and_party_rules(tmp_path):
    d = Deal(tmp_path / "x.jsonl", "buyer")
    assert re.fullmatch(r"d-[0-9a-f]{12}", d.id)
    with pytest.raises(ValueError):
        Deal(tmp_path / "x.jsonl", "merchant")
    with pytest.raises(ValueError):
        Deal(tmp_path / "s.jsonl", "seller", "d-x").mandate(merchant="a", cap="1", currency="USD")
    with pytest.raises(ValueError):
        d.raise_dispute("because", "")


# 2 -----------------------------------------------------------------------------

@pytest.mark.parametrize("kw, word", [
    (dict(total="19.00", seller="acme"), None),
    (dict(total="61.00", seller="acme"), "cap"),
    (dict(total="19.00", seller="other-store"), "merchant"),
])
def test_2_commit_inside_or_outside_the_mandate(tmp_path, kw, word):
    p = tmp_path / "buyer.jsonl"
    d = Deal(p, "buyer", "d-m")
    d.mandate(merchant="acme", cap="60.00", currency="USD", **WINDOW)
    row = d.commit(items=ITEMS, currency="USD", **kw)
    assert len(_rows(p)) == 2, "the row is written either way"
    if word is None:
        assert row["inside_mandate"] is True
    else:
        assert row["inside_mandate"] is False and word in row["mandate_reason"]


def test_2b_outside_the_window_and_no_mandate(tmp_path):
    d = Deal(tmp_path / "b.jsonl", "buyer", "d-w")
    d.mandate(merchant="acme", cap="60.00", currency="USD",
              not_before="2020-01-01T00:00:00Z", not_after="2020-12-31T00:00:00Z")
    row = d.commit(items=ITEMS, total="19.00", currency="USD", seller="acme")
    assert row["inside_mandate"] is False and "not_after" in row["mandate_reason"]
    lone = Deal(tmp_path / "c.jsonl", "buyer", "d-none").commit(
        items=ITEMS, total="19.00", currency="USD", seller="acme")
    assert lone["inside_mandate"] is False and "no mandate row" in lone["mandate_reason"]
    assert verify_file(tmp_path / "c.jsonl").ok is True


def test_2c_sealed_mandate_keeps_only_the_digest(tmp_path):
    side = tmp_path / "mandate.sealed.json"
    d = Deal(tmp_path / "b.jsonl", "buyer", "d-s")
    m = d.mandate(merchant="acme", cap="60.00", currency="USD", sealed=side, **WINDOW)
    assert m["sealed"] is True and "mandate" not in m
    body = json.loads(side.read_text(encoding="utf-8"))["mandate"]
    assert digest_json(body) == m["mandate_digest"]
    # a fresh writer (another process) cannot check without the body ...
    d2 = Deal(tmp_path / "b.jsonl", "buyer", "d-s")
    row = d2.commit(items=ITEMS, total="19.00", currency="USD", seller="acme")
    assert "inside_mandate" in row and row["inside_mandate"] is None
    # ... and can once the buyer discloses it
    row = d2.commit(items=ITEMS, total="19.00", currency="USD", seller="acme", mandate=body)
    assert row["inside_mandate"] is True


# 3 -----------------------------------------------------------------------------

def test_3_two_honest_tapes_match(tmp_path):
    b, s, _ = _honest(tmp_path)
    r = dispute("d-t1", b, s)
    assert r.verdict == V.MATCHED and r.exit_code == 0 and bool(r), r.to_dict()
    assert r.matched == 2 and r.findings == [] and r.could_not_look == []
    text = " ".join(r.position)
    for step in STEPS:
        assert step in text, step
    for line in r.position:
        assert not any(w in line for w in VERDICT_WORDS), line
    assert RECONCILE_LIMITS[3] in r.limits, "no pins: reconcile's own words"
    assert [e["step"] for e in r.timeline].count("commit") == 2


# 4 -----------------------------------------------------------------------------

def test_4_seller_changes_the_total(tmp_path):
    b, s, _ = _honest(tmp_path, seller_total="23.00")
    r = dispute("d-t1", b, s)
    assert r.verdict == V.ALTERED and r.exit_code == 1, r.to_dict()
    assert r.at == "commit#1"
    assert "total" in r.reason and "terms.total" in r.findings[0].reason


# 5 -----------------------------------------------------------------------------

def test_5_not_shipped_is_about_the_rows(tmp_path):
    b, s, _ = _honest(tmp_path, ship=False)
    Deal(b, "buyer", "d-t1").raise_dispute("not_shipped", "nothing arrived")
    r = dispute("d-t1", b, s)
    assert not [f for f in r.findings if str(f.at).startswith("ship")]
    assert r.verdict == V.MATCHED, r.to_dict()
    assert "ship: no ship row on either tape." in r.position
    assert any("claims not_shipped" in line for line in r.position)


# 6 -----------------------------------------------------------------------------

def test_6a_cancel_mirrored_then_ship(tmp_path):
    b, s, _ = _honest(tmp_path, ship=False)
    Deal(b, "buyer", "d-t1").cancel(reason="too slow", ts="2026-09-24T10:00:00Z")
    seller = Deal(s, "seller", "d-t1")
    seller.cancel(reason="too slow", ts="2026-09-24T10:05:00Z")
    row = seller.ship(carrier="ups", tracking="1Z1", ts="2026-09-24T10:41:00Z")
    assert row["after_cancel"] is True
    r = dispute("d-t1", b, s)
    assert r.verdict == V.MATCHED, r.to_dict()
    assert "cancel is on both tapes before any ship row." in r.position
    assert any("41 minutes after" in x and "not pinned" in x for x in r.position), r.position


def test_6b_cancel_not_mirrored(tmp_path):
    b, s, _ = _honest(tmp_path, ship=False)
    Deal(b, "buyer", "d-t1").cancel(reason="too slow", ts="2026-09-24T10:00:00Z")
    row = Deal(s, "seller", "d-t1").ship(carrier="ups", tracking="1Z1",
                                         ts="2026-09-24T10:41:00Z")
    assert row["after_cancel"] is False
    r = dispute("d-t1", b, s)
    assert r.verdict == V.MATCHED, r.to_dict()
    assert "seller tape holds no cancel row." in r.position
    assert ("seller's ship row is 41 minutes after buyer's cancel row "
            "(by ledger ts; not pinned).") in r.position


def test_6c_a_mirrored_ship_is_compared(tmp_path):
    b, s, _ = _honest(tmp_path)                       # seller shipped at 15:00
    Deal(b, "buyer", "d-t1").ship(carrier="ups", tracking="1Z1", at="2026-09-24T15:00:00Z")
    r = dispute("d-t1", b, s)
    assert r.verdict == V.MATCHED and r.matched == 3, r.to_dict()
    Deal(b, "buyer", "d-t1").ship(carrier="ups", tracking="1Z2", at="2026-09-24T16:00:00Z")
    r = dispute("d-t1", b, s)
    assert r.verdict == V.MISSING and r.at == "ship#2" and r.side == "seller", r.to_dict()


# 7 -----------------------------------------------------------------------------

def test_7_seller_cites_a_different_mandate_digest(tmp_path):
    b, s, _ = _honest(tmp_path, seller_md="sha256:json-c14n:v1:" + "0" * 64)
    r = dispute("d-t1", b, s)
    assert r.verdict == V.ALTERED and r.at == "commit#1", r.to_dict()
    assert all("mandate_digest mismatch" in f.reason for f in r.findings if f.at == "commit#1")
    assert any(f.side == "seller" for f in r.findings)


# 8 -----------------------------------------------------------------------------

def test_8_broken_chain_is_could_not_look_naming_the_side(tmp_path):
    b, s, _ = _honest(tmp_path)
    rows = _rows(s)
    rows[0]["shared"]["terms"]["total"] = "1.00"      # edited in place, not re-chained
    s.write_text("".join(json.dumps(x) + "\n" for x in rows), encoding="utf-8")
    assert verify_file(s).ok is False
    r = dispute("d-t1", b, s)
    assert r.verdict == V.COULD_NOT_LOOK and r.exit_code == 3, r.to_dict()
    assert "seller tape" in r.reason
    missing = dispute("d-t1", b, tmp_path / "nope.jsonl")
    assert missing.verdict == V.COULD_NOT_LOOK and "seller tape not found" in missing.reason
    empty = dispute("d-other", b, s.with_name("seller2.jsonl"))
    assert empty.verdict == V.COULD_NOT_LOOK


# 9 -----------------------------------------------------------------------------

def test_9_pins_catch_a_rewrite_in_agreement(tmp_path):
    b, s, _ = _honest(tmp_path, ship=False)
    store = WitnessStore(tmp_path / "witness.jsonl")
    pb = publish_head(store, "acme-buyer", Ledger(b))
    ps = publish_head(store, "acme-seller", Ledger(s))
    pins = [dict(pb, side="buyer"), dict(ps, side="seller")]
    ok = dispute("d-t1", b, s, pins=pins)
    assert ok.verdict == V.MATCHED and all(c["result"] == "agrees" for c in ok.pins_checked)
    assert all(e["pinned"] for e in ok.timeline), "every row is under an agreeing pin"
    # both tapes rewritten in agreement: the pair still matches, the pins do not
    for path in (b, s):
        rs = _rows(path)
        for x in rs:
            if x["kind"] == "deal.commit":
                x["shared"]["terms"]["total"] = "9.00"
                x["step_digest"] = digest_json(x["shared"])
        C.write_rechained(path, rs)
    assert dispute("d-t1", b, s).verdict == V.MATCHED
    r = dispute("d-t1", b, s, pins=pins)
    assert r.verdict == V.ALTERED, r.to_dict()
    assert {c["result"] for c in r.pins_checked} == {"head_differs"}
    assert r.at.startswith("row#") and "rewritten after the pin" in r.reason
    assert "call" not in r.reason
    # the same pins from the witness file itself, targeted by namespace
    r2 = dispute("d-t1", b, s, pin_path=tmp_path / "witness.jsonl",
                 buyer_ns="acme-buyer", seller_ns="acme-seller")
    assert r2.verdict == V.ALTERED and len(r2.pins_checked) == 2, r2.to_dict()


def test_9b_truncation_after_the_pin_is_missing(tmp_path):
    b, s, _ = _honest(tmp_path)
    ps = publish_head(WitnessStore(tmp_path / "w.jsonl"), "acme-seller", Ledger(s))
    lines = s.read_text(encoding="utf-8").splitlines(keepends=True)
    s.write_text("".join(lines[:-1]), encoding="utf-8")
    r = dispute("d-t1", b, s, pins=[dict(ps, side="seller")])
    assert any(f.verdict == V.MISSING and f.side == "seller" for f in r.findings), r.to_dict()
    assert r.exit_code == 1


def test_9c_unreadable_pin_file_is_could_not_look(tmp_path):
    b, s, _ = _honest(tmp_path)
    bad = tmp_path / "pins.json"
    bad.write_text("{not json", encoding="utf-8")
    r = dispute("d-t1", b, s, pin_path=bad)
    assert r.verdict == V.COULD_NOT_LOOK and "pin unreadable" in r.reason


# 10 ----------------------------------------------------------------------------

def test_10_pack_writes_the_files(tmp_path):
    b, s, _ = _honest(tmp_path, seller_total="23.00")
    r, out = pack("d-t1", b, s, tmp_path / "DEAL-d-t1")
    names = sorted(x.name for x in out.iterdir())
    assert names == ["buyer.deal.jsonl", "seller.deal.jsonl", "timeline.md", "verdict.json"]
    md = (out / "timeline.md").read_text(encoding="utf-8")
    assert md.splitlines()[0] == r.verdict == V.ALTERED
    assert "arcaeon deal dispute d-t1" in md and "How to check this yourself" in md
    assert json.loads((out / "verdict.json").read_text(encoding="utf-8"))["verdict"] == V.ALTERED
    assert len(_rows(out / "seller.deal.jsonl")) == 3


# 11 ----------------------------------------------------------------------------

def test_11_cli_help_lists_every_step(capsys):
    assert cli.main(["deal", "--help"]) == 0
    out = capsys.readouterr().out
    for step in ("mandate", "commit", "pay", "ship", "deliver", "cancel", "dispute",
                 "pack", "show"):
        assert f"  {step} " in out, step
    assert cli.main(["--help"]) == 0
    assert "  deal " in capsys.readouterr().out


def test_11b_cli_exit_codes_match_the_table(tmp_path, capsys):
    b, s, _ = _honest(tmp_path)
    args = ["deal", "dispute", "d-t1", "--buyer", str(b), "--seller", str(s)]
    assert cli.main(args) == V.EXIT_GOOD
    assert cli.main(args + ["--legacy-exit"]) == V.EXIT_GOOD
    (tmp_path / "x").mkdir()
    b2, s2, _ = _honest(tmp_path / "x", seller_total="23.00")
    bad = ["deal", "dispute", "d-t1", "--buyer", str(b2), "--seller", str(s2)]
    assert cli.main(bad) == V.EXIT_BAD
    assert cli.main(bad + ["--legacy-exit"]) == V.EXIT_BAD
    cnl = ["deal", "dispute", "d-t1", "--buyer", str(b), "--seller", str(tmp_path / "no.jsonl")]
    assert cli.main(cnl) == V.EXIT_COULD_NOT_LOOK
    assert cli.main(cnl + ["--legacy-exit"]) == V.EXIT_COULD_NOT_LOOK, "new verb: no legacy code"
    assert cli.main(["deal", "dispute", "d-t1", "--buyer", str(b)]) == V.EXIT_USAGE
    assert cli.main(["deal", "frob"]) == V.EXIT_USAGE
    capsys.readouterr()
    assert cli.main(args + ["--json"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == V.MATCHED


def test_11c_cli_remote_sends_nothing_and_keeps_the_local_code(tmp_path, capsys, monkeypatch):
    import arcaeon.remote as remote
    monkeypatch.setattr(remote, "reconcile_tapes",
                        lambda *a, **k: pytest.fail("nothing is sent for a deal"))
    b, s, _ = _honest(tmp_path)
    rc = cli.main(["deal", "dispute", "d-t1", "--buyer", str(b), "--seller", str(s), "--remote"])
    assert rc == 0
    assert "hosted deal verdict not yet available; local verdict above" in capsys.readouterr().err


def test_11d_cli_claim_writes_the_dispute_row_then_answers(tmp_path, capsys):
    b, s, _ = _honest(tmp_path, ship=False)
    rc = cli.main(["deal", "dispute", "d-t1", "--buyer", str(b), "--seller", str(s),
                   "--claim", "not_shipped", "--by", "buyer", "--text", "nothing came"])
    assert rc == 0
    assert _rows(b)[-1]["kind"] == "deal.dispute"
    assert "claims not_shipped" in capsys.readouterr().out
    assert cli.main(["deal", "show", str(b), "--deal", "d-t1"]) == 0
    assert len(capsys.readouterr().out.strip().splitlines()) == len(_rows(b))


# 12 ----------------------------------------------------------------------------

def test_12_import_deal_pulls_only_the_stdlib():
    # diffed against what the interpreter had loaded before the import: site
    # startup (.pth hooks such as pywin32's) is not this module's weight
    probe = ("import json, sys\n"
             "before = set(sys.modules)\n"
             "import arcaeon.record.deal\n"
             "std = set(sys.stdlib_module_names)\n"
             "top = {m.split('.')[0] for m in set(sys.modules) - before}\n"
             "print(json.dumps(sorted(t for t in top if t not in std and t != 'arcaeon'"
             " and not t.startswith('_'))))\n")
    if not hasattr(sys, "stdlib_module_names"):
        pytest.skip("sys.stdlib_module_names is 3.10+")
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
    p = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True,
                       env=env, timeout=120)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout.strip().splitlines()[-1]) == []


# docs/DEAL.md ----------------------------------------------------------------------

def _doc_steps():
    """(command, expected first output line or None) for every `$ arcaeon` line
    in a ```console block of docs/DEAL.md, in document order."""
    text = (ROOT / "docs" / "DEAL.md").read_text(encoding="utf-8")
    steps = []
    for block in re.findall(r"```console\n(.*?)```", text, flags=re.S):
        lines = block.splitlines()
        for i, line in enumerate(lines):
            if line.startswith("$ arcaeon "):
                nxt = lines[i + 1] if i + 1 < len(lines) else None
                steps.append((line[2:], None if nxt is None or nxt.startswith("$") else nxt))
    return steps


def test_docs_worked_example_runs(tmp_path, monkeypatch, capsys):
    steps = _doc_steps()
    assert len(steps) >= 12 and sum(1 for _, e in steps if e) >= 3
    monkeypatch.chdir(tmp_path)
    for cmd, expected in steps:
        argv = shlex.split(cmd)[1:]
        rc = cli.main(argv)
        out = capsys.readouterr().out
        if expected is None:
            assert rc == 0, (cmd, out)
            continue
        first = out.splitlines()[0]
        if expected.endswith("...}}"):
            # a step's one JSON line, shown cut short in the doc (qa-fixes item 8)
            assert first.startswith(expected[:-len("...}}")]), (cmd, first)
            assert rc == 0, (cmd, out)
            continue
        assert first == expected, (cmd, first)
        assert rc == V.exit_for(expected.split(" at ")[0].split(" ")[0]), (cmd, rc)
    assert (tmp_path / "DEAL-d-demo2" / "timeline.md").read_text(
        encoding="utf-8").splitlines()[0] == V.ALTERED
