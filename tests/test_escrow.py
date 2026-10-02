"""The escrow release rule (arcaeon.record.escrow, N01) and the recourse tier
on the mandate (N05). Mock rail only: these tests check rows, never money.

Covers: the happy path both sides, each refund path (ALTERED, MISSING), the
COULD NOT LOOK hold, the timeout refund, a one-byte tamper on the receipt that
flips release to refund, that no code path releases without a verified
receipt, the recourse rules in hold() and dispute(), dispute() over escrow
rows, pack() carrying them, and the CLI.
"""
import ast
import json
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.record import escrow as E
from arcaeon.record.deal import RECOURSE, Deal, deal_rows, dispute, pack
from arcaeon.record.ledger import verify_file
from arcaeon.record.receipt.call import call_receipt, phone_call_receipt
from arcaeon.record.receipt.core import save_receipt
from arcaeon.record.row import digest_json

ROOT = Path(__file__).resolve().parents[1]
ITEMS = [{"sku": "answer-1", "qty": 1, "unit_price": "0.30"}]
URL = "https://tool.example/v1/answer"
CRIT = {"seller": "acme-tools", "url": URL, "response_status": 200}
TIMEOUT = "2026-10-03T00:00:00Z"
BEFORE = "2026-10-02T12:00:00Z"
AFTER = "2026-10-03T00:00:01Z"
FOUR = (V.MATCHED, V.MISSING, V.ALTERED, V.COULD_NOT_LOOK)
VERDICT_WORDS = ("MATCHED", "MISSING", "ALTERED", "COULD NOT LOOK", "VERIFIED", "BROKEN")


def _receipt(tmp, name="call", *, status=200, body="the answer", error=None):
    """The seller's call receipt, written to the seller's call ledger."""
    led = tmp / "seller-calls.jsonl"
    rc = call_receipt({"method": "POST", "url": URL, "body": {"q": "x"}},
                      {"status": status, "body": body}, ledger_path=led, seller="acme-tools",
                      elapsed_ms=12, witness=False, anchor=False, error=error)
    return save_receipt(rc, tmp / f"{name}.receipt.json"), led


def _deal(tmp, deal="d-e1", *, recourse="escrow_challenge_window", seller_hold=True,
          crit=CRIT):
    """Buyer mandate (with recourse), both commits, the buyer's hold and the
    seller's mirrored hold. Returns (buyer_path, seller_path)."""
    b, s = tmp / "buyer.jsonl", tmp / "seller.jsonl"
    buyer, seller = Deal(b, "buyer", deal), Deal(s, "seller", deal)
    buyer.mandate(merchant="acme-tools", cap="1.00", currency="USD", recourse=recourse)
    bc = buyer.commit(items=ITEMS, total="0.30", currency="USD", seller="acme-tools")
    seller.commit(items=ITEMS, total="0.30", currency="USD", seller="acme-tools",
                  mandate_digest=bc["shared"]["mandate_digest"])
    kw = dict(amount="0.30", currency="USD", criteria_digest=E.criteria_digest(crit),
              recourse="escrow_challenge_window", timeout_at=TIMEOUT)
    E.hold(b, "buyer", deal, **kw)
    if seller_hold:
        E.hold(s, "seller", deal, **kw)
    return b, s


# happy path ---------------------------------------------------------------------

def test_happy_path_releases_on_both_sides_and_dispute_matches(tmp_path):
    b, s = _deal(tmp_path)
    rcp, led = _receipt(tmp_path)
    assert E.state(b, "d-e1") == E.HELD
    sb = E.settle(b, "buyer", "d-e1", receipt=rcp, receipt_ledger=led, criteria=CRIT, now=BEFORE)
    ss = E.settle(s, "seller", "d-e1", receipt=rcp, receipt_ledger=led, criteria=CRIT, now=BEFORE)
    for st in (sb, ss):
        assert st.state == E.RELEASED and st.look.verdict == V.MATCHED and st.look.verified
        assert st.row["kind"] == "deal.release" and st.row["shared"]["rail"] == "mock"
        assert st.row["mock_reference"].startswith("mock-release-")
    assert E.state(b, "d-e1") == E.RELEASED
    assert verify_file(b).ok is True and verify_file(s).ok is True
    # a settled hold writes nothing more
    n = len(deal_rows(b, "d-e1"))
    again = E.settle(b, "buyer", "d-e1", receipt=None, criteria=None, now=AFTER)
    assert again.state == E.RELEASED and again.row is None and len(deal_rows(b, "d-e1")) == n
    r = dispute("d-e1", b, s)
    assert r.verdict == V.MATCHED, r.to_dict()
    assert r.matched == 3, "commit, hold and release compared"
    assert "the buyer's mandate row records recourse escrow_challenge_window." in r.position
    for line in r.position:
        assert not any(w in line for w in VERDICT_WORDS), line
    # every step is a deal row the existing pack() carries
    _, out = pack("d-e1", b, s, tmp_path / "pack")
    kinds = [json.loads(x)["kind"] for x in
             (out / "buyer.deal.jsonl").read_text(encoding="utf-8").splitlines()]
    assert kinds == ["deal.mandate", "deal.commit", "deal.hold", "deal.release"]
    assert "| buyer | hold #1 |" in (out / "timeline.md").read_text(encoding="utf-8")


# refund paths ---------------------------------------------------------------------

def test_altered_refunds_when_the_call_is_not_the_one_the_criteria_named(tmp_path):
    b, _ = _deal(tmp_path, seller_hold=False)
    rcp, led = _receipt(tmp_path, status=500)
    st = E.settle(b, "buyer", "d-e1", receipt=rcp, receipt_ledger=led, criteria=CRIT, now=BEFORE)
    assert st.state == E.REFUNDED and st.look.verdict == V.ALTERED
    assert st.row["kind"] == "deal.refund" and st.row["shared"]["cause"] == V.ALTERED
    assert "response_status" in st.look.reason


def test_missing_refunds_when_the_receipt_row_is_not_on_the_counterpart_ledger(tmp_path):
    b, _ = _deal(tmp_path, seller_hold=False)
    rcp, _led = _receipt(tmp_path)
    other = tmp_path / "other.jsonl"
    _receipt_other = call_receipt({"method": "GET", "url": "u"}, {"status": 200, "body": "z"},
                                  ledger_path=other, witness=False, anchor=False)
    assert _receipt_other
    st = E.settle(b, "buyer", "d-e1", receipt=rcp, receipt_ledger=other, criteria=CRIT,
                  now=BEFORE)
    assert st.state == E.REFUNDED and st.look.verdict == V.MISSING
    assert st.row["shared"]["cause"] == V.MISSING


def test_missing_refunds_when_the_call_produced_nothing(tmp_path):
    b, _ = _deal(tmp_path, seller_hold=False)
    rcp, led = _receipt(tmp_path, error="upstream unreachable")
    st = E.settle(b, "buyer", "d-e1", receipt=rcp, receipt_ledger=led, criteria=CRIT, now=BEFORE)
    assert st.state == E.REFUNDED and st.look.verdict == V.MISSING


# COULD NOT LOOK: held, then the timeout ------------------------------------------------

@pytest.mark.parametrize("case", ["no_receipt", "receipt_gone", "no_ledger", "no_criteria",
                                  "wrong_criteria", "not_a_call", "not_json"])
def test_could_not_look_stays_held_before_the_timeout(tmp_path, case):
    b, _ = _deal(tmp_path, seller_hold=False)
    rcp, led = _receipt(tmp_path)
    kw = dict(receipt=rcp, receipt_ledger=led, criteria=CRIT)
    if case == "no_receipt":
        kw["receipt"] = None
    elif case == "receipt_gone":
        kw["receipt"] = tmp_path / "nope.json"
    elif case == "no_ledger":
        kw["receipt_ledger"] = None
    elif case == "no_criteria":
        kw["criteria"] = None
    elif case == "wrong_criteria":
        kw["criteria"] = dict(CRIT, response_status=201)   # not what the hold froze
    elif case == "not_a_call":
        # a genuine receipt of another kind, on the same ledger: not a call receipt
        kw["receipt"] = phone_call_receipt(["p-1", "p-2"], "2026-10-02T10:00:00Z",
                                           "2026-10-02T10:05:00Z", "sha256:abc",
                                           ledger_path=led, witness=False)
    elif case == "not_json":
        p = tmp_path / "bad.json"
        p.write_text("{not json", encoding="utf-8")
        kw["receipt"] = p
    st = E.settle(b, "buyer", "d-e1", now=BEFORE, **kw)
    assert st.state == E.HELD and st.look.verdict == V.COULD_NOT_LOOK, st.look.to_dict()
    assert st.look.reason_word in V.REASON_WORDS
    assert st.row["kind"] == "deal.look" and st.row["shared"]["verdict"] == V.COULD_NOT_LOOK
    assert E.state(b, "d-e1") == E.HELD
    assert not any(r["kind"] in ("deal.release", "deal.refund") for r in deal_rows(b, "d-e1"))


def test_could_not_look_refunds_at_the_declared_timeout(tmp_path):
    b, s = _deal(tmp_path)
    for led, party in ((b, "buyer"), (s, "seller")):
        held = E.settle(led, party, "d-e1", receipt=None, criteria=CRIT, now=BEFORE)
        assert held.state == E.HELD
        st = E.settle(led, party, "d-e1", receipt=None, criteria=CRIT, now=AFTER)
        assert st.state == E.REFUNDED and st.row["shared"]["cause"] == "timeout"
        assert st.row["ts"] == AFTER
    hold_row = next(r for r in deal_rows(b, "d-e1") if r["kind"] == "deal.hold")
    assert hold_row["shared"]["timeout_at"] == TIMEOUT, "declared at hold time"
    r = dispute("d-e1", b, s)
    assert r.verdict == V.MATCHED, r.to_dict()


def test_matched_after_the_timeout_still_releases(tmp_path):
    # the timeout governs COULD NOT LOOK only (TRANSITIONS)
    b, _ = _deal(tmp_path, seller_hold=False)
    rcp, led = _receipt(tmp_path)
    st = E.settle(b, "buyer", "d-e1", receipt=rcp, receipt_ledger=led, criteria=CRIT, now=AFTER)
    assert st.state == E.RELEASED


# the planted one-byte tamper ---------------------------------------------------------

def test_one_byte_tamper_on_the_receipt_flips_release_to_refund(tmp_path):
    rcp, led = _receipt(tmp_path)
    text = Path(rcp).read_text(encoding="utf-8")
    rd = json.loads(text)["checks"][0]["response_digest"]
    i = text.index(rd) + len(rd) - 1
    flipped = "0" if text[i] != "0" else "1"
    tampered = tmp_path / "tampered.receipt.json"
    tampered.write_text(text[:i] + flipped + text[i + 1:], encoding="utf-8")
    assert len(tampered.read_bytes()) == len(Path(rcp).read_bytes())
    diff = [k for k, (x, y) in enumerate(zip(tampered.read_bytes(), Path(rcp).read_bytes()))
            if x != y]
    assert len(diff) == 1, "exactly one byte differs"

    clean_dir, bad_dir = tmp_path / "clean", tmp_path / "bad"
    clean_dir.mkdir()
    bad_dir.mkdir()
    bc, _ = _deal(clean_dir, seller_hold=False)
    bb, _ = _deal(bad_dir, seller_hold=False)
    ok = E.settle(bc, "buyer", "d-e1", receipt=rcp, receipt_ledger=led, criteria=CRIT, now=BEFORE)
    bad = E.settle(bb, "buyer", "d-e1", receipt=tampered, receipt_ledger=led, criteria=CRIT,
                   now=BEFORE)
    assert ok.state == E.RELEASED
    assert bad.state == E.REFUNDED and bad.look.verdict == V.ALTERED
    assert "body_digest" in bad.look.reason


def test_a_tampered_counterpart_ledger_refunds(tmp_path):
    b, _ = _deal(tmp_path, seller_hold=False)
    rcp, led = _receipt(tmp_path)
    lines = led.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace('"checks":1', '"checks":2').replace('"checks": 1', '"checks": 2')
    led.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify_file(led).ok is False
    st = E.settle(b, "buyer", "d-e1", receipt=rcp, receipt_ledger=led, criteria=CRIT, now=BEFORE)
    assert st.state == E.REFUNDED and st.look.verdict == V.ALTERED


# no code path releases without a verified receipt ---------------------------------------

def test_release_writer_refuses_anything_look_did_not_verify(tmp_path):
    b, _ = _deal(tmp_path, seller_hold=False)
    d = Deal(b, "buyer", "d-e1")
    h = next(r for r in d.rows() if r["kind"] == "deal.hold")
    for lk in (E.Look(V.ALTERED, "x"), E.Look(V.MISSING, "x"), E.Look(V.COULD_NOT_LOOK, "x"),
               E.Look(V.MATCHED, "hand-made, not from look()"), None, {"verdict": V.MATCHED,
                                                                        "verified": True}):
        with pytest.raises(ValueError):
            E._release(d, h, lk, None)
    assert E.state(b, "d-e1") == E.HELD


def test_release_is_written_in_one_place_only():
    src = (ROOT / "src" / "arcaeon" / "record" / "escrow.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    writers = []
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef):
            for node in ast.walk(fn):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "_write" and node.args
                        and isinstance(node.args[0], ast.Constant)
                        and node.args[0].value == "release"):
                    writers.append(fn.name)
    assert writers == ["_release"]
    # and nothing else in the package writes a release row
    for p in (ROOT / "src" / "arcaeon").rglob("*.py"):
        if p.name == "escrow.py":
            continue
        t = p.read_text(encoding="utf-8")
        assert '_write("release"' not in t and "deal.release" not in t, p
    assert not hasattr(Deal, "release") and not hasattr(E, "release")
    assert "release" not in E.__all__


@pytest.mark.parametrize("bad", ["tampered", "wrong_ledger", "no_ledger", "no_receipt",
                                 "wrong_criteria", "criteria_field", "garbage", "not_a_call",
                                 "upstream_error"])
@pytest.mark.parametrize("now", [BEFORE, AFTER])
def test_no_unverified_input_ever_releases(tmp_path, bad, now):
    b, _ = _deal(tmp_path, seller_hold=False)
    rcp, led = _receipt(tmp_path, error="down" if bad == "upstream_error" else None)
    d = json.loads(Path(rcp).read_text(encoding="utf-8"))
    kw = dict(receipt=rcp, receipt_ledger=led, criteria=CRIT)
    if bad == "tampered":
        d["checks"][0]["response_status"] = 201
        kw["receipt"] = d
    elif bad == "wrong_ledger":
        kw["receipt_ledger"] = tmp_path / "buyer.jsonl"
    elif bad == "no_ledger":
        kw["receipt_ledger"] = None
    elif bad == "no_receipt":
        kw["receipt"] = None
    elif bad == "wrong_criteria":
        kw["criteria"] = {"seller": "acme-tools"}
    elif bad == "criteria_field":
        d2 = dict(d, subject=dict(d["subject"], seller="someone-else"))
        kw["receipt"] = d2
    elif bad == "garbage":
        kw["receipt"] = {"kind": "receipted-call"}
    elif bad == "not_a_call":
        kw["receipt"] = dict(d, kind="ballot")
    st = E.settle(b, "buyer", "d-e1", now=now, **kw)
    assert st.state != E.RELEASED, (bad, st.look.to_dict())
    assert st.look.verdict in FOUR and st.look.verdict != V.MATCHED
    assert not any(r["kind"] == "deal.release" for r in deal_rows(b, "d-e1"))


# N05: recourse on the mandate, before any work -----------------------------------------

def test_recourse_on_the_mandate_row_and_body(tmp_path):
    d = Deal(tmp_path / "b.jsonl", "buyer", "d-r")
    with pytest.raises(ValueError):
        d.mandate(merchant="m", cap="1", currency="USD", recourse="guaranteed")
    m = d.mandate(merchant="m", cap="1", currency="USD", recourse="high")
    assert m["recourse"] == "high" and m["mandate"]["recourse"] == "high"
    assert m["mandate_digest"] == digest_json(m["mandate"])
    old = Deal(tmp_path / "o.jsonl", "buyer", "d-o").mandate(merchant="m", cap="1", currency="USD")
    assert "recourse" not in old and "recourse" not in old["mandate"], "absent writes no key"
    sealed = Deal(tmp_path / "s.jsonl", "buyer", "d-s").mandate(
        merchant="m", cap="1", currency="USD", recourse="no_recourse",
        sealed=tmp_path / "side.json")
    assert sealed["recourse"] == "no_recourse" and "mandate" not in sealed
    assert RECOURSE == ("no_recourse", "escrow_challenge_window", "high")


def test_recourse_words_never_read_as_a_promise():
    words = " ".join(RECOURSE + E.STATES).lower()
    for bad in ("guarantee", "insured", "protected", "safe", "assured", "promise"):
        assert bad not in words


def test_hold_refuses_without_a_recourse_tier_recorded_before_work(tmp_path):
    kw = dict(amount="0.30", currency="USD", criteria_digest=E.criteria_digest(CRIT),
              recourse="escrow_challenge_window", timeout_at=TIMEOUT)
    # no recourse on the mandate
    b = tmp_path / "b1.jsonl"
    Deal(b, "buyer", "d").mandate(merchant="acme-tools", cap="1", currency="USD")
    with pytest.raises(ValueError, match="recourse"):
        E.hold(b, "buyer", "d", **kw)
    # recourse recorded only after work began
    b = tmp_path / "b2.jsonl"
    d = Deal(b, "buyer", "d")
    d.commit(items=ITEMS, total="0.30", currency="USD", seller="acme-tools")
    d.mandate(merchant="acme-tools", cap="1", currency="USD", recourse="escrow_challenge_window")
    with pytest.raises(ValueError, match="before work"):
        E.hold(b, "buyer", "d", **kw)
    # a different tier, and no_recourse
    b = tmp_path / "b3.jsonl"
    Deal(b, "buyer", "d").mandate(merchant="acme-tools", cap="1", currency="USD", recourse="high")
    with pytest.raises(ValueError):
        E.hold(b, "buyer", "d", **kw)
    with pytest.raises(ValueError, match="no hold"):
        E.hold(b, "buyer", "d", **dict(kw, recourse="no_recourse"))
    E.hold(b, "buyer", "d", **dict(kw, recourse="high"))
    with pytest.raises(ValueError, match="one hold"):
        E.hold(b, "buyer", "d", **dict(kw, recourse="high"))
    for bad in (dict(amount="0"), dict(amount="x"), dict(timeout_at="soon"),
                dict(criteria_digest="abc")):
        with pytest.raises(ValueError):
            E.hold(tmp_path / "b4.jsonl", "seller", "d", **dict(kw, **bad))
    with pytest.raises(ValueError):
        E.criteria_digest({"quality": "good"})


def test_dispute_checks_recourse_once_a_hold_is_on_a_tape(tmp_path):
    # seller holds; the buyer's mandate recorded no tier: MISSING
    b, s = _deal(tmp_path, seller_hold=False)
    b2, s2 = tmp_path / "b2.jsonl", tmp_path / "s2.jsonl"
    buyer, seller = Deal(b2, "buyer", "d-x"), Deal(s2, "seller", "d-x")
    buyer.mandate(merchant="acme-tools", cap="1.00", currency="USD")
    bc = buyer.commit(items=ITEMS, total="0.30", currency="USD", seller="acme-tools")
    seller.commit(items=ITEMS, total="0.30", currency="USD", seller="acme-tools",
                  mandate_digest=bc["shared"]["mandate_digest"])
    E.hold(s2, "seller", "d-x", amount="0.30", currency="USD",
           criteria_digest=E.criteria_digest(CRIT), recourse="high", timeout_at=TIMEOUT)
    r = dispute("d-x", b2, s2)
    assert r.verdict == V.MISSING and r.at == "hold#1", r.to_dict()
    # seller's hold carries a tier the buyer did not record: ALTERED
    E.hold(s, "seller", "d-e1", amount="0.30", currency="USD",
           criteria_digest=E.criteria_digest(CRIT), recourse="high", timeout_at=TIMEOUT)
    r = dispute("d-e1", b, s)
    assert r.verdict == V.ALTERED and r.at == "hold#1", r.to_dict()
    # a deal with no hold is untouched by recourse
    b3, s3 = tmp_path / "b3.jsonl", tmp_path / "s3.jsonl"
    m = Deal(b3, "buyer", "d-y")
    m.mandate(merchant="acme-tools", cap="1.00", currency="USD", recourse="no_recourse")
    c = m.commit(items=ITEMS, total="0.30", currency="USD", seller="acme-tools")
    Deal(s3, "seller", "d-y").commit(items=ITEMS, total="0.30", currency="USD",
                                     seller="acme-tools",
                                     mandate_digest=c["shared"]["mandate_digest"])
    r = dispute("d-y", b3, s3)
    assert r.verdict == V.MATCHED and not any(x.startswith("hold") for x in r.position)


# dispute() over escrow rows -------------------------------------------------------------

def test_dispute_names_a_hold_released_on_one_tape_and_refunded_on_the_other(tmp_path):
    b, s = _deal(tmp_path)
    rcp, led = _receipt(tmp_path)
    E.settle(b, "buyer", "d-e1", receipt=rcp, receipt_ledger=led, criteria=CRIT, now=BEFORE)
    E.settle(s, "seller", "d-e1", receipt=None, criteria=CRIT, now=AFTER)
    r = dispute("d-e1", b, s)
    assert r.verdict == V.ALTERED and "releases the hold" in r.reason, r.to_dict()


def test_dispute_flags_hand_written_escrow_rows(tmp_path):
    b, s = _deal(tmp_path)
    d = Deal(s, "seller", "d-e1")
    h = next(r for r in d.rows() if r["kind"] == "deal.hold")
    # a release row written around the rule, carrying a non-matching verdict
    d._write("release", {"hold_digest": h["step_digest"], "verdict": V.ALTERED,
                         "receipt_body_digest": None, "amount": "0.30", "currency": "USD",
                         "rail": "mock", "criteria_digest": h["shared"]["criteria_digest"]})
    r = dispute("d-e1", b, s)
    assert r.verdict == V.ALTERED and r.at == "release#1", r.to_dict()
    # a timeout refund written before the declared timeout
    d2 = Deal(b, "buyer", "d-e1")
    hb = next(r for r in d2.rows() if r["kind"] == "deal.hold")
    d2._write("refund", {"hold_digest": hb["step_digest"], "verdict": V.COULD_NOT_LOOK,
                         "receipt_body_digest": None, "amount": "0.30", "currency": "USD",
                         "rail": "mock", "cause": "timeout"}, ts=BEFORE)
    r = dispute("d-e1", b, s)
    assert any("before the hold's timeout_at" in f.reason for f in r.findings), r.to_dict()


def test_old_deals_say_nothing_about_escrow(tmp_path):
    b, s = tmp_path / "b.jsonl", tmp_path / "s.jsonl"
    m = Deal(b, "buyer", "d-old")
    m.mandate(merchant="acme", cap="60.00", currency="USD")
    c = m.commit(items=ITEMS, total="0.30", currency="USD", seller="acme")
    Deal(s, "seller", "d-old").commit(items=ITEMS, total="0.30", currency="USD", seller="acme",
                                      mandate_digest=c["shared"]["mandate_digest"])
    r = dispute("d-old", b, s)
    assert r.verdict == V.MATCHED
    for step in ("hold", "look", "release", "refund", "recourse"):
        assert not any(line.startswith(step) or f" {step} " in line for line in r.position), step


# the CLI ----------------------------------------------------------------------------------

def test_cli_hold_settle_state(tmp_path, capsys):
    b, s = tmp_path / "buyer.jsonl", tmp_path / "seller.jsonl"
    assert cli.main(["deal", "mandate", str(b), "--deal", "d-c", "--merchant", "acme-tools",
                     "--cap", "1.00", "--currency", "USD",
                     "--recourse", "escrow_challenge_window"]) == 0
    crit = tmp_path / "criteria.json"
    crit.write_text(json.dumps(CRIT), encoding="utf-8")
    assert cli.main(["escrow", "hold", str(b), "--deal", "d-c", "--party", "buyer",
                     "--amount", "0.30", "--currency", "USD", "--criteria", str(crit),
                     "--recourse", "escrow_challenge_window", "--timeout-at", TIMEOUT]) == 0
    capsys.readouterr()
    assert cli.main(["escrow", "state", str(b), "--deal", "d-c"]) == 0
    assert capsys.readouterr().out.strip() == "HELD"
    assert cli.main(["escrow", "state", str(b), "--deal", "d-none"]) == 3
    rcp, led = _receipt(tmp_path)
    base = ["escrow", "settle", str(b), "--deal", "d-c", "--party", "buyer",
            "--criteria", str(crit), "--receipt-ledger", str(led)]
    assert cli.main(base + ["--receipt", str(tmp_path / "gone.json"), "--now", BEFORE]) == 3
    assert "HELD: COULD NOT LOOK" in capsys.readouterr().out
    assert cli.main(base + ["--receipt", str(rcp), "--now", BEFORE]) == 0
    out = capsys.readouterr().out
    assert out.startswith("RELEASED: MATCHED") and "mock rail: no money moved" in out
    assert cli.main(base + ["--receipt", str(rcp), "--now", BEFORE]) == 0
    assert "already RELEASED" in capsys.readouterr().out
    assert cli.main(["escrow", "hold", str(b), "--deal", "d-c", "--party", "buyer",
                     "--amount", "0.30", "--currency", "USD", "--criteria-digest", "x",
                     "--recourse", "no_recourse", "--timeout-at", TIMEOUT]) == 2
    assert cli.main(["escrow", "frob"]) == 2
    assert cli.main(["escrow", "--help"]) == 0
    assert "MOCK RAIL ONLY" in capsys.readouterr().out


def test_module_says_mock_rail_and_never_holds_funds():
    doc = E.__doc__
    assert "MOCK RAIL ONLY" in doc and "never holds money" in doc and "never moves money" in doc


def test_transition_table_uses_only_the_four_words():
    assert {v for _, v, _ in E.TRANSITIONS} == set(FOUR)
    assert set(E.TRANSITIONS.values()) <= set(E.STATES)
    assert E.TRANSITIONS[(E.HELD, V.COULD_NOT_LOOK, False)] == E.HELD
    assert E.TRANSITIONS[(E.HELD, V.COULD_NOT_LOOK, True)] == E.REFUNDED
