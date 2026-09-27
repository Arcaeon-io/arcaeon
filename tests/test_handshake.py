"""KH7 unit tests: arcaeon.record.handshake, the CLI subcommand, the handlers.

Two agents on one machine, two ledgers, no network. The heavy test
(tests/heavy/test_kh7_handshake.py) runs the same flow over two servers.
"""
import json
from pathlib import Path

import pytest

import _arcaeon_chain as C
from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.record import handshake as H
from arcaeon.record.deal import deal_rows, dispute
from arcaeon.record.ledger import verify_file
from arcaeon.record.row import digest_json
from arcaeon.serve import h_handshake
from arcaeon.serve import routes as R

TERMS = {"task": "summarize the q3 notes", "fee": "4.00", "currency": "USD",
         "due": "2026-10-01T00:00:00Z"}


@pytest.fixture(autouse=True)
def _quiet(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")


def _pair(tmp, hid="h-t1", terms=TERMS):
    a, b = tmp / "agent_a.jsonl", tmp / "agent_b.jsonl"
    offer = H.propose(a, dict(terms), agent="agent-a", to="agent-b", handshake=hid)
    got = H.accept(b, offer, agent="agent-b")
    return a, b, offer, got


# the honest pair -----------------------------------------------------------------

def test_honest_pair_is_agreed_terms_exit_0(tmp_path):
    a, b, offer, got = _pair(tmp_path)
    r = H.verify(a, b)
    assert r.verdict == H.AGREED_TERMS and r.exit_code == 0 and bool(r), r.to_dict()
    assert r.handshake == "h-t1" and r.counts[H.AGREED_TERMS] == 1
    d = r.to_dict()
    assert d["results"][0]["proposer_ledger"] == "a" and d["results"][0]["acceptor"] == "agent-b"
    assert d["limits"] == H.LIMITS and d["exit_code"] == 0
    assert got["terms_digest"] == offer["terms_digest"] and got["proposer_chain"] == offer["proposer_chain"]
    # order of the two paths does not matter: roles come from the rows
    assert H.verify(b, a).verdict == H.AGREED_TERMS


def test_rows_are_deal_rows_written_by_the_deal_writer(tmp_path):
    a, b, offer, _ = _pair(tmp_path)
    (pa,), (pb,) = C.rows(a), C.rows(b)
    assert pa["kind"] == H.KIND_PROPOSE and pa["party"] == "proposer" and pa["deal"] == "h-t1"
    assert pb["kind"] == H.KIND_ACCEPT and pb["party"] == "acceptor" and pb["agent"] == "agent-b"
    assert pa["shared"] == pb["shared"] == {"handshake": "h-t1", "proposer": "agent-a",
                                            "to": "agent-b", "terms": TERMS}
    assert pa["step_digest"] == digest_json(pa["shared"]) == offer["terms_digest"]
    assert pb["proposal_chain"] == pa["chain"]
    assert verify_file(a).ok and verify_file(b).ok
    assert deal_rows(a, "h-t1") == [pa]                 # `deal show` reads them
    # a handshake step is not a sale step: dispute says so, never MATCHED
    assert dispute("h-t1", a, b).verdict == V.COULD_NOT_LOOK


def test_ids_are_generated_when_not_given(tmp_path):
    offer = H.propose(tmp_path / "a.jsonl", {"x": 1})
    assert offer["handshake"].startswith("h-") and offer["proposer"] is None


# DIFFERENT TERMS ------------------------------------------------------------------

def test_proposer_proposes_again_after_accept_is_different_terms(tmp_path):
    a, b, _, _ = _pair(tmp_path)
    H.propose(a, dict(TERMS, fee="40.00"), agent="agent-a", to="agent-b", handshake="h-t1")
    r = H.verify(a, b)
    assert r.verdict == H.DIFFERENT_TERMS and r.exit_code == 1, r.to_dict()
    res = r.results[0]
    assert res["fields"] == ["terms.fee"] and res["proposer_row"] == 2
    assert any("2 proposals" in p for p in res["position"])


def test_terms_edited_in_place_after_accept_is_different_terms(tmp_path):
    a, b, _, _ = _pair(tmp_path)
    rows = C.rows(a)
    rows[0]["shared"]["terms"]["fee"] = "0.40"          # a hand edit, chain not redone
    a.write_text("".join(json.dumps(x) + "\n" for x in rows), encoding="utf-8")
    assert verify_file(a).ok is False
    r = H.verify(a, b)
    assert r.verdict == H.DIFFERENT_TERMS and r.exit_code == 1, r.to_dict()
    assert r.results[0]["fields"] == ["terms.fee"]
    assert any("does not verify" in p for p in r.results[0]["position"])


def test_rechained_rewrite_of_the_terms_is_different_terms(tmp_path):
    a, b, _, _ = _pair(tmp_path)
    rows = C.rows(b)
    rows[0]["shared"]["terms"]["due"] = "2027-01-01T00:00:00Z"
    rows[0]["step_digest"] = digest_json(rows[0]["shared"])
    C.write_rechained(b, rows)                          # a forger's copy that verifies
    assert verify_file(b).ok
    r = H.verify(a, b)
    assert r.verdict == H.DIFFERENT_TERMS and r.results[0]["fields"] == ["terms.due"]


def test_step_digest_that_no_longer_matches_its_body_is_different_terms(tmp_path):
    a, b, _, _ = _pair(tmp_path)
    rows = C.rows(b)
    rows[0]["step_digest"] = "sha256:json-c14n:v1:" + "0" * 64
    C.write_rechained(b, rows)
    r = H.verify(a, b)
    assert r.verdict == H.DIFFERENT_TERMS and r.results[0]["fields"] == ["step_digest"]


# MISSING ---------------------------------------------------------------------------

def test_never_accepted_is_missing_exit_1(tmp_path):
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    H.propose(a, TERMS, agent="agent-a", handshake="h-t2")
    H.propose(b, {"other": True}, agent="agent-b", handshake="h-other")
    r = H.verify(a, b, "h-t2")
    assert r.verdict == H.MISSING and r.exit_code == 1
    assert "never accepted" in r.reason


def test_acceptance_on_the_proposers_own_ledger_is_missing(tmp_path):
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    offer = H.propose(a, TERMS, agent="agent-a", handshake="h-t3")
    H.accept(a, offer)                                  # one side countersigning itself
    H.propose(b, {"unrelated": 1}, handshake="h-x")
    r = H.verify(a, b, "h-t3")
    assert r.verdict == H.MISSING and "proposer's own" in r.reason


def test_acceptance_with_no_proposal_is_missing(tmp_path):
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    offer = H.propose(tmp_path / "elsewhere.jsonl", TERMS, handshake="h-t4")
    H.accept(b, offer)
    H.propose(a, {"unrelated": 1}, handshake="h-y")
    r = H.verify(a, b, "h-t4")
    assert r.verdict == H.MISSING and "proposed on neither" in r.reason


def test_many_handshakes_keep_their_counts_and_the_worst_word_leads(tmp_path):
    a, b, _, _ = _pair(tmp_path, "h-ok")
    H.propose(a, TERMS, handshake="h-open")
    r = H.verify(a, b)
    assert r.verdict == H.MISSING and r.counts == {H.AGREED_TERMS: 1, H.DIFFERENT_TERMS: 0,
                                                   H.MISSING: 1, H.COULD_NOT_LOOK: 0}
    assert r.reason.startswith("1 of 2 handshakes")


# COULD NOT LOOK --------------------------------------------------------------------

@pytest.mark.parametrize("make", ["missing", "directory", "garbage"])
def test_unreadable_ledger_is_could_not_look_exit_3(tmp_path, make):
    a, b, _, _ = _pair(tmp_path)
    if make == "missing":
        b.unlink()
    elif make == "directory":
        b.unlink()
        b.mkdir()
    else:
        b.write_text(b.read_text(encoding="utf-8") + "{not json\n", encoding="utf-8")
    r = H.verify(a, b)
    assert r.verdict == V.COULD_NOT_LOOK and r.exit_code == 3, r.to_dict()
    assert r.reason_word in V.REASON_WORDS and r.looked_for and r.where
    assert r.reason_word == ("missing" if make == "missing" else "unreadable")


def test_broken_chain_with_agreeing_terms_is_could_not_look(tmp_path):
    a, b, _, _ = _pair(tmp_path)
    rows = C.rows(a)
    rows[0]["ts"] = "2020-01-01T00:00:00Z"              # edited, but not the terms
    a.write_text("".join(json.dumps(x) + "\n" for x in rows), encoding="utf-8")
    r = H.verify(a, b)
    assert r.verdict == V.COULD_NOT_LOOK and r.exit_code == 3 and r.reason_word == "unreadable"


def test_no_handshake_rows_or_unknown_id_is_could_not_look_name_not_found(tmp_path):
    a, b, _, _ = _pair(tmp_path)
    r = H.verify(a, b, "h-nope")
    assert r.verdict == V.COULD_NOT_LOOK and r.reason_word == "name_not_found"
    e1, e2 = tmp_path / "e1.jsonl", tmp_path / "e2.jsonl"
    e1.write_text("", encoding="utf-8")
    e2.write_text("", encoding="utf-8")
    assert H.verify(e1, e2).verdict == V.COULD_NOT_LOOK


# accept refuses what it should not countersign ------------------------------------

def test_accept_refuses_an_offer_changed_in_transit(tmp_path):
    offer = H.propose(tmp_path / "a.jsonl", TERMS, agent="agent-a", to="agent-b")
    bad = dict(offer, terms=dict(TERMS, fee="0.01"))
    with pytest.raises(ValueError, match="terms_digest"):
        H.accept(tmp_path / "b.jsonl", bad, agent="agent-b")
    with pytest.raises(ValueError, match="not 'agent-c'"):
        H.accept(tmp_path / "b.jsonl", offer, agent="agent-c")
    for junk in ([], {"handshake": "h-1"}, dict(offer, kind="other/1")):
        with pytest.raises(ValueError):
            H.accept(tmp_path / "b.jsonl", junk)
    assert not (tmp_path / "b.jsonl").exists(), "nothing was countersigned"


def test_propose_refuses_terms_that_are_not_an_object(tmp_path):
    with pytest.raises(ValueError):
        H.propose(tmp_path / "a.jsonl", ["not", "an", "object"])


# words and exits ------------------------------------------------------------------

def test_the_four_words_and_their_exits():
    assert H.WORDS == ("AGREED TERMS", "DIFFERENT TERMS", "MISSING", "COULD NOT LOOK")
    assert [H.exit_for(w) for w in H.WORDS] == [0, 1, 1, 3]
    assert H.exit_for("SOMETHING ELSE") == 3, "an unknown word is never green"


# the handlers (the HTTP routes call exactly these) --------------------------------

def test_handlers_are_the_routes_declared_and_answer_with_exit(tmp_path):
    for op in ("propose", "accept", "verify"):
        route = R.find("POST", f"/v1/handshake/{op}")
        assert route.resolve() is getattr(h_handshake, op)
    a, b = str(tmp_path / "a.jsonl"), str(tmp_path / "b.jsonl")
    p = h_handshake.propose({"ledger": a, "terms": TERMS, "agent": "agent-a"})
    assert p["exit"] == 0
    acc = h_handshake.accept({"ledger": b, "proposal": p["proposal"], "agent": "agent-b"})
    assert acc["exit"] == 0 and acc["acceptance"]["kind"] == H.ACCEPTANCE_KIND
    v = h_handshake.verify({"a": a, "b": b})
    assert v["verdict"] == H.AGREED_TERMS and v["exit"] == 0
    assert h_handshake.propose({"terms": TERMS})["exit"] == 2
    assert h_handshake.propose({"ledger": a, "terms": "x"})["exit"] == 2
    assert h_handshake.accept({"ledger": b, "proposal": dict(p["proposal"], terms={})})["exit"] == 2
    assert h_handshake.verify({"a": a})["exit"] == 2
    assert h_handshake.verify({"a": a, "b": str(tmp_path / "gone.jsonl")})["exit"] == 3


# the CLI: `arcaeon deal handshake` -------------------------------------------------

def test_cli_round_trip_and_exit_codes(tmp_path, capsys):
    a, b = str(tmp_path / "a.jsonl"), str(tmp_path / "b.jsonl")
    assert cli.main(["deal", "handshake", "propose", a, "--terms", json.dumps(TERMS),
                     "--agent", "agent-a", "--to", "agent-b", "--id", "h-cli"]) == 0
    offer = json.loads(capsys.readouterr().out)
    of = tmp_path / "offer.json"
    of.write_text(json.dumps(offer), encoding="utf-8")
    assert cli.main(["deal", "handshake", "accept", b, "--proposal-file", str(of),
                     "--agent", "agent-b"]) == 0
    capsys.readouterr()
    assert cli.main(["deal", "handshake", "verify", a, b]) == 0
    assert capsys.readouterr().out.startswith("AGREED TERMS")
    assert cli.main(["deal", "handshake", "verify", a, b, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == H.AGREED_TERMS
    assert cli.main(["deal", "handshake", "propose", a, "--terms", json.dumps(dict(TERMS, fee="9")),
                     "--id", "h-cli", "--agent", "agent-a", "--to", "agent-b"]) == 0
    capsys.readouterr()
    assert cli.main(["deal", "handshake", "verify", a, b]) == 1
    assert capsys.readouterr().out.startswith("DIFFERENT TERMS")
    assert cli.main(["deal", "handshake", "verify", a, str(tmp_path / "gone.jsonl")]) == 3
    assert cli.main(["deal", "handshake", "propose", a, "--terms", "{nope"]) == 2
    assert cli.main(["deal", "handshake", "frob"]) == 2
    assert cli.main(["deal", "handshake", "--help"]) == 0
    assert cli.main(["deal", "handshake"]) == 2
    assert "handshake" in (capsys.readouterr().out)
