"""x402 V2 response extension (D063 / TE-24): the envelope on a paid
response, the gate before the mock escrow releases. Every key is a throwaway
seed in tmp_path; nothing reaches the network; the rail is in memory."""
from __future__ import annotations

import base64
import copy
import json
import secrets
from pathlib import Path

import pytest

from arcaeon import verdict as V
from arcaeon.prove import envelope as E
from arcaeon.prove import x402_ext as X

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

BIND = {"label": "premium market data", "audience": "buyer-agent-7", "deal": "d-x402-1",
        "purpose": "market-data", "not_after": "7d"}
BODY = b'{"price":"101.20","symbol":"ACME"}\n'
#: the success SettlementResponse from x402-specification-v2.md section 5.3.1
SETTLED = {"success": True,
           "transaction": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
           "network": "eip155:84532", "payer": "0x857b06519E91e3A54538791bDbb0E22373e36b66"}


@pytest.fixture(autouse=True)
def _cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    home = tmp_path / "home"                                 # never the real home folder
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))


def _sealed(tmp_path: Path, signed: bool = True):
    key = tmp_path / "seal.key"
    key.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"), encoding="ascii")
    f = tmp_path / "seller" / "data.json"
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(BODY)
    env = E.seal(f, key_file=key if signed else None, **BIND)
    sigs = env["dsseEnvelope"]["signatures"]
    return env, (sigs[0]["keyid"] if sigs else "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")


def _paid(tmp_path, **kw):
    env, did = _sealed(tmp_path, **kw)
    return X.attach(SETTLED, env), did


def _check(resp, body, did, tmp_path, audience="buyer-agent-7", action="pay", deal="d-x402-1",
           purpose="market-data"):
    return X.check(resp, body, audience, action, signers=[did], deal=deal, purpose=purpose,
                   record_dir=tmp_path / "records",
                   ledger=tmp_path / "ledger.jsonl" if deal is not None else None)


# --- placement --------------------------------------------------------------------

def test_attach_places_the_envelope_under_the_extension_key(tmp_path):
    env, _ = _sealed(tmp_path)
    paid = X.attach(SETTLED, env)
    entry = paid["extensions"]["arcaeon-labeled-exchange"]
    assert set(entry) == {"info", "schema"}                 # the V2 extension shape
    assert entry["info"] == {"envelope": env}
    assert "bundle" not in json.dumps(entry)
    assert "extensions" not in SETTLED                      # the input is not changed
    with pytest.raises(ValueError):
        X.attach(paid, env)                                  # no silent overwrite
    assert X.attach(paid, env, replace=True) == paid


def test_header_round_trip_and_check_from_the_header_value(tmp_path):
    paid, did = _paid(tmp_path)
    header = X.encode_header(paid)
    assert X.decode_header(header) == paid
    c = _check(header, BODY, did, tmp_path)
    assert c.release is True and c.verdict == V.VERIFIED


# --- the four outcomes ------------------------------------------------------------

def test_good_response_releases(tmp_path):
    paid, did = _paid(tmp_path)
    rail = X.MockEscrowRail()
    rail.hold("d-x402-1", "0.01", "USDC")
    c = _check(paid, BODY, did, tmp_path)
    assert c.release is True and c.verdict == V.VERIFIED and c.decision.decision == "allow"
    assert c.extension == "present" and c.settled
    assert rail.settle("d-x402-1", c)["released"] is True
    assert rail.state("d-x402-1") == X.RELEASED
    again = rail.settle("d-x402-1", c)                       # never released twice
    assert again["released"] is False and rail.state("d-x402-1") == X.RELEASED


def test_tampered_body_is_broken_no_release_and_evidence(tmp_path):
    paid, did = _paid(tmp_path)
    rail = X.MockEscrowRail()
    rail.hold("d-x402-1", "0.01", "USDC")
    c = _check(paid, BODY.replace(b"101.20", b"999.99"), did, tmp_path)
    assert c.release is False and c.verdict == V.BROKEN
    assert c.reason.startswith("do not release")
    ev = Path(c.evidence)
    assert (ev / "evidence.json").is_file()
    assert (ev / "x402-settlement-response.json").is_file()
    assert json.loads((ev / "evidence.json").read_text(encoding="utf-8"))["verdict"] == V.BROKEN
    out = rail.settle("d-x402-1", c)
    assert out["released"] is False and rail.state("d-x402-1") == X.HELD
    assert rail.holds["d-x402-1"]["evidence"] == c.evidence
    from arcaeon.prove import dispute_packet as P             # the pack still renders
    assert P.render_json(P.from_evidence(c.evidence))


def test_stripped_extension_is_could_not_look_and_holds(tmp_path):
    paid, did = _paid(tmp_path)
    stripped = copy.deepcopy(paid)
    del stripped["extensions"]["arcaeon-labeled-exchange"]
    for resp in (stripped, SETTLED):
        c = _check(resp, BODY, did, tmp_path)
        assert c.release is False and c.verdict == V.COULD_NOT_LOOK
        assert c.extension == "missing" and c.reason.startswith("hold")
        # D066 on the stack: a COULD NOT LOOK refusal with a deal id writes a pack too
        # and, A16, the dispute packet with the verdict recorded as COULD NOT LOOK
        assert c.evidence is not None and c.dispute["verdict"] == V.COULD_NOT_LOOK
    rail = X.MockEscrowRail()
    rail.hold("d-x402-1", "0.01", "USDC")
    assert rail.settle("d-x402-1", c)["released"] is False
    assert rail.state("d-x402-1") == X.HELD


def test_wrong_audience_is_broken(tmp_path):
    paid, did = _paid(tmp_path)
    c = _check(paid, BODY, did, tmp_path, audience="buyer-agent-8")
    assert c.release is False and c.verdict == V.BROKEN
    assert any("audience" in r for r in c.decision.reasons)


# --- the other refusals -----------------------------------------------------------

def test_unsigned_envelope_is_could_not_look(tmp_path):
    paid, did = _paid(tmp_path, signed=False)
    c = _check(paid, BODY, did, tmp_path)
    assert c.release is False and c.verdict == V.COULD_NOT_LOOK


def test_settlement_without_success_does_not_release(tmp_path):
    paid, did = _paid(tmp_path)
    paid["success"] = False
    c = _check(paid, BODY, did, tmp_path)
    assert c.verdict == V.VERIFIED and c.release is False and not c.settled


def test_rail_refuses_a_check_run_for_another_deal_or_none(tmp_path):
    paid, did = _paid(tmp_path)
    rail = X.MockEscrowRail()
    rail.hold("d-other", "0.01", "USDC")
    assert rail.settle("d-other", _check(paid, BODY, did, tmp_path))["released"] is False
    c = _check(paid, BODY, did, tmp_path, deal=None)        # deal not named: a replay (F2)
    assert c.release is False and c.verdict == V.COULD_NOT_LOOK and c.escrow == "HOLD"
    assert "pass --deal so the envelope is held to this exchange" in c.decision.reasons
    assert rail.settle("d-other", c)["released"] is False
    assert rail.state("d-other") == X.HELD


def test_act_without_deal_or_purpose_never_releases(tmp_path):
    """R3-1: the gate allows `act` unbound (F2 binds pay/irreversible only), but a
    release moves escrowed money: an envelope sealed for another deal must not
    come back RELEASE because the check named no deal."""
    paid, did = _paid(tmp_path)
    for deal, purpose in ((None, None), (None, "market-data"), ("d-x402-1", None)):
        c = _check(paid, BODY, did, tmp_path, action="act", deal=deal, purpose=purpose)
        assert c.release is False and c.escrow == "HOLD", (deal, purpose)
        assert "--deal and --purpose" in c.reason
    rail = X.MockEscrowRail()
    rail.hold("d-x402-1", "0.01", "USDC")
    c = _check(paid, BODY, did, tmp_path, action="act", deal=None, purpose=None)
    assert rail.settle("d-x402-1", c)["released"] is False


def test_only_pay_or_act(tmp_path):
    paid, did = _paid(tmp_path)
    assert _check(paid, BODY, did, tmp_path, action="act").release is True
    for bad in ("read", "irreversible", "release"):
        with pytest.raises(ValueError):
            _check(paid, BODY, did, tmp_path, action=bad)


# --- hostile input: an answer, never a traceback ------------------------------------

def _deep(n):
    s = "[" * n + "]" * n
    return '{"success":true,"extensions":{"arcaeon-labeled-exchange":{"info":{"envelope":' + s + "}}}}"


HOSTILE = [
    None, 7, [], "", "not base64 !!", b"\xff\xfe", "{", "[1,2]",
    '{"success":true,"success":false}',                                   # duplicate key
    base64.b64encode(b'{"a":1,"a":2}').decode(),
    _deep(5000), "x" * (X.MAX_RESPONSE_BYTES + 1),
    {"success": True, "extensions": "arcaeon-labeled-exchange"},
    {"success": True, "extensions": {"arcaeon-labeled-exchange": None}},
    {"success": True, "extensions": {"arcaeon-labeled-exchange": {"info": []}}},
    {"success": True, "extensions": {"arcaeon-labeled-exchange": {"info": {"bundle": {}}}}},
    {"success": True, "extensions": {"arcaeon-labeled-exchange": {"info": {"envelope": "x"}}}},
    {"success": True, "extensions": {"arcaeon-labeled-exchange": {"info": {"envelope": float("nan")}}}},
    {"success": True, "extensions": {"arcaeon-labeled-exchange": {"info": {"envelope": {1, 2}}}}},
    {"success": True, "extensions": {"arcaeon-labeled-exchange": {"info": {"envelope": {
        "mediaType": E.MEDIA_TYPE, "dsseEnvelope": {"payloadType": E.PAYLOAD_TYPE,
                                                    "payload": "!!", "signatures": []}}}}}},
]


@pytest.mark.parametrize("resp", HOSTILE, ids=range(len(HOSTILE)))
def test_hostile_response_holds_without_a_traceback(tmp_path, resp):
    c = X.check(resp, BODY, "buyer-agent-7", "pay", signers=["did:key:zX"], deal="d-x402-1",
                record_dir=tmp_path / "records", ledger=tmp_path / "ledger.jsonl")
    assert c.release is False
    assert c.verdict in (V.COULD_NOT_LOOK, V.BROKEN)
    json.dumps(c.to_dict(), default=str)


def test_hostile_body_and_deep_response_dict(tmp_path):
    paid, did = _paid(tmp_path)
    for body in (None, "text", 12):
        c = _check(paid, body, did, tmp_path)
        assert c.release is False and c.verdict == V.COULD_NOT_LOOK
    deep: dict = {}
    cur = deep
    for _ in range(5000):
        cur["a"] = {}
        cur = cur["a"]
    paid["extensions"]["arcaeon-labeled-exchange"]["info"]["envelope"] = deep
    c = _check(paid, BODY, did, tmp_path)
    assert c.release is False


def test_hostile_sidecar_name_stays_in_the_temp_dir(tmp_path):
    paid, did = _paid(tmp_path)
    c = X.check(paid, BODY, "buyer-agent-7", "pay", signers=[did], deal="d-x402-1",
                purpose="market-data", file_name="../../escape.json", ledger=tmp_path / "ledger.jsonl")
    assert c.release is True and not (tmp_path / "escape.json").exists()


# --- D068: BROKEN is a HOLD with a dispute packet, never a refund ------------------

class RefundTrapRail(X.MockEscrowRail):
    """A mock rail with a refund() that records and raises: the x402 path
    must never reach it."""

    def __init__(self) -> None:
        super().__init__()
        self.refunds: list = []

    def refund(self, *a, **kw):
        self.refunds.append((a, kw))
        raise AssertionError("the x402 path called refund()")


def test_extension_id_is_fixed():
    assert X.EXTENSION_KEY == "arcaeon-labeled-exchange"
    assert X.ESCROW_ACTIONS == ("RELEASE", "HOLD")          # no REFUND word at all
    assert not hasattr(X.MockEscrowRail, "refund")


def test_the_bare_old_id_is_not_read(tmp_path):
    paid, did = _paid(tmp_path)
    old = copy.deepcopy(paid)
    old["extensions"] = {"labeled-exchange": old["extensions"].pop("arcaeon-labeled-exchange")}
    c = _check(old, BODY, did, tmp_path)
    assert c.verdict == V.COULD_NOT_LOOK and c.extension == "missing"
    assert c.escrow == "HOLD" and c.release is False


def test_broken_holds_makes_a_packet_and_never_refunds(tmp_path):
    from arcaeon.prove import dispute_packet as P
    paid, did = _paid(tmp_path)
    rail = RefundTrapRail()
    rail.hold("d-x402-1", "0.01", "USDC")
    c = _check(paid, BODY.replace(b"101.20", b"999.99"), did, tmp_path)
    assert c.verdict == V.BROKEN and c.escrow == "HOLD" and c.release is False
    assert c.dispute and c.dispute["kind"] == P.KIND and c.dispute["verdict"] == V.BROKEN
    assert c.dispute_error is None
    ev = Path(c.evidence)
    assert json.loads((ev / X.PACKET_JSON).read_text(encoding="utf-8"))["kind"] == P.KIND
    assert (ev / X.PACKET_MD).read_text(encoding="utf-8").strip()
    out = rail.settle("d-x402-1", c)
    assert out["released"] is False and out["state"] == X.HELD and out["escrow"] == "HOLD"
    assert rail.refunds == []                                  # refund() never called
    assert rail.state("d-x402-1") == X.HELD
    assert rail.holds["d-x402-1"]["dispute"]["kind"] == P.KIND
    assert any(e["event"] == "dispute" for e in rail.log)
    assert c.to_dict()["escrow"] == "HOLD" and c.to_dict()["dispute"]["kind"] == P.KIND
    # D066 on the stack: the settlement response and the packet are in the pack before
    # its gate.evidence row, so the row's pack digest still matches
    from arcaeon.prove import gate as G
    row = c.decision.chain_row
    assert row and c.decision.chain_error is None
    assert (ev / "x402-settlement-response.json").is_file()
    assert G.verify_evidence_pack(ev, row)["verdict"] == V.VERIFIED


def test_deal_without_ledger_raises_before_anything(tmp_path):
    with pytest.raises(ValueError):
        X.check({}, BODY, "buyer-agent-7", "pay", deal="d-x402-1")


def test_broken_without_a_deal_id_still_has_a_packet(tmp_path):
    paid, did = _paid(tmp_path)
    c = _check(paid, BODY, did, tmp_path, audience="buyer-agent-8", deal=None)
    assert c.verdict == V.BROKEN and c.escrow == "HOLD" and c.evidence is None
    assert c.dispute and c.dispute["verdict"] == V.BROKEN
    assert c.dispute["handed"]["sha256"]                        # hashed while the body existed


def test_could_not_look_with_a_deal_holds_with_a_packet_that_says_could_not_look(tmp_path):
    """A16: money is held on a named deal either way, so COULD NOT LOOK writes
    the dispute packet too, as BROKEN does. The packet records COULD NOT LOOK,
    never BROKEN, and lists nothing as failed: it asserts no finding."""
    from arcaeon.prove import dispute_packet as P
    from arcaeon.prove import gate as G
    paid, did = _paid(tmp_path)
    del paid["extensions"]["arcaeon-labeled-exchange"]
    rail = RefundTrapRail()
    rail.hold("d-x402-1", "0.01", "USDC")
    c = _check(paid, BODY, did, tmp_path)
    assert c.verdict == V.COULD_NOT_LOOK and c.escrow == "HOLD" and c.release is False
    assert c.dispute is not None and c.dispute_error is None
    assert c.dispute["kind"] == P.KIND and c.dispute["verdict"] == V.COULD_NOT_LOOK
    assert c.dispute["failed"] == [] and c.dispute["not_checked"]
    ev = Path(c.evidence)
    on_disk = json.loads((ev / X.PACKET_JSON).read_text(encoding="utf-8"))
    assert on_disk["verdict"] == V.COULD_NOT_LOOK and V.BROKEN not in on_disk["verdict"]
    md = (ev / X.PACKET_MD).read_text(encoding="utf-8")
    assert "**COULD NOT LOOK**" in md and "**BROKEN**" not in md
    # the packet is in the pack before its gate.evidence row: the digest still matches
    assert G.verify_evidence_pack(ev, c.decision.chain_row)["verdict"] == V.VERIFIED
    for _ in range(3):                                          # held, however often settled
        assert rail.settle("d-x402-1", c)["state"] == X.HELD
    assert rail.refunds == [] and rail.holds["d-x402-1"]["dispute"]["verdict"] == V.COULD_NOT_LOOK
    assert c.reason.startswith("hold")


def test_could_not_look_without_a_deal_has_no_packet(tmp_path):
    paid, did = _paid(tmp_path)
    del paid["extensions"]["arcaeon-labeled-exchange"]
    c = _check(paid, BODY, did, tmp_path, deal=None)
    assert c.verdict == V.COULD_NOT_LOOK and c.escrow == "HOLD"
    assert c.evidence is None and c.dispute is None


def test_verified_path_unchanged(tmp_path):
    paid, did = _paid(tmp_path)
    rail = RefundTrapRail()
    rail.hold("d-x402-1", "0.01", "USDC")
    c = _check(paid, BODY, did, tmp_path)
    assert c.release is True and c.escrow == "RELEASE" and c.dispute is None
    out = rail.settle("d-x402-1", c)
    assert out["released"] is True and out["escrow"] == "RELEASE"
    assert rail.state("d-x402-1") == X.RELEASED and rail.refunds == []


# --- F2: pay needs the exchange named (no cross-deal replay) ---------------------------

def test_pay_without_deal_holds_could_not_look_no_traceback(tmp_path):
    paid, did = _paid(tmp_path)                     # sealed for d-x402-1 / market-data
    rail = RefundTrapRail()
    rail.hold("d-x402-1", "0.01", "USDC")
    c = X.check(paid, BODY, "buyer-agent-7", "pay", signers=[did])
    assert c.release is False and c.escrow == "HOLD" and c.verdict == V.COULD_NOT_LOOK
    assert "pass --deal so the envelope is held to this exchange" in c.decision.reasons
    assert c.evidence is None and c.dispute is None
    json.dumps(c.to_dict(), default=str)
    assert rail.settle("d-x402-1", c)["released"] is False and rail.refunds == []
    c = _check(paid, BODY, did, tmp_path, purpose=None)
    assert c.release is False and c.verdict == V.COULD_NOT_LOOK
    assert "pass --purpose so the envelope is held to this exchange" in c.decision.reasons


# --- F1: an exception inside the gate is a HOLD, never a traceback ----------------------

SECRET = "C:/secret/path/do-not-echo"


def _assert_held_on_crash(c, rail, word):
    assert c.release is False and c.escrow == "HOLD" and c.verdict == V.COULD_NOT_LOOK
    assert c.decision.decision == "refuse" and c.dispute is None
    assert word in c.reason and SECRET not in json.dumps(c.to_dict(), default=str)
    assert "Traceback" not in c.reason
    out = rail.settle("d-x402-1", c)
    assert out["released"] is False and rail.state("d-x402-1") == X.HELD
    assert rail.refunds == []


def test_decide_raising_is_a_hold_not_a_traceback(tmp_path, monkeypatch):
    paid, did = _paid(tmp_path)

    def boom(*a, **kw):
        raise RuntimeError(SECRET)

    monkeypatch.setattr(X.G, "decide", boom)                   # the gate as x402_ext sees it
    rail = RefundTrapRail()
    rail.hold("d-x402-1", "0.01", "USDC")
    _assert_held_on_crash(_check(paid, BODY, did, tmp_path), rail, "RuntimeError")


def test_on_pack_raising_is_a_hold_not_a_traceback(tmp_path, monkeypatch):
    paid, did = _paid(tmp_path)
    real = X.G.decide

    def leaky(*a, on_pack=None, **kw):                         # a decide that lets on_pack raise
        on_pack(tmp_path / "no-such-pack")
        return real(*a, on_pack=on_pack, **kw)

    monkeypatch.setattr(X.G, "decide", leaky)
    rail = RefundTrapRail()
    rail.hold("d-x402-1", "0.01", "USDC")
    _assert_held_on_crash(_check(paid, BODY, did, tmp_path), rail, "FileNotFoundError")


def test_unreadable_signers_is_a_hold_not_a_traceback(tmp_path):
    paid, _ = _paid(tmp_path)
    rail = RefundTrapRail()
    rail.hold("d-x402-1", "0.01", "USDC")
    c = X.check(paid, BODY, "buyer-agent-7", "pay", signers=7, deal="d-x402-1",
                purpose="market-data", record_dir=tmp_path / "records",
                ledger=tmp_path / "ledger.jsonl")
    _assert_held_on_crash(c, rail, "TypeError")


def test_dispute_pack_raising_inside_the_real_gate_still_holds(tmp_path, monkeypatch):
    paid, did = _paid(tmp_path)

    def boom(*a, **kw):
        raise RuntimeError(SECRET)

    monkeypatch.setattr(X, "_dispute_pack", boom)              # the real decide swallows on_pack
    c = _check(paid, BODY.replace(b"101.20", b"999.99"), did, tmp_path)
    assert c.release is False and c.escrow == "HOLD" and c.verdict == V.BROKEN
    json.dumps(c.to_dict(), default=str)
