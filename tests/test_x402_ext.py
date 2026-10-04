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


def _check(resp, body, did, tmp_path, audience="buyer-agent-7", action="pay", deal="d-x402-1"):
    return X.check(resp, body, audience, action, signers=[did], deal=deal,
                   record_dir=tmp_path / "records")


# --- placement --------------------------------------------------------------------

def test_attach_places_the_envelope_under_the_extension_key(tmp_path):
    env, _ = _sealed(tmp_path)
    paid = X.attach(SETTLED, env)
    entry = paid["extensions"]["labeled-exchange"]
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
    del stripped["extensions"]["labeled-exchange"]
    for resp in (stripped, SETTLED):
        c = _check(resp, BODY, did, tmp_path)
        assert c.release is False and c.verdict == V.COULD_NOT_LOOK
        assert c.extension == "missing" and c.reason.startswith("hold")
        assert c.evidence is None
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
    c = _check(paid, BODY, did, tmp_path, deal=None)        # deal not held: a replay risk
    assert c.release is True
    assert rail.settle("d-other", c)["released"] is False
    assert rail.state("d-other") == X.HELD


def test_only_pay_or_act(tmp_path):
    paid, did = _paid(tmp_path)
    assert _check(paid, BODY, did, tmp_path, action="act").release is True
    for bad in ("read", "irreversible", "release"):
        with pytest.raises(ValueError):
            _check(paid, BODY, did, tmp_path, action=bad)


# --- hostile input: an answer, never a traceback ------------------------------------

def _deep(n):
    s = "[" * n + "]" * n
    return '{"success":true,"extensions":{"labeled-exchange":{"info":{"envelope":' + s + "}}}}"


HOSTILE = [
    None, 7, [], "", "not base64 !!", b"\xff\xfe", "{", "[1,2]",
    '{"success":true,"success":false}',                                   # duplicate key
    base64.b64encode(b'{"a":1,"a":2}').decode(),
    _deep(5000), "x" * (X.MAX_RESPONSE_BYTES + 1),
    {"success": True, "extensions": "labeled-exchange"},
    {"success": True, "extensions": {"labeled-exchange": None}},
    {"success": True, "extensions": {"labeled-exchange": {"info": []}}},
    {"success": True, "extensions": {"labeled-exchange": {"info": {"bundle": {}}}}},
    {"success": True, "extensions": {"labeled-exchange": {"info": {"envelope": "x"}}}},
    {"success": True, "extensions": {"labeled-exchange": {"info": {"envelope": float("nan")}}}},
    {"success": True, "extensions": {"labeled-exchange": {"info": {"envelope": {1, 2}}}}},
    {"success": True, "extensions": {"labeled-exchange": {"info": {"envelope": {
        "mediaType": E.MEDIA_TYPE, "dsseEnvelope": {"payloadType": E.PAYLOAD_TYPE,
                                                    "payload": "!!", "signatures": []}}}}}},
]


@pytest.mark.parametrize("resp", HOSTILE, ids=range(len(HOSTILE)))
def test_hostile_response_holds_without_a_traceback(tmp_path, resp):
    c = X.check(resp, BODY, "buyer-agent-7", "pay", signers=["did:key:zX"], deal="d-x402-1",
                record_dir=tmp_path / "records")
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
    paid["extensions"]["labeled-exchange"]["info"]["envelope"] = deep
    c = _check(paid, BODY, did, tmp_path)
    assert c.release is False


def test_hostile_sidecar_name_stays_in_the_temp_dir(tmp_path):
    paid, did = _paid(tmp_path)
    c = X.check(paid, BODY, "buyer-agent-7", "pay", signers=[did], deal="d-x402-1",
                file_name="../../escape.json")
    assert c.release is True and not (tmp_path / "escape.json").exists()
