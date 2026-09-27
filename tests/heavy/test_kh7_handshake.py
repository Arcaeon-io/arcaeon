"""KH7: agent-to-agent handshake over HTTP (roadmap N23), end to end.

Two agents on one machine, each with its own `arcaeon serve` on its own
loopback port (two server threads), its own served root and its own ledger.
Agent A proposes on A's server, carries the offer to B's server, B accepts
there; either side verifies. Then the tamper cases, all over HTTP:

- one side edits the terms after accept      -> DIFFERENT TERMS, exit 1
- one side never accepts                     -> MISSING, exit 1
- a ledger that cannot be read               -> COULD NOT LOOK, exit 3

Every verdict comes back HTTP 200 with the integer `exit`: a verdict never
rides in the status. No network beyond 127.0.0.1.
"""
import inspect
import json
import shutil
import threading
import urllib.error
import urllib.request

import pytest

import _arcaeon_chain as C
from arcaeon.record import handshake as H
from arcaeon.serve import server as S

TERMS = {"task": "translate the onboarding page to Spanish", "fee": "12.00",
         "currency": "USD", "due": "2026-10-03T17:00:00Z", "revisions": 2}


@pytest.fixture()
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arcaeon-home"))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    monkeypatch.delenv("ARCAEON_KEY", raising=False)


class Agent:
    """One agent: a served root, a ledger in it, a server thread on a free port."""

    def __init__(self, name, root, token):
        self.name, self.root, self.token = name, root, token
        root.mkdir(parents=True, exist_ok=True)
        self.ledger = root / f"{name}.jsonl"
        params = inspect.signature(S.make_server).parameters
        kw = {}
        if "token" in params:
            kw["token"] = token
        if "root" in params:
            kw["root"] = str(root)
        self.server = S.make_server(port=0, **kw)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def post(self, op, body):
        req = urllib.request.Request(
            f"{self.server.url}/v1/handshake/{op}", data=json.dumps(body).encode("utf-8"),
            method="POST", headers={"Content-Type": "application/json",
                                    "Authorization": f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8") or "{}")

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


@pytest.fixture()
def agents(tmp_path, home):
    a = Agent("agent_a", tmp_path / "a_root", "token-a-" + "x" * 24)
    b = Agent("agent_b", tmp_path / "b_root", "token-b-" + "y" * 24)
    try:
        yield a, b
    finally:
        a.stop()
        b.stop()
    assert not a.thread.is_alive() and not b.thread.is_alive(), "every server stopped"


def _handshake(a, b, hid="h-kh7", terms=TERMS):
    st, p = a.post("propose", {"ledger": str(a.ledger), "terms": terms, "agent": a.name,
                               "to": b.name, "handshake": hid})
    assert st == 200 and p["exit"] == 0, p
    st, acc = b.post("accept", {"ledger": str(b.ledger), "proposal": p["proposal"],
                                "agent": b.name})
    assert st == 200 and acc["exit"] == 0, acc
    return p["proposal"], acc["acceptance"]


def _verify_on_a(a, b, hid=None):
    """B hands A a copy of its ledger (A's server reads only A's root)."""
    copy = a.root / "from_agent_b.jsonl"
    if b.ledger.exists():
        shutil.copyfile(b.ledger, copy)
    body = {"a": str(a.ledger), "b": str(copy)}
    if hid:
        body["handshake"] = hid
    return a.post("verify", body)


def test_two_agents_two_servers_two_ledgers_agree(agents):
    a, b = agents
    assert a.server.server_address[1] != b.server.server_address[1]
    offer, acc = _handshake(a, b)
    assert acc["terms_digest"] == offer["terms_digest"]
    assert [r["kind"] for r in C.rows(a.ledger)] == [H.KIND_PROPOSE]
    assert [r["kind"] for r in C.rows(b.ledger)] == [H.KIND_ACCEPT]
    st, v = _verify_on_a(a, b)
    assert st == 200 and v["verdict"] == "AGREED TERMS" and v["exit"] == 0, v
    # B can verify too, from its side, with a copy of A's ledger
    shutil.copyfile(a.ledger, b.root / "from_agent_a.jsonl")
    st, v2 = b.post("verify", {"a": str(b.root / "from_agent_a.jsonl"), "b": str(b.ledger)})
    assert st == 200 and v2["verdict"] == "AGREED TERMS" and v2["exit"] == 0
    # the CLI reads the originals and gives the same word
    assert H.api_verify({"a": str(a.ledger), "b": str(b.ledger)})["verdict"] == v["verdict"]


def test_one_side_edits_terms_after_accept_is_different_terms(agents):
    a, b = agents
    _handshake(a, b)
    rows = C.rows(a.ledger)
    rows[0]["shared"]["terms"]["fee"] = "120.00"        # A edits its own ledger afterwards
    a.ledger.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    st, v = _verify_on_a(a, b)
    assert st == 200 and v["verdict"] == "DIFFERENT TERMS" and v["exit"] == 1, v
    assert v["results"][0]["fields"] == ["terms.fee"]


def test_proposing_again_after_accept_is_different_terms(agents):
    a, b = agents
    _handshake(a, b)
    st, p = a.post("propose", {"ledger": str(a.ledger), "terms": dict(TERMS, revisions=0),
                               "agent": a.name, "to": b.name, "handshake": "h-kh7"})
    assert p["exit"] == 0
    st, v = _verify_on_a(a, b)
    assert v["verdict"] == "DIFFERENT TERMS" and v["results"][0]["fields"] == ["terms.revisions"]


def test_one_side_never_accepts_is_missing(agents):
    a, b = agents
    _handshake(a, b, "h-done")
    st, p = a.post("propose", {"ledger": str(a.ledger), "terms": TERMS, "agent": a.name,
                               "to": b.name, "handshake": "h-ignored"})
    assert p["exit"] == 0                               # B never calls accept
    st, v = _verify_on_a(a, b, "h-ignored")
    assert st == 200 and v["verdict"] == "MISSING" and v["exit"] == 1, v
    st, whole = _verify_on_a(a, b)
    assert whole["verdict"] == "MISSING" and whole["counts"]["AGREED TERMS"] == 1


def test_unreadable_ledger_is_could_not_look_exit_3(agents):
    a, b = agents
    _handshake(a, b)
    bad = a.root / "from_agent_b.jsonl"
    bad.write_bytes(b"\x00\x01 not a ledger {\n")
    st, v = a.post("verify", {"a": str(a.ledger), "b": str(bad)})
    assert st == 200 and v["verdict"] == "COULD NOT LOOK" and v["exit"] == 3, v
    assert v["reason_word"] == "unreadable" and v["looked_for"] and v["where"]
    st, v = a.post("verify", {"a": str(a.ledger), "b": str(a.root / "never_sent.jsonl")})
    assert st == 200 and v["verdict"] == "COULD NOT LOOK" and v["exit"] == 3
    assert v["reason_word"] == "missing"


def test_an_offer_changed_in_transit_is_refused_and_nothing_is_written(agents):
    a, b = agents
    st, p = a.post("propose", {"ledger": str(a.ledger), "terms": TERMS, "agent": a.name,
                               "to": b.name, "handshake": "h-mitm"})
    forged = dict(p["proposal"], terms=dict(TERMS, fee="1.20"))
    st, acc = b.post("accept", {"ledger": str(b.ledger), "proposal": forged, "agent": b.name})
    # a refused offer is bad usage: exit 2 in the body; the server answers it
    # as 400 (lane A's rule, bad usage is the request, not a verdict)
    assert st in (200, 400) and acc["exit"] == 2 and "terms_digest" in acc["error"]
    assert not b.ledger.exists()


def test_bad_bodies_are_400_or_usage_never_a_verdict(agents):
    a, _ = agents
    st, body = a.post("propose", {"ledger": str(a.ledger)})       # schema: terms required
    assert st == 400 and body["exit"] == 2
    st, body = a.post("verify", {"a": str(a.ledger)})
    assert st == 400 and body["exit"] == 2
