# SPDX-License-Identifier: MIT
"""Failure-first tests for pinning a tape's head at the witness (completeness slice 2).

A tape is pinned like any ledger: the witness's existing body
`{namespace, rows, chain}`, through `publish_head`, which already refuses an
empty or unverified log. `HostedWitness` is the HTTP client half of the hosted
witness (`POST /api/pin`). The optional `pair` and `record_format` fields the
design proposed are SENT, because the hosted witness does not reject unknown
fields (arcaeon-witness api/pin.js validates only namespace/rows/chain), and
then CHECKED against the pin the witness echoes: today's witness builds the
pin from named fields only, so they come back `dropped_by_witness`, never
claimed as recorded. A witness that rejects them gets one retry without them.

Every test runs against a MOCK witness on 127.0.0.1 that mimics pin.js. The
live witness is never contacted: nothing here has a default URL.

Break arms swap in a lying pinner and a lying client and prove the checks
catch them.
"""
from __future__ import annotations

import http.server
import json
import threading
from pathlib import Path

import pytest

import arcaeon.prove.reconcile as R
from arcaeon.record.ledger import Ledger, digest_json
from arcaeon.record.ledger import tape_pin as TP
from arcaeon.record.ledger.witness import HostedWitness, HostedWitnessError, WitnessStore


# -- a mock witness with pin.js's rules ----------------------------------------

class MockWitness:
    """mode 'drop'   : today's pin.js (unknown fields accepted, not stored)
       mode 'keep'   : a future witness that stores pair / record_format
       mode 'strict' : a witness that 400s on any unknown field"""

    NAMED = {"namespace", "rows", "chain", "intent"}

    def __init__(self, mode="drop", key="k-demo"):
        self.mode, self.key = mode, key
        self.requests: list[dict] = []
        self.latest: dict[str, dict] = {}
        mock = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                mock.requests.append(body)
                code, out = mock.handle(self.path, self.headers.get("Authorization", ""), body)
                raw = json.dumps(out).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def handle(self, path, auth, body):
        import re
        if path != "/api/pin":
            return 404, {"error": "not found"}
        if auth != f"Bearer {self.key}":
            return 401, {"error": "invalid or missing bearer key"}
        if not isinstance(body.get("namespace"), str) or not re.fullmatch(r"[a-z0-9-]{1,64}", body["namespace"]):
            return 400, {"error": "namespace must match [a-z0-9-]{1,64}"}
        if not isinstance(body.get("rows"), int) or body["rows"] < 1:
            return 400, {"error": "rows must be a positive integer"}
        if not isinstance(body.get("chain"), str) or not re.fullmatch(r"[0-9a-fA-F]{8,64}", body["chain"]):
            return 400, {"error": "chain must be a hex string of 8-64 chars"}
        if self.mode == "strict" and set(body) - self.NAMED:
            return 400, {"error": f"unknown field {sorted(set(body) - self.NAMED)[0]}"}
        ns, rows, chain = body["namespace"], body["rows"], body["chain"].lower()
        cur = self.latest.get(ns)
        if cur and rows < cur["rows"]:
            return 409, {"error": "monotonic violation: a witness never goes backward",
                         "latest_rows": cur["rows"], "submitted_rows": rows}
        if cur and rows == cur["rows"] and chain == cur["chain"]:
            return 200, {"ok": True, "note": "already witnessed (idempotent re-pin)", "pin": cur}
        pin = {"namespace": ns, "rows": rows, "chain": chain,
               "pinned_at": "2026-09-22T12:00:00.000Z", "seq": (cur or {}).get("seq", 0) + 1,
               "cadence_hours": 24, "next_pin_due_by": "2026-09-23T12:00:00.000Z",
               "record_kind": "content_head_advance"}
        if self.mode == "keep":
            for k in ("pair", "record_format"):
                if k in body:
                    pin[k] = body[k]
        self.latest[ns] = pin
        return 201, {"ok": True, "record_kind": "content_head_advance", "pin": pin}

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def witness():
    made = []

    def make(mode="drop"):
        w = MockWitness(mode)
        made.append(w)
        return w
    yield make
    for w in made:
        w.close()


# -- tapes -------------------------------------------------------------------

def _row(side, idx, ns):
    return {"evt": "tape_call", "tape": R.TAPE_FORMAT, "side": side, "ns": ns, "idx": idx,
            "tool": "echo", "req": digest_json({"name": "echo", "arguments": {"n": idx}}),
            "resp": digest_json({"result": {"n": idx}}), "status": "ok"}


def tape(tmp, side="tool", n=4, ns="demo-tool", name=None):
    p = Path(tmp) / (name or f"{side}.tape.jsonl")
    p.touch()
    lg = Ledger(p)
    for k in range(1, n + 1):
        lg.append(_row(side, k, ns))
    return p


def client(w):
    return HostedWitness(w.url, w.key)


# -- the checks the break arms replay -----------------------------------------

def check_pin_is_the_counter(tmp_path, w):
    t = tape(tmp_path)
    pin = TP.pin_tape(t, client(w), pair="demo-agent")
    assert (pin["namespace"], pin["rows"], pin["side"]) == ("demo-tool", 4, "tool")
    assert pin["chain"] == Ledger(t).head().chain
    sent = w.requests[-1]
    assert (sent["namespace"], sent["rows"], sent["chain"]) == ("demo-tool", 4, pin["chain"])
    # and the pin is a working counter: the tape agrees now, and a cut is caught
    r = R.reconcile(t, tape(tmp_path, "agent", ns="demo-agent"), pins=[pin])
    assert r.verdict == R.MATCHED and r.pins_checked[0]["result"] == "agrees", r.summary
    lines = t.read_text(encoding="utf-8").splitlines(True)
    t.write_text("".join(lines[:3]), encoding="utf-8")
    r = R.reconcile(t, tape(tmp_path, "agent", n=3, ns="demo-agent", name="agent3.tape.jsonl"),
                    pins=[pin])
    assert (r.verdict, r.at) == (R.MISSING, 4), r.summary
    return pin


def check_dropped_extras_are_not_claimed(tmp_path, w):
    pin = TP.pin_tape(tape(tmp_path), client(w), pair="demo-agent")
    assert w.requests[-1]["pair"] == "demo-agent"
    assert w.requests[-1]["record_format"] == "arcaeon-tape/1"
    assert pin["extra_fields"] == "dropped_by_witness", pin
    return pin


# -- failure-first --------------------------------------------------------------

def test_a_tape_pins_rows_as_calls_and_chain_as_the_head(tmp_path, witness):
    check_pin_is_the_counter(tmp_path, witness())


def test_todays_witness_accepts_but_drops_the_extra_fields_and_we_say_so(tmp_path, witness):
    check_dropped_extras_are_not_claimed(tmp_path, witness("drop"))


def test_a_witness_that_stores_the_extra_fields_is_reported_recorded(tmp_path, witness):
    w = witness("keep")
    pin = TP.pin_tape(tape(tmp_path), client(w), pair="demo-agent")
    assert pin["extra_fields"] == "recorded"
    assert w.latest["demo-tool"]["pair"] == "demo-agent"


def test_a_witness_that_rejects_unknown_fields_gets_one_retry_without_them(tmp_path, witness):
    w = witness("strict")
    pin = TP.pin_tape(tape(tmp_path), client(w), pair="demo-agent")
    assert pin["extra_fields"] == "refused_by_witness"
    assert len(w.requests) == 2 and "pair" not in w.requests[1]
    assert pin["rows"] == 4


def test_no_pair_sends_record_format_only(tmp_path, witness):
    w = witness("keep")
    TP.pin_tape(tape(tmp_path), client(w))
    assert "pair" not in w.requests[-1] and w.requests[-1]["record_format"] == "arcaeon-tape/1"


def test_a_tape_that_does_not_verify_is_refused_and_nothing_is_sent(tmp_path, witness):
    w = witness()
    t = tape(tmp_path)
    lines = t.read_text(encoding="utf-8").splitlines(True)
    lines[1] = lines[1].replace('"idx": 2', '"idx": 9')
    t.write_text("".join(lines), encoding="utf-8")
    with pytest.raises(ValueError):
        TP.pin_tape(t, client(w))
    assert w.requests == []


def test_an_empty_tape_is_refused_and_nothing_is_sent(tmp_path, witness):
    w = witness()
    t = tmp_path / "empty.tape.jsonl"
    t.touch()
    with pytest.raises(ValueError):
        TP.pin_tape(t, client(w), namespace="demo-tool")
    assert w.requests == []


def test_a_seam_log_is_not_a_tape_and_is_refused(tmp_path, witness):
    w = witness()
    p = tmp_path / "seam.jsonl"
    Ledger(p).append({"evt": "session_begin"})
    with pytest.raises(ValueError, match="not an arcaeon-tape/1"):
        TP.pin_tape(p, client(w), namespace="demo-tool")
    assert w.requests == []


def test_no_namespace_anywhere_is_refused(tmp_path, witness):
    w = witness()
    with pytest.raises(ValueError, match="namespace"):
        TP.pin_tape(tape(tmp_path, ns=None), client(w))
    assert w.requests == []


def test_a_namespace_that_contradicts_the_rows_is_refused(tmp_path, witness):
    w = witness()
    with pytest.raises(ValueError, match="namespace"):
        TP.pin_tape(tape(tmp_path), client(w), namespace="someone-else")
    assert w.requests == []


def test_a_malformed_pair_is_refused_locally(tmp_path, witness):
    w = witness()
    with pytest.raises(ValueError, match="pair"):
        TP.pin_tape(tape(tmp_path), client(w), pair="Not A Namespace")
    assert w.requests == []


def test_a_backward_pin_is_a_named_error_not_a_green(tmp_path, witness):
    w = witness()
    t = tape(tmp_path, n=4)
    TP.pin_tape(t, client(w))
    t2 = tape(tmp_path, n=2, name="short.tape.jsonl")
    with pytest.raises(HostedWitnessError) as e:
        TP.pin_tape(t2, client(w))
    assert e.value.status == 409


def test_an_idempotent_repin_is_reported_as_such(tmp_path, witness):
    w = witness()
    t = tape(tmp_path)
    TP.pin_tape(t, client(w))
    again = TP.pin_tape(t, client(w))
    assert again["witness_status"] == 200 and again["idempotent"] is True


def test_a_wrong_key_is_a_named_error(tmp_path, witness):
    w = witness()
    with pytest.raises(HostedWitnessError) as e:
        TP.pin_tape(tape(tmp_path), HostedWitness(w.url, "wrong"))
    assert e.value.status == 401


def test_an_unreachable_witness_is_a_named_error(tmp_path):
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(HostedWitnessError):
        TP.pin_tape(tape(tmp_path), HostedWitness(f"http://127.0.0.1:{port}", "k", timeout=2))


def test_a_witness_that_records_a_different_head_is_not_accepted(tmp_path, witness):
    w = witness()
    real = w.handle

    def liar(path, auth, body):
        code, out = real(path, auth, body)
        out["pin"] = dict(out["pin"], rows=out["pin"]["rows"] - 1)
        return code, out
    w.handle = liar
    with pytest.raises(HostedWitnessError, match="different head"):
        TP.pin_tape(tape(tmp_path), client(w))


def test_the_local_reference_store_still_pins_a_tape_without_extras(tmp_path):
    store = WitnessStore(tmp_path / "w.jsonl")
    pin = TP.pin_tape(tape(tmp_path), store, pair="demo-agent")
    assert pin["rows"] == 4 and pin["extra_fields"] == "not_sent"
    assert store.latest("demo-tool")["rows"] == 4


def test_the_key_is_never_in_the_result(tmp_path, witness):
    w = witness()
    pin = TP.pin_tape(tape(tmp_path), client(w))
    assert w.key not in json.dumps(pin)


def test_the_result_is_a_pin_file_reconcile_reads(tmp_path, witness):
    w = witness()
    pin = TP.pin_tape(tape(tmp_path), client(w))
    p = tmp_path / "pin.json"
    p.write_text(json.dumps(pin), encoding="utf-8")
    assert R.load_pins(p)[0]["rows"] == 4


# -- break arms ------------------------------------------------------------------

def test_breakarm_a_pinner_that_pins_one_row_short_is_caught(tmp_path, witness, monkeypatch):
    real = TP.pin_tape

    def short(path, store, **kw):
        pin = real(path, store, **kw)
        return dict(pin, rows=pin["rows"] - 1)
    monkeypatch.setattr(TP, "pin_tape", short)
    with pytest.raises(AssertionError):
        check_pin_is_the_counter(tmp_path, witness())


def test_breakarm_a_client_that_claims_extras_recorded_is_caught(tmp_path, witness, monkeypatch):
    real = HostedWitness.record

    def boastful(self, *a, **kw):
        out = real(self, *a, **kw)
        return dict(out, extra_fields="recorded")
    monkeypatch.setattr(HostedWitness, "record", boastful)
    with pytest.raises(AssertionError):
        check_dropped_extras_are_not_claimed(tmp_path, witness("drop"))
