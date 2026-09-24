"""Tests for arcaeon_receipt.call_proxy: a tiny local upstream and the proxy
both run on ephemeral ports in threads -- no network, no real x402 client.
Covers byte-for-byte passthrough, the two added receipt headers, fetching a
receipt back and verifying it, x402 payment-header passthrough, the 502
upstream-failure receipt path, and that no request/response body text ever
lands in the ledger file or the receipts directory."""
import http.client
import http.server
import json
import socket
import threading
import time
from pathlib import Path

import pytest

from arcaeon.record.receipt import call_proxy, verify_receipt


class _CapturingHandler(http.server.BaseHTTPRequestHandler):
    """Tiny local upstream: GET /boom -> 500, GET /slow -> sleeps 0 then 200,
    any other GET -> fixed JSON, POST anywhere -> echoes the body back
    byte-for-byte. Records every request's headers so tests can assert on
    what actually crossed the proxy."""

    received_headers = []
    _lock = threading.Lock()

    def log_message(self, fmt, *args):
        pass

    def _record(self):
        with self._lock:
            type(self).received_headers.append(dict(self.headers.items()))

    def do_GET(self):
        self._record()
        if self.path == "/boom":
            body = b'{"error":"boom"}'
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/slow":
            time.sleep(0)
        if self.path == "/empty":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b'{"echo":"get"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self._record()
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        self.send_response(200)
        self.send_header("Content-Type", self.headers.get("Content-Type", "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _unused_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _get_ci(headers: dict, name: str):
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


@pytest.fixture
def upstream():
    _CapturingHandler.received_headers = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CapturingHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def proxy(tmp_path, upstream):
    port = upstream.server_address[1]
    ledger_path = tmp_path / "calls.log.jsonl"
    receipts_dir = tmp_path / "receipts"
    server = call_proxy.build_server(
        listen="127.0.0.1:0",
        upstream=f"http://127.0.0.1:{port}",
        seller="acme",
        ledger_path=ledger_path,
        receipts_dir=receipts_dir,
        witness=False,
    )
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield server, ledger_path, receipts_dir
    finally:
        server.shutdown()
        server.server_close()


def _fetch_receipt(port: int, url: str) -> dict:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", url)
    r = conn.getresponse()
    data = json.loads(r.read())
    conn.close()
    return data


def test_byte_for_byte_passthrough(proxy):
    server, _, _ = proxy
    port = server.server_address[1]
    payload = bytes(range(256)) * 4  # every byte value, including nulls and 0xff
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/echo", body=payload, headers={"Content-Type": "application/octet-stream"})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    assert resp.status == 200
    assert data == payload


def test_receipt_headers_added(proxy):
    server, _, _ = proxy
    port = server.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/echo", body=b"hi", headers={"Content-Type": "text/plain"})
    resp = conn.getresponse()
    resp.read()
    conn.close()
    digest = resp.getheader("X-Arcaeon-Receipt")
    url = resp.getheader("X-Arcaeon-Receipt-URL")
    assert digest and digest.startswith("sha256:")
    assert url == f"/_arcaeon/receipt/{digest}"


def test_receipt_fetchable_and_verifies(proxy):
    server, ledger_path, _ = proxy
    port = server.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/echo", body=b"hello world", headers={"Content-Type": "text/plain"})
    resp = conn.getresponse()
    resp.read()
    digest = resp.getheader("X-Arcaeon-Receipt")
    url = resp.getheader("X-Arcaeon-Receipt-URL")
    conn.close()

    receipt = _fetch_receipt(port, url)
    assert receipt["body_digest"] == digest
    assert receipt["kind"] == "receipted-call"
    res = verify_receipt(receipt, ledger_path=ledger_path)
    assert res["ok"], res


def test_malformed_payment_header_is_digested_not_refused(proxy):
    # A-006, resolved as a finding rather than the refusal the batch item
    # assumed: call.py's own SCOPE says on its face "the payment header is
    # digested, not verified. Payment verification belongs to the
    # facilitator" (arcaeon_receipt/call.py), and _payment_header() extracts
    # whatever bytes sit under a known header name with no structural check
    # at all. There is no "required field" concept for an x402 header
    # anywhere in this codebase to be malformed against, and adding one
    # would mean this proxy silently taking on a payment-verification job
    # its own scope explicitly disclaims -- not a small, obvious bug fix,
    # so it is not done here. This test documents the actual, intentional
    # contract instead: a header that is structurally garbage still gets
    # digested and receipted like any other, never refused and never
    # dropped into a partial receipt.
    #
    # One small, genuinely obvious bug found and fixed on contact while
    # writing this test: call.py's call_receipt() computed
    # `_digest_any(pay) if pay else None`, which treats an empty-but-PRESENT
    # payment header the same as no header at all (empty string is falsy in
    # Python) -- collapsing two different facts (no header sent / an empty
    # header sent) into the same None. Fixed to `if pay is not None else None`
    # so an empty header still gets a real digest of empty bytes, distinct
    # from "absent". (Residual, NOT fixed: `_payment_header()` returns on the
    # FIRST recognized header name it meets in header order, even if that
    # header's value is empty -- a client sending both a stale empty
    # X-PAYMENT and a real PAYMENT-SIGNATURE would have the real one
    # silently ignored. Which header should win when more than one is
    # present is a product decision, not a bug fix, and is left as a
    # finding.)
    server, _, _ = proxy
    port = server.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/ping", headers={"X-PAYMENT": "{not even json, no scheme, no network"})
    resp = conn.getresponse()
    resp.read()
    digest = resp.getheader("X-Arcaeon-Receipt")
    conn.close()

    assert resp.status == 200  # not refused
    assert digest  # a full receipt was still issued, not a partial one

    receipt = _fetch_receipt(port, f"/_arcaeon/receipt/{digest}")
    check = receipt["checks"][0]
    # garbage in, digested exactly like a well-formed header would be --
    # proving the proxy never inspects the header's structure, only its
    # presence.
    assert check["payment_header_digest"] is not None
    assert "upstream_error" not in check

    # the empty-vs-absent fix, isolated: an empty (but present) header now
    # digests to something real, distinct from no header at all.
    from arcaeon.record.receipt import call as call_module
    absent = call_module._payment_header({"Content-Type": "text/plain"})
    present_empty = call_module._payment_header({"X-PAYMENT": ""})
    assert absent is None
    assert present_empty == ""
    assert call_module._digest_any(present_empty) != call_module._digest_any(None)


def test_x402_payment_header_forwarded_unchanged(proxy):
    server, _, _ = proxy
    port = server.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/ping", headers={"X-PAYMENT": "sig-abc-123",
                                          "PAYMENT-SIGNATURE": "another-sig"})
    resp = conn.getresponse()
    resp.read()
    conn.close()

    assert _CapturingHandler.received_headers, "upstream never received a request"
    seen = _CapturingHandler.received_headers[-1]
    assert _get_ci(seen, "X-PAYMENT") == "sig-abc-123"
    assert _get_ci(seen, "PAYMENT-SIGNATURE") == "another-sig"


def test_receipt_survives_added_and_reordered_headers(proxy):
    """A-024: the receipt this proxy issues must not be perturbed by a header
    reorder or an added, irrelevant header on the client's request -- the
    receipt's fields (body_digest, payment_header_digest) are computed from
    the request BODY and the one recognized payment header's VALUE only
    (call.py's `_payment_header`/`_digest_any`), never from header order or
    header count. Two requests carrying the identical body and the identical
    X-PAYMENT value, but with a different number of surrounding headers in a
    different order, must produce the same payment_header_digest and the
    same request_digest."""
    server, _, _ = proxy
    port = server.server_address[1]

    def _post(headers):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", "/echo", body=b"same body", headers=headers)
        resp = conn.getresponse()
        resp.read()
        digest = resp.getheader("X-Arcaeon-Receipt")
        conn.close()
        return _fetch_receipt(port, f"/_arcaeon/receipt/{digest}")

    # Same payment value, same body -- one request with a minimal header
    # set, the other with extra headers ahead of it and the dict built in a
    # different insertion order (a proxy hop can add/reorder headers freely;
    # HOP_BY_HOP-filtered headers like Connection are excluded either way).
    receipt_minimal = _post({
        "Content-Type": "text/plain",
        "X-PAYMENT": "sig-order-test-1",
    })
    receipt_reordered = _post({
        "X-Custom-Trace-Id": "abc123",
        "X-PAYMENT": "sig-order-test-1",
        "Content-Type": "text/plain",
        "X-Another-Added-Header": "added-by-a-hop",
    })

    check_a = receipt_minimal["checks"][0]
    check_b = receipt_reordered["checks"][0]
    assert check_a["payment_header_digest"] == check_b["payment_header_digest"]
    assert check_a["request_digest"] == check_b["request_digest"]
    assert check_a["payment_header_digest"] is not None


def test_zero_byte_response_is_receipted_honestly(proxy):
    """A-035: an upstream that answers with a real 200 and zero response
    bytes (an empty delivery, distinct from a transport failure) must
    produce a normal, honest receipt -- a real digest of empty bytes, not a
    null/None response_digest and not a crash."""
    server, _, _ = proxy
    port = server.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/empty")
    resp = conn.getresponse()
    body = resp.read()
    digest = resp.getheader("X-Arcaeon-Receipt")
    conn.close()

    assert resp.status == 200
    assert body == b""
    assert digest

    receipt = _fetch_receipt(port, f"/_arcaeon/receipt/{digest}")
    check = receipt["checks"][0]
    assert check["response_status"] == 200
    # a real digest of zero bytes, not None/empty-string/absent -- an empty
    # delivery is a fact worth receipting, not something to leave blank.
    assert check["response_digest"]
    assert "upstream_error" not in check


def test_upstream_status_passthrough_and_receipted(proxy):
    server, _, _ = proxy
    port = server.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/boom")
    resp = conn.getresponse()
    body = resp.read()
    digest = resp.getheader("X-Arcaeon-Receipt")
    conn.close()
    assert resp.status == 500
    assert body == b'{"error":"boom"}'

    receipt = _fetch_receipt(port, f"/_arcaeon/receipt/{digest}")
    assert receipt["checks"][0]["response_status"] == 500


def test_slow_route_completes_and_receipts_elapsed(proxy):
    server, _, _ = proxy
    port = server.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/slow")
    resp = conn.getresponse()
    resp.read()
    digest = resp.getheader("X-Arcaeon-Receipt")
    conn.close()
    assert resp.status == 200

    receipt = _fetch_receipt(port, f"/_arcaeon/receipt/{digest}")
    assert receipt["checks"][0]["elapsed_ms"] >= 0


def test_upstream_connection_failure_is_receipted_502(tmp_path):
    dead_port = _unused_port()  # bound then closed: guaranteed nothing is listening
    ledger_path = tmp_path / "calls_502.log.jsonl"
    server = call_proxy.build_server(
        listen="127.0.0.1:0",
        upstream=f"http://127.0.0.1:{dead_port}",
        seller="acme",
        ledger_path=ledger_path,
        witness=False,
        upstream_timeout=2.0,
    )
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        port = server.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/anything")
        resp = conn.getresponse()
        resp.read()
        digest = resp.getheader("X-Arcaeon-Receipt")
        conn.close()
        assert resp.status == 502
        assert digest

        rows = [json.loads(l) for l in Path(ledger_path).read_text(encoding="utf-8").splitlines()]
        assert rows and rows[-1]["body_digest"] == digest

        receipt = _fetch_receipt(port, f"/_arcaeon/receipt/{digest}")
        check = receipt["checks"][0]
        assert check["response_status"] == 502
        assert "upstream_error" in check and check["upstream_error"]
    finally:
        server.shutdown()
        server.server_close()


def test_health_endpoint_reports_ledger_state(proxy):
    server, _, _ = proxy
    port = server.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/echo-warmup")
    conn.getresponse().read()
    conn.close()

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/_arcaeon/health")
    r = conn.getresponse()
    payload = json.loads(r.read())
    conn.close()
    assert r.status == 200
    assert payload["ok"] is True
    assert payload["rows"] >= 1
    assert "chain" in payload


def test_health_endpoint_goes_non_200_when_the_ledger_is_unreadable(proxy):
    """The planted-DEAD arm. A probe that reads only the status code must not
    see a healthy proxy when the ledger cannot be read: an error body under a
    200 is a green light with a note attached that nothing reads."""
    server, ledger_path, _ = proxy
    port = server.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/echo-warmup")
    conn.getresponse().read()
    conn.close()

    with open(ledger_path, "w", encoding="utf-8") as fh:
        fh.write("{this is not a ledger row\n")

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/_arcaeon/health")
    r = conn.getresponse()
    payload = json.loads(r.read())
    conn.close()
    assert payload["ok"] is False, "fixture did not break the ledger; the test proves nothing"
    assert r.status == 503
    assert payload["error"]


def test_no_body_text_leaks_into_ledger_or_receipts_dir(proxy):
    server, ledger_path, receipts_dir = proxy
    port = server.server_address[1]
    secret_req = "super-secret-request-body-xyz789"
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/echo", body=secret_req.encode(), headers={"Content-Type": "text/plain"})
    resp = conn.getresponse()
    echoed = resp.read()
    conn.close()
    assert echoed.decode() == secret_req  # proxy really did carry it -- just never logged it

    ledger_text = Path(ledger_path).read_text(encoding="utf-8")
    assert secret_req not in ledger_text

    if receipts_dir.exists():
        for f in receipts_dir.glob("*.json"):
            assert secret_req not in f.read_text(encoding="utf-8")

    witness_path = Path(str(ledger_path) + ".witness.jsonl")
    if witness_path.exists():
        assert secret_req not in witness_path.read_text(encoding="utf-8")
