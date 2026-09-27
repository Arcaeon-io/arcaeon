"""K036R: a reader talks to the endpoint it was given and nothing else.

A 3xx is never followed (it would carry the key to the Location host and the
answer would be filed under the first host), and no proxy is used. Loopback
servers only.
"""
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from arcaeon import verdict as V
from arcaeon.prove.readers import ReaderCallError
from arcaeon.prove.readers.anthropic import AnthropicReader
from arcaeon.prove.readers.gemini import GeminiReader
from arcaeon.prove.readers.openai_compat import OpenAICompatReader
from readings.stub_llm import StubLLM

SENTENCE = "Does the claim state the dispatch time?"
SECRET = "sk-test-REDIRECT-DO-NOT-LEAK-0123456789"
ENV = "ARCAEON_TEST_REDIRECT_KEY"


class _Recorder:
    """A loopback server that records every request and answers `status`
    (with `location` for a 3xx) or a yes in every model shape."""

    def __init__(self, status=200, location=None):
        self.status, self.location, self.requests = status, location, []

    def __enter__(self):
        rec = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _any(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                rec.requests.append({"method": self.command, "path": self.path,
                                     "headers": {k.lower(): v for k, v in self.headers.items()},
                                     "raw": raw})
                if 300 <= rec.status < 400:
                    self.send_response(rec.status)
                    self.send_header("Location", rec.location)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                out = json.dumps({"choices": [{"message": {"content": "yes"}}],
                                  "content": [{"type": "text", "text": "yes"}],
                                  "candidates": [{"content": {"parts": [{"text": "yes"}]}}]}
                                 ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            do_POST = do_GET = _any

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)
        return False


def _dead_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


READERS = {
    "openai_compat": lambda base: OpenAICompatReader(base_url=base + "/v1", model="m",
                                                     key_env=ENV),
    "anthropic": lambda base: AnthropicReader(base_url=base, model="m", key_env=ENV),
    "gemini": lambda base: GeminiReader(base_url=base, model="m", key_env=ENV),
}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv(ENV, SECRET)
    for var in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(var, raising=False)


@pytest.mark.parametrize("kind", sorted(READERS))
@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_a_redirect_is_refused_and_the_other_host_never_hears_from_us(kind, code):
    with _Recorder() as other:
        with _Recorder(status=code, location=other.url + "/steal") as first:
            with pytest.raises(ReaderCallError) as e:
                READERS[kind](first.url).read(claim_id="c1", claim_text="x",
                                              criterion_text=SENTENCE)
        assert e.value.reason_word == "redirect_refused"
        assert e.value.reason_word in V.REASON_WORDS
        other_port = other.url.rsplit(":", 1)[1]
        assert f"127.0.0.1:{other_port}" in str(e.value)       # the Location host is named
        assert SECRET not in str(e.value)
        assert len(first.requests) == 1
        assert other.requests == []                             # never followed
    joined = json.dumps([r["headers"] for r in other.requests])
    assert SECRET not in joined


def test_a_redirect_to_another_host_name_is_named_not_followed():
    with _Recorder(status=302, location="http://attacker.invalid/x") as first:
        with pytest.raises(ReaderCallError) as e:
            READERS["openai_compat"](first.url).read(claim_id="c1", claim_text="x",
                                                     criterion_text=SENTENCE)
    assert e.value.reason_word == "redirect_refused"
    assert "attacker.invalid" in str(e.value) and len(first.requests) == 1


@pytest.mark.parametrize("kind", sorted(READERS))
def test_a_dead_http_proxy_is_ignored_and_the_stub_is_reached_directly(kind, monkeypatch):
    dead = f"http://127.0.0.1:{_dead_port()}"
    for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
        monkeypatch.setenv(var, dead)
    with StubLLM(answers=["yes"]) as stub:
        base = stub.url
        row = READERS[kind](base).read(claim_id="c1", claim_text="x", criterion_text=SENTENCE)
    assert row["reading"] == "yes" and len(stub.requests) == 1


def test_a_live_proxy_never_receives_the_request_or_the_key(monkeypatch):
    with _Recorder() as proxy:
        for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
            monkeypatch.setenv(var, proxy.url)
        with StubLLM(answers=["no"]) as stub:
            row = READERS["openai_compat"](stub.url).read(claim_id="c1", claim_text="x",
                                                          criterion_text=SENTENCE)
    assert row["reading"] == "no" and len(stub.requests) == 1
    assert proxy.requests == []


def test_the_opener_carries_an_empty_proxy_table_and_no_following_redirect_handler(monkeypatch):
    # urllib already skips a proxy for 127.0.0.1 on some platforms, so the two
    # loopback tests above cannot fail on their own; this pins the opener itself.
    import urllib.request

    from arcaeon.prove import readers
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    op = readers._opener()
    proxies = [h for h in op.handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert all(h.proxies == {} for h in proxies)   # ProxyHandler({}) registers no proxy_open
    assert not any(hasattr(h, "http_open") and hasattr(h, "proxies") for h in op.handlers)
    redirs = [h for h in op.handlers if isinstance(h, urllib.request.HTTPRedirectHandler)]
    assert len(redirs) == 1 and type(redirs[0]) is not urllib.request.HTTPRedirectHandler
    assert redirs[0].redirect_request(None, None, 302, "Found", {}, "http://x.invalid/") is None
