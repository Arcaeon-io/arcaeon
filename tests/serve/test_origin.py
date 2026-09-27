"""The browser-origin guard (K108): a POST the dashboard accepts on its
session cookie must carry Origin equal to the served origin; a cross-origin
POST is 403 and its form is never read. Bearer-token calls (agents) are not
affected. Headless over a loopback server the test starts and stops."""
from __future__ import annotations

import pytest

from arcaeon import journal
from arcaeon.serve import auth
from arcaeon.serve import h_core
from serve import _pages as P

PAGES_THAT_POST = ("/verify", "/packs", "/readings", "/mandate")


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("ARCAEON_JOURNAL", raising=False)
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    r = tmp_path / "root"
    r.mkdir()
    for i in range(2):
        assert h_core.log({"ledger": str(r / "l.jsonl"),
                           "fields": {"t": f"2026-09-27T10:0{i}:00Z", "n": i}})["exit"] == 0
    return r


@pytest.fixture()
def session(root):
    with P.running(root) as srv:
        yield srv, P.sign_in(srv)


def _verified(r) -> bool:
    return "VERIFIED" in [n.text() for n in P.by_class(P.parse(r.text), "verdict-word")]


def test_same_origin_post_works_on_both_served_names(session):
    srv, ck = session
    port = srv.server_address[1]
    for origin in (srv.url, f"http://localhost:{port}", f"http://LOCALHOST:{port}/"):
        r = P.post_form(srv, "/verify", {"ledger": "l.jsonl"}, cookie=ck, origin=origin)
        assert r.status == 200 and _verified(r), origin


@pytest.mark.parametrize("origin", [
    "http://evil.example",
    "https://127.0.0.1",
    "null",
    "",
    "http://127.0.0.1",                       # right host, no port
    "https://127.0.0.1:{port}",               # right host and port, other scheme
    "http://127.0.0.1:{other}",               # another local server
    "http://127.0.0.1.evil.example:{port}",
    None,                                     # no Origin at all
])
def test_cross_origin_cookie_post_is_403_and_unread(session, origin):
    srv, ck = session
    port = srv.server_address[1]
    o = origin if origin is None else origin.format(port=port, other=port + 1)
    before = len(journal.read())
    r = P.post_form(srv, "/verify", {"ledger": "l.jsonl"}, cookie=ck, origin=o)
    assert r.status == 403
    assert "did not come from this dashboard" in r.text
    assert not _verified(r) and "state-ok" not in r.text
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert len(journal.read()) == before          # the check never ran


def test_every_posting_page_is_guarded(session):
    srv, ck = session
    for path in PAGES_THAT_POST:
        r = P.post_form(srv, path, {"x": "y"}, cookie=ck, origin="http://evil.example")
        assert r.status == 403, path


def test_a_refused_big_form_still_gets_its_403(session):
    """The refusal drains the declared body before it answers, so a client
    still sending gets the 403 page, not a reset (WinError 10053)."""
    srv, ck = session
    for path in PAGES_THAT_POST:
        r = P.post_form(srv, path, {"x": "y" * (1 << 20)}, cookie=ck,
                        origin="http://evil.example")
        assert r.status == 403 and "did not come from this dashboard" in r.text, path


def test_bearer_token_calls_are_unaffected(session):
    srv, _ck = session
    bearer = {"Authorization": f"Bearer {P.TOKEN}"}
    for origin in (None, "http://evil.example"):
        r = P.post_form(srv, "/verify", {"ledger": "l.jsonl"}, origin=origin, headers=bearer)
        assert r.status == 200 and _verified(r)
    r = P.request(srv, "/v1/verify", method="POST", data=b'{"ledger": "l.jsonl"}',
                  headers={**bearer, "Content-Type": "application/json",
                           "Origin": "http://evil.example"})
    assert r.status == 200 and '"VERIFIED"' in r.text


def test_a_wrong_token_is_still_401_not_let_through(session):
    srv, ck = session
    r = P.post_form(srv, "/verify", {"ledger": "l.jsonl"}, cookie=ck, origin=None,
                    headers={"Authorization": "Bearer wrong"})
    assert r.status == 401


def test_no_session_is_401_before_the_origin_is_looked_at(session):
    srv, _ck = session
    r = P.post_form(srv, "/verify", {"ledger": "l.jsonl"}, origin="http://evil.example")
    assert r.status == 401


def test_get_pages_need_no_origin(session):
    srv, ck = session
    assert P.get(srv, "/verify", cookie=ck).status == 200


def test_pages_ask_browsers_to_send_their_origin(session):
    srv, ck = session
    r = P.get(srv, "/verify", cookie=ck)
    # under no-referrer a browser posts `Origin: null`, which the guard refuses
    assert r.headers["Referrer-Policy"] == "same-origin"


def test_origin_ok_unit():
    h = {"Origin": "http://127.0.0.1:8787"}
    assert auth.origin_ok(h, 8787)
    assert not auth.origin_ok(h, 8788)
    assert not auth.origin_ok({}, 8787)
    assert not auth.origin_ok({"Origin": "null"}, 8787)
    assert auth.served_origins(8787) == {"http://127.0.0.1:8787", "http://localhost:8787"}
