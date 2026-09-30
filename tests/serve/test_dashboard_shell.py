"""The dashboard shell and session (K100): a one-time code becomes an
HttpOnly, SameSite=Strict cookie once; every page carries the CSP header and
loads nothing from anywhere else. Headless: urllib plus html.parser over a
loopback server this test starts and stops."""
from __future__ import annotations

import json
import re
import urllib.parse

import pytest

from arcaeon.serve import dashboard as D
from serve import _pages as P


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    r = tmp_path / "root"
    r.mkdir()
    return r


@pytest.fixture()
def srv(root):
    with P.running(root) as s:
        yield s


def _code(srv) -> str:
    r = P.mint(srv)
    assert r.status == 200
    body = json.loads(r.text)
    assert body["exit"] == 0 and body["expires_in"] == D.CODE_TTL
    assert body["url"] == f"{srv.url}/?t={body['code']}"
    return body["code"]


def test_code_works_once_second_use_is_401(srv):
    code = _code(srv)
    first = P.get(srv, "/?t=" + urllib.parse.quote(code))
    assert first.status == 303 and first.headers["Location"] == "/"
    cookie = first.headers["Set-Cookie"]
    assert cookie.startswith(D.COOKIE + "=")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/" in cookie
    second = P.get(srv, "/?t=" + urllib.parse.quote(code))
    assert second.status == 401
    assert "Set-Cookie" not in second.headers
    assert "already used" in second.text


def test_the_cookie_opens_the_dashboard(srv):
    cookie = P.sign_in(srv)
    r = P.get(srv, "/", cookie=cookie)
    assert r.status == 200
    assert r.headers["Content-Type"].startswith("text/html")
    assert "Arcaeon on this machine" in r.text


def test_every_answer_carries_the_csp_header(srv):
    cookie = P.sign_in(srv)
    for path, ck in (("/", cookie), ("/", None), ("/static/placeholder.css", cookie),
                     ("/static/app.js", cookie), ("/?t=nope", None)):
        r = P.get(srv, path, cookie=ck)
        csp = r.headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp, path
        assert "frame-ancestors 'none'" in csp
    ok = P.get(srv, "/", cookie=cookie)
    assert ok.headers["X-Frame-Options"] == "DENY"
    assert ok.headers["Cache-Control"] == "no-store"


def test_no_cookie_no_token_is_401(srv):
    r = P.get(srv, "/")
    assert r.status == 401 and "arcaeon open" in r.text
    assert P.get(srv, "/static/placeholder.css").status == 401


def test_a_forged_cookie_is_401(srv):
    assert P.get(srv, "/", cookie=f"{D.COOKIE}=not-a-session").status == 401


def test_bearer_token_still_opens_pages(srv):
    r = P.get(srv, "/", headers={"Authorization": f"Bearer {P.TOKEN}"})
    assert r.status == 200
    assert P.get(srv, "/", headers={"Authorization": "Bearer wrong"}).status == 401


def test_minting_a_code_needs_the_token(srv):
    r = P.request(srv, D.CODE_PATH, data=b"", method="POST")
    assert r.status == 401
    assert P.mint(srv, token="wrong").status == 401
    assert P.get(srv, D.CODE_PATH).status == 405
    cookie = P.sign_in(srv)
    r = P.request(srv, D.CODE_PATH, data=b"", method="POST", headers={"Cookie": cookie})
    assert r.status == 401          # a browser session cannot mint more codes


def test_an_expired_code_is_401(srv, monkeypatch):
    code = _code(srv)
    real = D._now
    monkeypatch.setattr(D, "_now", lambda: real() + D.CODE_TTL + 1)
    assert P.get(srv, "/?t=" + urllib.parse.quote(code)).status == 401


def test_an_expired_session_is_401(srv, monkeypatch):
    cookie = P.sign_in(srv)
    real = D._now
    monkeypatch.setattr(D, "_now", lambda: real() + D.SESSION_TTL + 1)
    assert P.get(srv, "/", cookie=cookie).status == 401


def test_issue_code_in_process(srv):
    code = D.issue_code(srv)
    assert P.get(srv, "/?t=" + urllib.parse.quote(code)).status == 303


def test_static_serves_only_named_files(srv):
    cookie = P.sign_in(srv)
    css = P.get(srv, "/static/placeholder.css", cookie=cookie)
    assert css.status == 200 and css.headers["Content-Type"].startswith("text/css")
    assert css.text.startswith("/* TODO(design-system): replace with the Claude Design "
                               "system (navy #0C1828 / gold, C2 chevron mark) before any "
                               "second face ships */")
    for bad in ("index.html", "..%2Fdashboard.py", "../dashboard.py", "nope.css"):
        assert P.get(srv, "/static/" + bad, cookie=cookie).status in (401, 404), bad


def test_the_page_loads_nothing_from_elsewhere(srv):
    cookie = P.sign_in(srv)
    tree = P.parse(P.get(srv, "/", cookie=cookie).text)
    refs = [ref for n in tree.walk() for a in ("src", "href", "action")
            if (ref := n.attrs.get(a))]
    assert refs, "the page links its stylesheet and script"
    for ref in refs:
        assert ref.startswith("/") and not ref.startswith("//"), ref
    for name in D.STATIC_FILES:
        text = (D.STATIC / name).read_text(encoding="utf-8")
        assert not re.search(r"https?://|@import|url\(|fetch\(|XMLHttpRequest", text), name


def test_api_routes_are_unchanged_under_the_mount(srv):
    r = P.get(srv, "/health")
    assert r.status == 200 and json.loads(r.text)["ok"] is True
    assert P.get(srv, "/v1/status").status == 401     # the token rule, not the cookie
    cookie = P.sign_in(srv)
    assert P.get(srv, "/v1/status", cookie=cookie).status == 401


def test_a_bad_host_header_is_refused(srv):
    assert P.get(srv, "/", headers={"Host": "evil.example"}).status == 400


def test_route_table_index_returns_the_home_page():
    assert "Arcaeon on this machine" in D.index({})
