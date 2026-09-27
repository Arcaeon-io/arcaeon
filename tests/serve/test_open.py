"""`arcaeon open` (K107): finds a running serve via serve.json or starts one,
then opens the browser; `--no-browser` prints the link with its one-time
code. webbrowser.open is patched in every test, and every server a test
starts, it stops. Loopback only."""
from __future__ import annotations

import io
import json
import socket
import threading
import time
import urllib.parse

import pytest

from arcaeon.serve import auth
from arcaeon.serve import open_cli as O
from arcaeon.serve import server as S
from serve import _pages as P


@pytest.fixture()
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("ARCAEON_HOME", str(h))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    (h / auth.TOKEN_FILE).write_text(P.TOKEN + "\n", encoding="utf-8")
    return h


@pytest.fixture()
def opened(monkeypatch):
    """Every url webbrowser.open was asked for; answers True (a browser opened)."""
    calls: list[str] = []
    state = {"answer": True}

    def fake_open(url, *a, **k):
        calls.append(url)
        return state["answer"]

    import webbrowser
    monkeypatch.setattr(webbrowser, "open", fake_open)
    return calls, state


def _link_works_once(srv_url, link):
    assert link.startswith(srv_url + "/?t=")
    split = urllib.parse.urlsplit(link)

    class _S:
        url = srv_url
    first = P.get(_S, "/?" + split.query)
    assert first.status == 303 and "arcaeon_session=" in first.headers["Set-Cookie"]
    assert P.get(_S, "/?" + split.query).status == 401


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_no_browser_prints_a_one_time_link_from_the_running_server(home, tmp_path, capsys,
                                                                   opened):
    calls, _ = opened
    with P.running(tmp_path) as srv:
        assert O.running_url() == srv.url
        assert O.main(["--no-browser"]) == 0
        out = capsys.readouterr()
        link = out.out.strip()
        assert calls == []
        assert P.TOKEN not in out.out and P.TOKEN not in out.err
        _link_works_once(srv.url, link)


def test_opens_the_browser_on_the_running_server(home, tmp_path, capsys, opened):
    calls, _ = opened
    with P.running(tmp_path) as srv:
        assert O.main([]) == 0
        out = capsys.readouterr()
        assert len(calls) == 1
        assert calls[0] not in out.out                 # opened, not printed
        assert P.TOKEN not in out.out and P.TOKEN not in out.err
        _link_works_once(srv.url, calls[0])


def test_no_browser_available_prints_the_link(home, tmp_path, capsys, opened):
    calls, state = opened
    state["answer"] = False
    with P.running(tmp_path) as srv:
        assert O.main([]) == 0
        out = capsys.readouterr().out
        assert len(calls) == 1 and calls[0] in out
        _link_works_once(srv.url, calls[0])


def _start_in_thread(argv):
    result = {}

    def target():
        result["rc"] = O.main(argv)
    t = threading.Thread(target=target, daemon=True)
    t.start()
    deadline = time.monotonic() + 15
    while O.current is None and time.monotonic() < deadline:
        time.sleep(0.02)
    assert O.current is not None
    return t, result, O.current


def _wait_serving(path, deadline=15):
    end = time.monotonic() + deadline
    while not path.exists() and time.monotonic() < end:
        time.sleep(0.02)
    assert path.exists()


def test_starts_one_when_none_is_running(home, tmp_path, opened):
    calls, _ = opened
    root = tmp_path / "root"
    root.mkdir()
    assert O.running_url() is None
    t, result, srv = _start_in_thread(["--port", "0", "--root", str(root)])
    try:
        _wait_serving(S.serve_json_path())
        deadline = time.monotonic() + 10
        while not calls and time.monotonic() < deadline:
            time.sleep(0.02)
        assert len(calls) == 1
        assert str(srv.fence.root) == str(root.resolve())
        _link_works_once(srv.url, calls[0])
        assert O.running_url() == srv.url
    finally:
        srv.shutdown()
        t.join(15)
    assert not t.is_alive() and result["rc"] == 0
    assert not S.serve_json_path().exists()
    assert O.current is None


def test_stale_or_foreign_serve_json_is_not_used(home, tmp_path, opened, monkeypatch):
    calls, _ = opened
    for doc in ({"pid": 1, "port": _free_port(), "url": f"http://127.0.0.1:{_free_port()}"},
                {"pid": 1, "port": 80, "url": "http://example.com:80"},
                {"pid": 1, "url": "http://127.0.0.1:notaport"}):
        S.serve_json_path().write_text(json.dumps(doc), encoding="utf-8")
        assert O.running_url() is None
    contacted = []
    real = O._opener

    def watching():
        op = real()
        orig = op.open

        def open_(req, *a, **k):
            url = req if isinstance(req, str) else req.full_url
            contacted.append(url)
            return orig(req, *a, **k)
        op.open = open_
        return op
    monkeypatch.setattr(O, "_opener", watching)
    S.serve_json_path().write_text(json.dumps({"url": "http://example.com:80"}),
                                   encoding="utf-8")
    t, result, srv = _start_in_thread(["--port", "0", "--root", str(tmp_path),
                                       "--no-browser"])
    try:
        _wait_serving(S.serve_json_path())
    finally:
        srv.shutdown()
        t.join(15)
    assert result["rc"] == 0 and contacted == []


def test_a_server_without_the_dashboard_is_could_not_look(home, tmp_path, capsys, opened):
    calls, _ = opened
    srv = S.make_server(port=0, token=P.TOKEN, root=tmp_path)
    ready = threading.Event()
    t = threading.Thread(target=S.run, args=(srv,), kwargs={"ready": ready,
                                                           "out": io.StringIO()}, daemon=True)
    t.start()
    assert ready.wait(10)
    try:
        assert O.main(["--no-browser"]) == 3
        err = capsys.readouterr().err
        assert "COULD NOT LOOK" in err and "does not answer the dashboard" in err
        assert calls == []
    finally:
        srv.shutdown()
        t.join(10)
    assert not t.is_alive()


def test_a_token_that_does_not_match_is_could_not_look(home, tmp_path, capsys, opened):
    calls, _ = opened
    with P.running(tmp_path, token="a-different-token"):
        assert O.main([]) == 3
        out = capsys.readouterr()
        assert "did not accept" in out.err and calls == []
        assert P.TOKEN not in out.err and "a-different-token" not in out.err


def test_bad_usage(home, capsys):
    assert O.main(["--port", "70000"]) == 2
    assert O.main(["--root", "does-not-exist-anywhere", "--port", "0"]) == 2


def test_the_cli_verb_routes_here(home, tmp_path, capsys, opened):
    from arcaeon import cli
    with P.running(tmp_path) as srv:
        assert cli.main(["open", "--no-browser"]) == 0
        link = capsys.readouterr().out.strip().splitlines()[-1]
        _link_works_once(srv.url, link)
