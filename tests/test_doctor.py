"""`arcaeon doctor` (K115): every check read -> 0, any COULD NOT LOOK -> 3.
No network beyond a 127.0.0.1 stub this file starts itself."""
import http.server
import json
import socket
import sys
import threading

import pytest

from arcaeon import cli, doctor
from arcaeon import verdict as V
from arcaeon.connect import catalog as C


@pytest.fixture
def home(tmp_path, monkeypatch):
    d = tmp_path / "arc_home"
    d.mkdir()
    monkeypatch.setenv("ARCAEON_HOME", str(d))
    monkeypatch.setenv("ARCAEON_CONNECT_HOME", str(tmp_path / "user"))
    monkeypatch.delenv("ARCAEON_JOURNAL", raising=False)
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    from arcaeon import remote
    monkeypatch.setattr(remote, "_request", lambda *a, **k: pytest.fail("network used"))
    return d


def _by(rep, name):
    return next(c for c in rep["checks"] if c["check"] == name)


def _file_client():
    return next(e for e in C.CATALOG if e.writes_file and C.config_path(e))


def _config(entry):
    from pathlib import Path
    p = Path(C.config_path(entry))
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def test_clean_home_reads_everything_and_exits_0(home, capsys):
    assert doctor.main([]) == 0
    out = capsys.readouterr().out
    assert "every check was read (exit 0)" in out
    assert V.COULD_NOT_LOOK not in out


def test_json_carries_every_check_and_the_exit(home, capsys):
    assert doctor.main(["--json"]) == 0
    rep = json.loads(capsys.readouterr().out)
    names = [c["check"] for c in rep["checks"]]
    assert names[0] == "python" and names[-1] == "journal"
    assert {"key", "serve", "extra mcp", "extra ts", "extra sign"} <= set(names)
    assert [n for n in names if n.startswith("client ")] == [f"client {n}" for n in C.names()]
    assert rep["ok"] is True and rep["exit"] == 0 and "verdict" not in rep


def test_key_is_reported_set_never_its_value(home, monkeypatch, capsys):
    monkeypatch.setenv("ARCAEON_KEY", "sk-do-not-print-4242")
    assert doctor.main(["--json"]) == 0
    out = capsys.readouterr().out
    assert "sk-do-not-print-4242" not in out
    assert _by(json.loads(out), "key")["detail"] == "ARCAEON_KEY is set"


def test_python_line_names_this_interpreter(home):
    v = sys.version_info
    assert doctor.check_python()["detail"].startswith(f"{v[0]}.{v[1]}.{v[2]}")


def test_missing_extra_is_a_reading_not_a_fault(home, monkeypatch):
    monkeypatch.setattr(cli, "_importable", lambda m: False)
    rep = doctor.report(doctor.run())
    assert _by(rep, "extra mcp")["status"] == "no"
    assert rep["exit"] == 0


class _Health(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200 if self.path == "/health" else 404)
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def log_message(self, *a):
        pass


def test_serve_reachable_on_a_loopback_stub(home):
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Health)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}"
        (home / "serve.json").write_text(json.dumps({"url": url}), encoding="utf-8")
        c = doctor.check_serve()
    finally:
        srv.shutdown()
        srv.server_close()
    assert c["status"] == "ok" and url in c["detail"]


def test_serve_json_left_over_is_a_reading(home):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    (home / "serve.json").write_text(json.dumps({"url": f"http://127.0.0.1:{port}"}),
                                     encoding="utf-8")
    c = doctor.check_serve()
    assert c["status"] in ("no", V.COULD_NOT_LOOK)
    if c["status"] == "no":
        assert "left over" in c["detail"]


def test_serve_json_off_this_machine_is_never_asked(home, monkeypatch, capsys):
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: pytest.fail("network used"))
    (home / "serve.json").write_text(json.dumps({"url": "http://example.com:8787"}),
                                     encoding="utf-8")
    assert doctor.main([]) == 3
    out = capsys.readouterr().out
    assert "COULD NOT LOOK: 1 check(s) could not be looked at (exit 3)" in out


def test_unparsable_serve_json_is_could_not_look(home):
    (home / "serve.json").write_text("{not json", encoding="utf-8")
    c = doctor.check_serve()
    assert c["status"] == V.COULD_NOT_LOOK and c["reason_word"] == "unreadable"


def test_client_absent_present_stale(home):
    e = _file_client()
    assert doctor.check_client(e)["state"] == "absent"
    p = _config(e)
    p.write_text(json.dumps({e.key: {"other": {"command": "x"}}}), encoding="utf-8")
    assert doctor.check_client(e)["state"] == "absent"
    p.write_text(json.dumps({e.key: {"arcaeon": {"command": sys.executable, "args": []}}}),
                 encoding="utf-8")
    assert doctor.check_client(e)["state"] == "present"
    p.write_text(json.dumps({e.key: {"arcaeon": {"command": "no-such-cmd-k115"}}}),
                 encoding="utf-8")
    c = doctor.check_client(e)
    assert c["state"] == "stale" and c["status"] == "ok"


def test_client_file_that_does_not_parse_exits_3(home, capsys):
    e = _file_client()
    _config(e).write_text("{broken", encoding="utf-8")
    assert doctor.main(["--json"]) == 3
    rep = json.loads(capsys.readouterr().out)
    assert rep["verdict"] == V.COULD_NOT_LOOK and rep["ok"] is None and rep["exit"] == 3
    c = _by(rep, f"client {e.name}")
    assert c["status"] == V.COULD_NOT_LOOK and c["where"] == C.config_path(e)


def test_doctor_writes_nothing_it_did_not_find(home, tmp_path):
    before = sorted(p.name for p in tmp_path.rglob("*"))
    doctor.run()
    assert sorted(p.name for p in tmp_path.rglob("*")) == before


def test_journal_off_and_missing_home(home, monkeypatch, tmp_path):
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    assert "off" in doctor.check_journal()["detail"]
    monkeypatch.delenv("ARCAEON_JOURNAL")
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "nope" / "deeper"))
    c = doctor.check_journal()
    assert c["status"] == "ok" and "not there yet" in c["detail"]
    assert not (tmp_path / "nope").exists()


def test_bad_usage_and_help(home, capsys):
    assert doctor.main(["--nope"]) == 2
    assert doctor.main(["--help"]) == 0
    assert "usage: arcaeon doctor" in capsys.readouterr().out


def test_front_door_runs_it(home, capsys):
    assert cli.main(["doctor"]) == 0
    assert "every check was read" in capsys.readouterr().out
