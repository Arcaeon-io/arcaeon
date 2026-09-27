"""Path fence (K006): every request path is resolved against the served root,
symlinks followed, and refused with 400 `outside the served root` if it
leaves it. Output directories likewise."""
from __future__ import annotations

import http.client
import io
import json
import os
import threading
from dataclasses import replace

import pytest

from arcaeon.serve import cli as serve_cli
from arcaeon.serve import fence as F
from arcaeon.serve import h_core as H
from arcaeon.serve import routes as R
from arcaeon.serve import server as S


@pytest.fixture()
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arcaeon-home"))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    r = tmp_path / "served"
    (r / "nested" / "deeper").mkdir(parents=True)
    (tmp_path / "elsewhere").mkdir()
    return r


def _symlink_or_skip(link, target, is_dir=False):
    try:
        os.symlink(target, link, target_is_directory=is_dir)
    except (OSError, NotImplementedError) as e:
        pytest.skip(f"this OS or account cannot make a symlink ({type(e).__name__})")


def _ledger(p):
    for i in range(2):
        assert H.log({"ledger": str(p), "fields": {"i": i}})["exit"] == 0
    return p


# --- the fence on its own ------------------------------------------------------------

def test_dot_dot_is_refused(root):
    with pytest.raises(F.OutsideRoot, match="outside the served root"):
        F.Fence(root).resolve("../x", "ledger")


def test_dot_dot_that_comes_back_in_is_allowed(root):
    got = F.Fence(root).resolve("nested/../nested/a.jsonl")
    assert got == str((root / "nested" / "a.jsonl").resolve())


def test_an_absolute_path_elsewhere_is_refused(root, tmp_path):
    with pytest.raises(F.OutsideRoot):
        F.Fence(root).resolve(str(tmp_path / "elsewhere" / "l.jsonl"))


def test_a_sibling_with_the_root_as_a_prefix_is_refused(root, tmp_path):
    (tmp_path / "served-evil").mkdir()
    with pytest.raises(F.OutsideRoot):
        F.Fence(root).resolve(str(tmp_path / "served-evil" / "l.jsonl"))


def test_a_legal_nested_path_resolves_under_the_root(root):
    got = F.Fence(root).resolve("nested/deeper/l.jsonl")
    assert got == str((root / "nested" / "deeper" / "l.jsonl").resolve())
    assert F.Fence(root).resolve(str(root / "nested")) == str((root / "nested").resolve())


def test_a_file_symlink_pointing_out_is_refused(root, tmp_path):
    target = tmp_path / "elsewhere" / "secret.jsonl"
    target.write_text("{}\n", encoding="utf-8")
    _symlink_or_skip(root / "link.jsonl", target)
    with pytest.raises(F.OutsideRoot):
        F.Fence(root).resolve("link.jsonl")


def test_a_directory_symlink_pointing_out_is_refused(root, tmp_path):
    _symlink_or_skip(root / "outdir", tmp_path / "elsewhere", is_dir=True)
    with pytest.raises(F.OutsideRoot):
        F.Fence(root).resolve("outdir/new.jsonl", "out")


def test_a_symlink_inside_pointing_inside_is_allowed(root):
    (root / "nested" / "real.jsonl").write_text("{}\n", encoding="utf-8")
    _symlink_or_skip(root / "alias.jsonl", root / "nested" / "real.jsonl")
    got = F.Fence(root).resolve("alias.jsonl")
    assert got == str((root / "nested" / "real.jsonl").resolve())


def test_a_nul_byte_is_refused(root):
    with pytest.raises(F.OutsideRoot):
        F.Fence(root).resolve("a\0b")


def test_apply_fences_every_path_field_and_leaves_names_alone(root):
    body = {"ledger": "l.jsonl", "out": "nested", "ns": "../not-a-path", "strict": True}
    got = F.Fence(root).apply(body)
    assert got["ledger"] == str((root / "l.jsonl").resolve())
    assert got["out"] == str((root / "nested").resolve())
    assert got["ns"] == "../not-a-path" and got["strict"] is True
    with pytest.raises(F.OutsideRoot, match="`out`"):
        F.Fence(root).apply({"ledger": "l.jsonl", "out": "../../x"})


def test_a_root_that_is_not_a_directory_is_refused(root):
    with pytest.raises(NotADirectoryError):
        F.Fence(root / "missing")


def test_serve_root_not_a_directory_is_usage_2(root, capsys):
    assert serve_cli.main(["--port", "0", "--root", str(root / "missing")]) == 2
    assert "not a directory" in capsys.readouterr().err


# --- over HTTP -----------------------------------------------------------------------------

@pytest.fixture()
def srv(root, monkeypatch):
    new = replace(R.find("POST", "/v1/verify"), handler="arcaeon.serve.h_core:verify")
    monkeypatch.setattr(R, "ROUTES", tuple(new if r.path == "/v1/verify" else r
                                           for r in R.ROUTES))
    monkeypatch.chdir(root.parent)          # the root is NOT the working directory
    server = S.make_server(port=0, token=None, root=root)
    ready = threading.Event()
    t = threading.Thread(target=S.run, args=(server,),
                         kwargs={"ready": ready, "out": io.StringIO()}, daemon=True)
    t.start()
    assert ready.wait(10)
    yield server
    server.shutdown()
    t.join(10)


def post(server, path, body):
    c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=30)
    c.request("POST", path, body=json.dumps(body).encode(),
              headers={"Content-Type": "application/json"})
    r = c.getresponse()
    out = json.loads(r.read())
    c.close()
    return r.status, out


@pytest.mark.parametrize("where", ["../elsewhere/l.jsonl", "ABS"])
def test_http_refuses_paths_outside_with_400(srv, root, tmp_path, where):
    led = _ledger(tmp_path / "elsewhere" / "l.jsonl")
    value = str(led) if where == "ABS" else where
    status, body = post(srv, "/v1/verify", {"ledger": value})
    assert status == 400 and body["exit"] == 2
    assert body["error"] == "`ledger` is outside the served root"
    assert str(tmp_path) not in body["error"]


def test_http_refuses_a_symlink_out(srv, root, tmp_path):
    led = _ledger(tmp_path / "elsewhere" / "l.jsonl")
    _symlink_or_skip(root / "link.jsonl", led)
    status, body = post(srv, "/v1/verify", {"ledger": "link.jsonl"})
    assert status == 400 and "outside the served root" in body["error"]


def test_http_relative_paths_mean_relative_to_the_root(srv, root):
    _ledger(root / "nested" / "l.jsonl")
    status, body = post(srv, "/v1/verify", {"ledger": "nested/l.jsonl"})
    assert status == 200 and body["verdict"] == "VERIFIED" and body["exit"] == 0


def test_http_a_witness_file_outside_is_refused_too(srv, root, tmp_path):
    _ledger(root / "l.jsonl")
    status, body = post(srv, "/v1/verify", {"ledger": "l.jsonl",
                                            "witness": str(tmp_path / "pins.jsonl")})
    assert status == 400 and body["error"] == "`witness` is outside the served root"
