"""`connect chatgpt` and `connect generic-http` write nothing (K024)."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from arcaeon.connect import catalog as C
from arcaeon.connect import cli

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = "needs a public URL, which is a deploy decision"


@pytest.fixture()
def arcaeon_home(tmp_path, monkeypatch):
    h = tmp_path / "arcaeon-home"
    monkeypatch.setenv("ARCAEON_HOME", str(h))
    return h


def test_chatgpt_says_why_in_plain_words(capsys, arcaeon_home):
    assert cli.main(["chatgpt"]) == 0
    out = capsys.readouterr().out
    assert "remote connectors or GPT Actions" in out
    assert "public HTTPS address" in out and "127.0.0.1 only" in out
    assert f"GPT Action manifest: {C.GPT_ACTION_MANIFEST}" in out
    assert "arcaeon schema --format gpt-action" in out
    lines = out.rstrip("\n").splitlines()
    assert lines[-2] == DEPLOY and lines[-1] == cli.NOTHING_WRITTEN


def test_the_manifest_it_names_is_committed_and_is_openapi():
    doc = json.loads((ROOT / C.GPT_ACTION_MANIFEST).read_text(encoding="utf-8"))
    assert doc["openapi"].startswith("3.") and doc["paths"]


def test_chatgpt_json_names_the_manifest(capsys, arcaeon_home):
    assert cli.main(["chatgpt", "--json"]) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["written"] is False and "file" not in d
    assert (d["gpt_action_manifest"], d["deploy"]) == (C.GPT_ACTION_MANIFEST, DEPLOY)


@pytest.mark.parametrize("action", ["--write", "--undo", "--check"])
def test_chatgpt_write_exits_2_with_the_sentence(capsys, action, arcaeon_home):
    home = Path(os.environ[C.HOME_ENV])
    assert cli.main(["chatgpt", action]) == 2
    err = capsys.readouterr().err
    assert DEPLOY in err and "nothing written" in err
    assert not home.exists() and not arcaeon_home.exists()


def test_generic_http_prints_url_token_and_openapi(capsys, arcaeon_home):
    assert cli.main(["generic-http"]) == 0
    out = capsys.readouterr().out
    assert "url: http://127.0.0.1:8787  (the default port" in out
    assert "openapi: http://127.0.0.1:8787/openapi.json" in out
    assert f"token: {arcaeon_home / 'serve.token'}" in out
    arcaeon_home.mkdir()
    (arcaeon_home / "serve.json").write_text(
        json.dumps({"pid": 1, "port": 9911, "url": "http://127.0.0.1:9911"}), encoding="utf-8")
    assert cli.main(["generic-http", "--json"]) == 0
    d = json.loads(capsys.readouterr().out)
    assert (d["url"], d["openapi_url"]) == ("http://127.0.0.1:9911",
                                            "http://127.0.0.1:9911/openapi.json")
    assert d["token_file"] == str(arcaeon_home / "serve.token")


def test_generic_http_write_exits_2(capsys, arcaeon_home):
    assert cli.main(["generic-http", "--write"]) == 2
    assert "GET /openapi.json" in capsys.readouterr().err
    assert not Path(os.environ[C.HOME_ENV]).exists()
