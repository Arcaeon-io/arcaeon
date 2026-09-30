"""The connect table on the site's get page is generated from the catalog (K123).

The page check needs a site checkout (ARCAEON_SITE_ROOT, the same variable
test_docs uses for get.html) and is skipped without one. The rest runs
everywhere: every catalog client is in the block, its JSON is the exact
merge_json the command prints under the installed launch form, and the
block does not depend on this machine's home, OS or connect override.
"""
from __future__ import annotations

import json
import os
import re
from html import unescape
from pathlib import Path

import pytest

from arcaeon.connect import catalog as C
from arcaeon.connect import cli as CC
from _load import load_module

ROOT = Path(__file__).resolve().parents[2]
gen = load_module("gen_get_table", ROOT / "tools" / "gen_get_table.py")


def _site_page() -> Path:
    root = os.environ.get("ARCAEON_SITE_ROOT")
    if not root:
        pytest.skip("ARCAEON_SITE_ROOT is not set (no site checkout to compare against)")
    page = Path(root) / "get.html"
    if not page.is_file():
        pytest.skip("ARCAEON_SITE_ROOT has no get.html")
    return page


def test_site_get_page_block_matches_the_catalog():
    page = _site_page()
    assert gen.main(["--site", str(page.parent), "--check"]) == 0, (
        "get.html connect table drifted; run py tools/gen_get_table.py --site "
        "<site> --write")


def test_check_says_drift_when_a_snippet_is_edited(tmp_path):
    text = gen.render_block("\r\n")
    edited = text.replace('"mcp"', '"mcp", "--edited"', 1)
    assert edited != text
    (tmp_path / "get.html").write_bytes(("<main>\r\n" + edited + "\r\n</main>\r\n").encode())
    assert gen.main(["--site", str(tmp_path), "--check"]) == 1
    assert gen.main(["--site", str(tmp_path), "--write"]) == 0
    assert gen.main(["--site", str(tmp_path), "--check"]) == 0
    assert b"--edited" not in (tmp_path / "get.html").read_bytes()


def test_check_without_markers_is_could_not_look(tmp_path):
    (tmp_path / "get.html").write_text("<main></main>", encoding="utf-8")
    assert gen.main(["--site", str(tmp_path), "--check"]) == 3


def test_every_catalog_client_has_one_row_in_catalog_order():
    block = gen.render_block()
    found = re.findall(r"<code>arcaeon connect ([a-z-]+)</code>", block)
    assert found == C.names()


def test_each_snippet_is_what_connect_merges_under_the_installed_form(monkeypatch):
    monkeypatch.setattr(CC, "launch_form", lambda *a, **k: dict(gen.PUBLIC_FORM))
    snippets = [unescape(s) for s in
                re.findall(r"<pre><code>(.*?)</code></pre>", gen.render_block(), re.S)]
    want = [json.dumps(CC.merge_json(e), indent=2) for e in C.CATALOG if e.writes_file]
    assert snippets == want


def test_rows_without_a_file_say_why_in_plain_words():
    by = {r["client"]: r for r in gen.rows()}
    assert CC.DEPLOY_LINE in by["chatgpt"]["says"]
    assert "/openapi.json" in by["generic-http"]["says"]
    assert "127.0.0.1" in by["generic-http"]["says"]


def test_block_does_not_depend_on_this_machine(tmp_path, monkeypatch):
    first = gen.render_block()
    monkeypatch.setenv(C.HOME_ENV, str(tmp_path / "somewhere-else"))
    monkeypatch.setattr(CC, "launch_form", lambda *a, **k: {"command": "/x/python",
                                                            "args": ["-m", "arcaeon", "mcp"]})
    assert gen.render_block() == first
    assert str(tmp_path) not in first
    assert os.environ[C.HOME_ENV] == str(tmp_path / "somewhere-else")
    assert CC.launch_form()["command"] == "/x/python"


def test_unconfirmed_paths_are_marked_on_the_page():
    block = gen.render_block()
    for e in C.CATALOG:
        for os_name in C.OSES:
            if e.writes_file and e.paths.get(os_name) and not C.confirmed_for(e, os_name):
                row = next(x for x in block.splitlines()
                           if f"arcaeon connect {e.name}</code>" in x)
                assert f"{gen.OS_LABEL[os_name]}: " in row
                assert "not stated in the app's docs" in row, (e.name, os_name)


@pytest.mark.parametrize("ch", ["—", "–", " - "])
def test_block_has_no_dash(ch):
    assert ch not in gen.render_block()
