"""tools/make_latest_json.py writes the signed latest.json the check-in reads.

Round trip: the generator's output VERIFIES in the client (arcaeon.checkin)
when the signer is trusted, and an edited copy is ignored. Signing here uses
the TEST key under tests/fixtures/checkin; the real key is the release
owner's and is never made or read by this suite.
"""
from __future__ import annotations

import base64
import importlib.util
import io
import json
import os
from pathlib import Path

import pytest

from arcaeon import checkin

pytest.importorskip("cryptography")

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "checkin"
TEST_KEY = FIX / "TEST_ONLY_checkin_key.b64"

_spec = importlib.util.spec_from_file_location("make_latest_json",
                                               ROOT / "tools" / "make_latest_json.py")
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

BASE = ["--latest", "0.11.0", "--minimum-supported", "0.9.0",
        "--block-after-version", "0.12.0", "--block-after-date", "2099-01-01",
        "--notice", "a test notice", "--issued-at", "2026-10-05T00:00:00Z"]


def _did(seed_file: Path) -> str:
    from arcaeon.prove.vet.receipts import did_key, public_key_from_seed
    return did_key(public_key_from_seed(base64.b64decode(seed_file.read_text().strip())))


def _make(tmp_path, *extra, capsys=None) -> tuple[int, Path]:
    out = tmp_path / "latest.json"
    rc = gen.main([*BASE, "--test-key", str(TEST_KEY), "--out", str(out), *extra])
    return rc, out


def test_round_trip_verifies_in_the_client(tmp_path, monkeypatch):
    rc, out = _make(tmp_path)
    assert rc == 0
    monkeypatch.setattr(checkin, "CHECKIN_KEYS", (_did(TEST_KEY),))
    word, p, why = checkin.verify_document(out.read_bytes())
    assert word == "VERIFIED", why
    assert p == {"kind": "arcaeon.latest", "schema": 1, "latest": "0.11.0",
                 "minimum_supported": "0.9.0",
                 "block_after": {"version": "0.12.0", "date": "2099-01-01"},
                 "notice": "a test notice", "issued_at": "2026-10-05T00:00:00Z"}


def test_an_edited_output_is_ignored(tmp_path, monkeypatch):
    rc, out = _make(tmp_path)
    monkeypatch.setattr(checkin, "CHECKIN_KEYS", (_did(TEST_KEY),))
    d = json.loads(out.read_text())
    d["payload"]["latest"] = "0.10.0"
    word, p, _ = checkin.verify_document(json.dumps(d).encode())
    assert word == "BROKEN" and p is None


def test_end_to_end_through_the_fetch(tmp_path, monkeypatch):
    rc, out = _make(tmp_path)
    monkeypatch.setattr(checkin, "CHECKIN_KEYS", (_did(TEST_KEY),))
    monkeypatch.delenv("ARCAEON_NO_CHECKIN", raising=False)
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "ah"))
    monkeypatch.setattr(checkin, "__version__", "0.10.0")
    monkeypatch.setattr(checkin, "_open", lambda req, timeout: io.BytesIO(out.read_bytes()))
    checkin.maybe_fetch()
    b = checkin.block()
    assert (b["signature"], b["line"]) == ("VERIFIED", "Update to the latest version.")


def test_the_untrusted_test_key_is_ignored_by_the_shipped_client(tmp_path):
    rc, out = _make(tmp_path)
    assert checkin.verify_document(out.read_bytes())[0] == "COULD NOT LOOK"


def test_the_seed_never_appears_in_any_output(tmp_path, capsys):
    rc, out = _make(tmp_path)
    seed_b64 = TEST_KEY.read_text().strip()
    o = capsys.readouterr()
    for text in (o.out, o.err, out.read_text()):
        assert seed_b64 not in text
    assert _did(TEST_KEY) in o.err          # the public id is said, so the owner can check it


def test_key_from_a_named_environment_variable(tmp_path, monkeypatch, capsys):
    k = tmp_path / "throwaway.b64"
    k.write_text(base64.b64encode(os.urandom(32)).decode() + "\n")
    monkeypatch.setenv("SOME_KEY_PATH", str(k))
    out = tmp_path / "o.json"
    assert gen.main([*BASE, "--key-env", "SOME_KEY_PATH", "--out", str(out)]) == 0
    monkeypatch.setattr(checkin, "CHECKIN_KEYS", (_did(k),))
    assert checkin.verify_document(out.read_bytes())[0] == "VERIFIED"
    assert k.read_text().strip() not in capsys.readouterr().err


def test_key_file_flag(tmp_path, monkeypatch):
    k = tmp_path / "throwaway.b64"
    k.write_text(base64.b64encode(os.urandom(32)).decode() + "\n")
    out = tmp_path / "o.json"
    assert gen.main([*BASE, "--key-file", str(k), "--out", str(out)]) == 0
    monkeypatch.setattr(checkin, "CHECKIN_KEYS", (_did(k),))
    assert checkin.verify_document(out.read_bytes())[0] == "VERIFIED"


@pytest.mark.parametrize("argv", [
    ["--key-file", str(TEST_KEY)],                 # a TEST key through the real door
    ["--test-key", "not_a_test_key.b64"],           # the test door for a non-test file
    ["--key-env", "NO_SUCH_VARIABLE_SET_HERE"],
    [],                                            # no key at all
    ["--key-file", "a", "--test-key", str(TEST_KEY)],
])
def test_key_doors_refuse(tmp_path, argv, capsys):
    out = tmp_path / "o.json"
    assert gen.main([*BASE, *argv, "--out", str(out)]) == 2
    assert not out.exists()


@pytest.mark.parametrize("swap", [
    ("--latest", "soon"), ("--minimum-supported", "x"), ("--block-after-date", "next week"),
    ("--block-after-version", "?"), ("--issued-at", "yesterday"),
])
def test_bad_fields_refuse(tmp_path, swap):
    argv = list(BASE)
    argv[argv.index(swap[0]) + 1] = swap[1]
    out = tmp_path / "o.json"
    assert gen.main([*argv, "--test-key", str(TEST_KEY), "--out", str(out)]) == 2
    assert not out.exists()


def test_latest_and_minimum_are_required(tmp_path):
    out = tmp_path / "o.json"
    assert gen.main(["--latest", "1.0", "--test-key", str(TEST_KEY), "--out", str(out)]) == 2


def test_block_after_is_optional(tmp_path, monkeypatch):
    out = tmp_path / "o.json"
    assert gen.main(["--latest", "1.0", "--minimum-supported", "0.9", "--test-key",
                     str(TEST_KEY), "--out", str(out)]) == 0
    monkeypatch.setattr(checkin, "CHECKIN_KEYS", (_did(TEST_KEY),))
    word, p, _ = checkin.verify_document(out.read_bytes())
    assert word == "VERIFIED" and p["block_after"] is None and p["notice"] is None


def test_the_tool_has_no_key_generation():
    src = (ROOT / "tools" / "make_latest_json.py").read_text(encoding="utf-8")
    assert "generate" not in src.lower() and "urandom" not in src and "secrets" not in src


# --- docs/UPDATES.md says what the code does -------------------------------------------

UPDATES = (ROOT / "docs" / "UPDATES.md").read_text(encoding="utf-8")


def test_updates_page_names_the_off_switch_lines_and_url():
    for must in (checkin.OFF_ENV + "=1", checkin.DEFAULT_URL, checkin.PYPI_URL,
                 checkin.UPGRADE_COMMAND, "User-Agent: arcaeon/", *checkin.LINES):
        assert must in UPDATES, must


def test_updates_page_lists_exactly_the_verbs_that_fetch():
    import re
    from arcaeon import cli
    para = UPDATES.split("It runs after these verbs only:")[1].split(".\n")[0]
    assert set(re.findall(r"`([a-z-]+)`", para)) == set(cli.CHECKIN_VERBS)
    assert "verify" not in cli.CHECKIN_VERBS


def test_updates_page_invents_no_dates_and_has_limits():
    import re
    assert not re.search(r"\b20\d\d-\d\d-\d\d\b", UPDATES)
    assert UPDATES.count("set by the release owner") >= 6
    assert "## Limits" in UPDATES and "\u2014" not in UPDATES


def test_readme_links_the_updates_page():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "](docs/UPDATES.md)" in readme and "ARCAEON_NO_CHECKIN=1" in readme
