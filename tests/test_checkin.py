"""The version check-in (arcaeon.checkin): a signed latest.json, read once a
day, two human lines, the full detail for agents, and a verifier that never
depends on it.

Every fetch here goes through a mocked opener (checkin._open); the suite runs
with ARCAEON_NO_CHECKIN=1 (root conftest) and these tests opt back in with
the `on` fixture. The signing key is a TEST key under tests/fixtures/checkin,
patched into the module constant; the shipped constant stays empty.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import sys
import urllib.error
from pathlib import Path

import pytest

from arcaeon import __version__, checkin
from arcaeon.prove import jcs

FIX = Path(__file__).resolve().parent / "fixtures" / "checkin"
TEST_SEED = base64.b64decode((FIX / "TEST_ONLY_checkin_key.b64").read_text().strip())
OTHER_SEED = base64.b64decode((FIX / "TEST_ONLY_checkin_other_key.b64").read_text().strip())

UPDATE = "Update to the latest version."
UNSUPPORTED = "This version is no longer supported."
DAY = 86400
T0 = 1_800_000_000.0   # a fixed "now" for the clock-driven tests


def _crypto():
    return pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")


def _pub(seed: bytes) -> bytes:
    ed = _crypto()
    from cryptography.hazmat.primitives import serialization as S
    return ed.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        S.Encoding.Raw, S.PublicFormat.Raw)


def _did(seed: bytes) -> str:
    from arcaeon.prove.vet.receipts import did_key
    return did_key(_pub(seed))


def _sign(seed: bytes, msg: bytes) -> bytes:
    ed = _crypto()
    return ed.Ed25519PrivateKey.from_private_bytes(seed).sign(msg)


def payload(**over):
    p = {"kind": "arcaeon.latest", "schema": 1, "latest": "99.0.0",
         "minimum_supported": "0.1.0", "block_after": {"version": "99.1.0", "date": "2099-01-01"},
         "notice": "a test notice", "issued_at": "2026-10-05T00:00:00Z"}
    p.update(over)
    return p


def doc(p=None, seed=TEST_SEED, keyid=None) -> dict:
    p = payload() if p is None else p
    sig = _sign(seed, jcs.canonicalize(p))
    return {"payload": p, "signatures": [{"keyid": keyid or _did(seed),
                                          "sig": base64.b64encode(sig).decode()}]}


def raw(d) -> bytes:
    return json.dumps(d).encode()


@pytest.fixture
def trusted(monkeypatch):
    monkeypatch.setattr(checkin, "CHECKIN_KEYS", (_did(TEST_SEED),))


@pytest.fixture
def on(monkeypatch, tmp_path):
    """Check-in ON for this test, with its own ARCAEON_HOME."""
    monkeypatch.delenv("ARCAEON_NO_CHECKIN", raising=False)
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "ah"))
    return tmp_path / "ah"


class Opener:
    """A stand-in for the network: answers by URL, records every request."""

    def __init__(self, answers=None):
        self.answers = answers or {}
        self.requests = []

    def __call__(self, req, timeout):
        self.requests.append(req)
        a = self.answers.get(req.full_url)
        if a is None:
            raise urllib.error.URLError("offline (test)")
        if isinstance(a, Exception):
            raise a
        return io.BytesIO(a)


@pytest.fixture
def net(monkeypatch):
    o = Opener()
    monkeypatch.setattr(checkin, "_open", o)
    return o


def _pypi(version: str) -> bytes:
    return json.dumps({"info": {"version": version}, "releases": {}}).encode()


# --- the shipped constant and the suite default --------------------------------------

def test_the_suite_runs_with_checkin_off():
    assert os.environ.get("ARCAEON_NO_CHECKIN") == "1"
    assert checkin.enabled() is False


def test_the_shipped_trusted_key_list_is_empty():
    assert checkin.CHECKIN_KEYS == ()


def test_no_environment_variable_swaps_the_trusted_key(on, net, monkeypatch):
    for name in ("ARCAEON_CHECKIN_KEYS", "ARCAEON_CHECKIN_KEY", "ARCAEON_LATEST_KEY"):
        monkeypatch.setenv(name, _did(TEST_SEED))
    word, p, why = checkin.verify_document(raw(doc()))
    assert word == "COULD NOT LOOK" and p is None and "no trusted key" in why
    src = Path(checkin.__file__).read_text(encoding="utf-8")
    assert "CHECKIN_KEYS" in src
    assert not any(k in src for k in ("ARCAEON_CHECKIN_KEY", "ARCAEON_LATEST_KEY"))


def test_default_urls():
    assert checkin.DEFAULT_URL == "https://arcaeon.io/latest.json"
    assert checkin.PYPI_URL == "https://pypi.org/pypi/arcaeon/json"


# --- Ed25519 without the extra -------------------------------------------------------

def test_pure_ed25519_rfc8032_vector_1():
    pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
                        "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    assert checkin._ed25519_verify_pure(pub, b"", sig) is True
    assert checkin._ed25519_verify_pure(pub, b"x", sig) is False
    bad = bytearray(sig); bad[0] ^= 1
    assert checkin._ed25519_verify_pure(pub, b"", bytes(bad)) is False


def test_pure_ed25519_agrees_with_cryptography():
    pub = _pub(TEST_SEED)
    for i in range(4):
        m = hashlib.sha256(bytes([i])).digest() * i
        s = _sign(TEST_SEED, m)
        assert checkin._ed25519_verify_pure(pub, m, s) is True
        assert checkin._ed25519_verify_pure(_pub(OTHER_SEED), m, s) is False


def test_without_the_sign_extra_the_pure_verifier_decides(trusted, monkeypatch):
    d = doc()
    monkeypatch.setitem(sys.modules, "cryptography.hazmat.primitives.asymmetric.ed25519", None)
    assert checkin.verify_document(raw(d))[0] == "VERIFIED"
    d["payload"]["latest"] = "0.0.1"
    assert checkin.verify_document(raw(d))[0] == "BROKEN"


def test_pure_ed25519_refuses_a_noncanonical_s():
    pub = _pub(TEST_SEED)
    s = _sign(TEST_SEED, b"m")
    L = 2 ** 252 + 27742317777372353535851937790883648493
    big = (int.from_bytes(s[32:], "little") + L).to_bytes(32, "little")
    assert checkin._ed25519_verify_pure(pub, b"m", s[:32] + big) is False


# --- the signed document: VERIFIED, or ignored with a reason --------------------------

def test_a_good_document_is_verified(trusted):
    word, p, why = checkin.verify_document(raw(doc()))
    assert word == "VERIFIED" and p["latest"] == "99.0.0" and why is None


def test_with_no_trusted_key_every_answer_is_unverified():
    word, p, why = checkin.verify_document(raw(doc()))
    assert (word, p) == ("COULD NOT LOOK", None) and "no trusted key" in why


@pytest.mark.parametrize("case", ["bad_sig", "unknown_kid", "edited", "kid_swapped"])
def test_tampered_documents_are_broken(trusted, case):
    d = doc()
    if case == "bad_sig":
        s = bytearray(base64.b64decode(d["signatures"][0]["sig"])); s[5] ^= 0xFF
        d["signatures"][0]["sig"] = base64.b64encode(bytes(s)).decode()
    elif case == "unknown_kid":
        d = doc(seed=OTHER_SEED)
    elif case == "edited":
        d["payload"]["latest"] = "0.0.1"
    elif case == "kid_swapped":
        d = doc(seed=OTHER_SEED, keyid=_did(TEST_SEED))
    word, p, why = checkin.verify_document(raw(d))
    assert word == "BROKEN" and p is None and why


@pytest.mark.parametrize("bad", [
    b"not json", b"[]", b"{}", json.dumps({"payload": payload()}).encode(),
    json.dumps({"payload": "x", "signatures": []}).encode(),
    json.dumps({"payload": payload(), "signatures": [{"keyid": 1, "sig": "!"}]}).encode(),
    b"\xff\xfe", b"{" * 5000,
])
def test_malformed_documents_are_broken(trusted, bad):
    word, p, why = checkin.verify_document(bad)
    assert word == "BROKEN" and p is None and why


@pytest.mark.parametrize("over", [
    {"latest": "not a version"}, {"minimum_supported": 3}, {"kind": "something.else"},
    {"schema": 2}, {"block_after": "soon"}, {"notice": "x" * 5000}, {"latest": None},
])
def test_a_signed_but_malformed_payload_is_broken(trusted, over):
    word, p, why = checkin.verify_document(raw(doc(payload(**over))))
    assert word == "BROKEN" and p is None and why


# --- versions and the two lines -------------------------------------------------------

@pytest.mark.parametrize("a,b", [
    ("0.10.0", "0.11.0"), ("0.9", "0.10"), ("1.0rc1", "1.0"), ("1.0a1", "1.0b1"),
    ("1.0.dev1", "1.0a1"), ("1.0", "1.0.post1"), ("v1.2", "1.3"), ("1.0", "1.0.1"),
])
def test_version_order(a, b):
    assert checkin.parse_version(a) < checkin.parse_version(b)


def test_trailing_zeros_compare_equal():
    assert checkin.parse_version("1.0") == checkin.parse_version("1.0.0")


@pytest.mark.parametrize("s", ["", "abc", "1..2", "1.0-foo", None, 3, "1.0+local!"])
def test_unparseable_versions(s):
    assert checkin.parse_version(s) is None


def test_line_for():
    lf = checkin.line_for
    assert lf("0.10.0", "0.11.0", "0.9.0") == UPDATE
    assert lf("0.8.0", "0.11.0", "0.9.0") == UNSUPPORTED          # past support wins
    assert lf("0.11.0", "0.11.0", "0.9.0") is None
    assert lf("0.12.0", "0.11.0", "0.9.0") is None
    assert lf("0.10.0", "garbage", "0.9.0") is None
    assert lf("garbage", "0.11.0", "0.9.0") is None
    assert lf("0.10.0", "0.11.0", None) == UPDATE
    assert checkin.LINES == (UPDATE, UNSUPPORTED)


# --- what is sent ----------------------------------------------------------------------

def test_the_request_carries_the_version_and_nothing_else(on, trusted, net):
    net.answers[checkin.DEFAULT_URL] = raw(doc())
    assert checkin.maybe_fetch(now=T0) is True
    (req,) = net.requests
    assert req.get_method() == "GET" and req.data is None
    assert req.full_url == "https://arcaeon.io/latest.json"
    headers = {k.lower(): v for k, v in req.header_items()}
    assert headers == {"user-agent": f"arcaeon/{__version__}", "accept": "application/json"}
    blob = json.dumps([req.full_url, sorted(headers.values())]).lower()   # what varies
    for leak in (os.environ.get("USERNAME", "\0").lower(), os.getcwd().lower(), "cookie",
                 str(on).lower()):
        assert leak not in blob


def test_the_pypi_fallback_request_is_the_same_shape(on, net):
    checkin.maybe_fetch(now=T0)
    urls = [r.full_url for r in net.requests]
    assert urls == [checkin.DEFAULT_URL, checkin.PYPI_URL]
    for r in net.requests:
        assert {k.lower() for k, _ in r.header_items()} == {"user-agent", "accept"}


# --- off, cache, once a day ------------------------------------------------------------

def test_off_means_no_fetch_no_line_no_cache(monkeypatch, tmp_path, net):
    monkeypatch.setenv("ARCAEON_NO_CHECKIN", "1")
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "ah"))
    assert checkin.maybe_fetch(now=T0) is False
    assert checkin.cli_notice(now=T0) is None
    assert checkin.block(now=T0) is None
    assert net.requests == [] and not (tmp_path / "ah").exists()


def test_the_cache_lives_under_arcaeon_home(on):
    assert checkin.cache_path() == on / "checkin.json"


def test_at_most_one_fetch_per_day(on, trusted, net):
    net.answers[checkin.DEFAULT_URL] = raw(doc())
    assert checkin.maybe_fetch(now=T0) is True
    assert checkin.maybe_fetch(now=T0 + DAY - 60) is False
    assert len(net.requests) == 1
    assert checkin.maybe_fetch(now=T0 + DAY + 1) is True
    assert len(net.requests) == 2


def test_a_failed_fetch_also_waits_a_day(on, net):
    checkin.maybe_fetch(now=T0)
    n = len(net.requests)
    assert checkin.maybe_fetch(now=T0 + 3600) is False and len(net.requests) == n


def test_the_cli_line_is_printed_at_most_once_a_day(on, trusted, net):
    net.answers[checkin.DEFAULT_URL] = raw(doc())
    checkin.maybe_fetch(now=T0)
    assert checkin.cli_notice(now=T0) == UPDATE
    assert checkin.cli_notice(now=T0 + 60) is None
    assert checkin.cli_notice(now=T0 + DAY) == UPDATE


def test_offline_prints_nothing_and_raises_nothing(on, net, capsys):
    net.answers[checkin.DEFAULT_URL] = OSError("boom")
    net.answers[checkin.PYPI_URL] = urllib.error.HTTPError(checkin.PYPI_URL, 503, "x", {}, None)
    checkin.maybe_fetch(now=T0)
    assert checkin.cli_notice(now=T0) is None
    b = checkin.block(now=T0)
    assert b["line"] is None and b["signature"] == "COULD NOT LOOK"
    assert capsys.readouterr() == ("", "")


def test_an_unwritable_cache_never_raises(on, trusted, net):
    on.parent.mkdir(parents=True, exist_ok=True)
    on.write_text("a file where the directory should be")
    net.answers[checkin.DEFAULT_URL] = raw(doc())
    checkin.maybe_fetch(now=T0)
    assert checkin.cli_notice(now=T0) is None
    assert checkin.block(now=T0) is None


def test_a_garbled_cache_is_no_answer(on):
    on.mkdir(parents=True)
    (on / "checkin.json").write_text("{nope")
    assert checkin.cli_notice(now=T0) is None
    assert checkin.block(now=T0) is None


# --- tampered = ignored ----------------------------------------------------------------

def test_a_tampered_answer_is_ignored_and_the_agent_block_says_why(on, trusted, net):
    d = doc()
    d["payload"]["minimum_supported"] = "0.0.1"     # edited after signing
    net.answers[checkin.DEFAULT_URL] = raw(d)
    net.answers[checkin.PYPI_URL] = _pypi("99.0.0")
    checkin.maybe_fetch(now=T0)
    assert [r.full_url for r in net.requests] == [checkin.DEFAULT_URL]   # no fallback
    assert checkin.cli_notice(now=T0) is None
    b = checkin.block(now=T0)
    assert b["line"] is None and b["signature"] == "BROKEN" and b["latest"] is None
    assert b["ignored_because"]


def test_an_edited_cache_is_reverified_and_ignored(on, trusted, net):
    net.answers[checkin.DEFAULT_URL] = raw(doc(payload(latest="0.0.1")))
    checkin.maybe_fetch(now=T0)
    assert checkin.block(now=T0)["line"] is None
    c = json.loads((on / "checkin.json").read_text())
    c["signed"]["doc"]["payload"]["latest"] = "99.0.0"
    (on / "checkin.json").write_text(json.dumps(c))
    b = checkin.block(now=T0)
    assert b["line"] is None and b["signature"] == "BROKEN"


def test_an_older_signed_answer_does_not_replace_a_newer_one(on, trusted, net):
    net.answers[checkin.DEFAULT_URL] = raw(doc(payload(issued_at="2026-10-05T00:00:00Z")))
    checkin.maybe_fetch(now=T0)
    net.answers[checkin.DEFAULT_URL] = raw(doc(payload(latest="0.0.1",
                                                       issued_at="2026-01-01T00:00:00Z")))
    checkin.maybe_fetch(now=T0 + DAY + 1)
    b = checkin.block(now=T0 + DAY + 1)
    assert b["latest"] == "99.0.0" and b["line"] == UPDATE


# --- the full detail for agents; the PyPI fallback -------------------------------------

def test_the_agent_block(on, trusted, net):
    net.answers[checkin.DEFAULT_URL] = raw(doc())
    checkin.maybe_fetch(now=T0)
    b = checkin.block(now=T0)
    assert b == {
        "installed": __version__, "latest": "99.0.0", "minimum_supported": "0.1.0",
        "block_after": {"version": "99.1.0", "date": "2099-01-01"}, "notice": "a test notice",
        "upgrade_command": "pip install -U arcaeon", "signature": "VERIFIED",
        "source": checkin.DEFAULT_URL, "fetched_at": b["fetched_at"], "line": UPDATE,
        "ignored_because": None,
    }
    assert b["fetched_at"].endswith("Z")


def test_unsupported_wins_in_the_line(on, trusted, net):
    net.answers[checkin.DEFAULT_URL] = raw(doc(payload(minimum_supported="98.0")))
    checkin.maybe_fetch(now=T0)
    assert checkin.block(now=T0)["line"] == UNSUPPORTED
    assert checkin.cli_notice(now=T0) == UNSUPPORTED


def test_pypi_fallback_is_unsigned_and_only_says_update(on, net):
    net.answers[checkin.DEFAULT_URL] = urllib.error.HTTPError(checkin.DEFAULT_URL, 404, "nf", {}, None)
    net.answers[checkin.PYPI_URL] = _pypi("99.0.0")
    checkin.maybe_fetch(now=T0)
    b = checkin.block(now=T0)
    assert (b["signature"], b["source"], b["line"]) == ("unsigned", checkin.PYPI_URL, UPDATE)
    assert b["minimum_supported"] is None and b["block_after"] is None


def test_pypi_never_overrides_a_signed_answer(on, trusted, net):
    net.answers[checkin.DEFAULT_URL] = raw(doc(payload(latest=__version__)))
    checkin.maybe_fetch(now=T0)
    assert checkin.block(now=T0)["line"] is None
    del net.answers[checkin.DEFAULT_URL]
    net.answers[checkin.PYPI_URL] = _pypi("99.0.0")
    checkin.maybe_fetch(now=T0 + DAY + 1)
    b = checkin.block(now=T0 + DAY + 1)
    assert b["signature"] == "VERIFIED" and b["line"] is None


def test_pypi_garbage_is_no_line(on, net):
    net.answers[checkin.PYPI_URL] = b"<html>"
    checkin.maybe_fetch(now=T0)
    assert checkin.block(now=T0)["line"] is None


def test_an_oversized_answer_is_refused(on, trusted, net):
    net.answers[checkin.DEFAULT_URL] = b" " * (checkin.MAX_BYTES + 10) + raw(doc())
    checkin.maybe_fetch(now=T0)
    assert checkin.block(now=T0)["line"] is None


# --- the CLI face ----------------------------------------------------------------------

def test_cli_prints_the_line_once_a_day_on_stderr(on, trusted, net, capsys):
    from arcaeon import cli
    net.answers[checkin.DEFAULT_URL] = raw(doc())
    assert cli.main(["version"]) == 0
    out, err = capsys.readouterr()
    assert err.splitlines()[-1] == UPDATE and UPDATE not in out
    assert err.count(UPDATE) == 1
    assert cli.main(["version"]) == 0
    assert UPDATE not in capsys.readouterr().err
    assert len(net.requests) == 1


def test_cli_offline_changes_nothing(on, net, capsys, monkeypatch):
    from arcaeon import cli
    monkeypatch.setenv("ARCAEON_NO_CHECKIN", "1")
    rc_off = cli.main(["version"]); off = capsys.readouterr()
    monkeypatch.delenv("ARCAEON_NO_CHECKIN")
    rc_on = cli.main(["version"]); on_ = capsys.readouterr()
    assert (rc_off, off) == (rc_on, on_)


def test_cli_with_checkin_off_never_touches_the_network(monkeypatch, net, capsys):
    from arcaeon import cli
    cli.main(["version"])
    assert net.requests == []


# --- the verifier never depends on it --------------------------------------------------

def _ledger(tmp_path) -> str:
    """Two rows, written with the check-in off (`log` may fetch; this setup must not)."""
    from arcaeon import cli
    p = tmp_path / "l.jsonl"
    was = os.environ.get("ARCAEON_NO_CHECKIN")
    os.environ["ARCAEON_NO_CHECKIN"] = "1"
    try:
        for i in range(2):
            assert cli.main(["log", str(p), json.dumps({"n": i})]) == 0
    finally:
        if was is None:
            del os.environ["ARCAEON_NO_CHECKIN"]
        else:
            os.environ["ARCAEON_NO_CHECKIN"] = was
    return str(p)


def _run_verify(capsys, *argv):
    from arcaeon import cli
    capsys.readouterr()
    rc = cli.main(["verify", *argv])
    o = capsys.readouterr()
    return rc, o.out, o.err


@pytest.mark.parametrize("which", ["good", "broken", "missing"])
def test_verify_is_byte_identical_with_no_cache_or_checkin_off(tmp_path, monkeypatch, net,
                                                               capsys, which):
    led = _ledger(tmp_path)
    if which == "broken":
        lines = Path(led).read_text().splitlines()
        lines[0] = lines[0].replace('"n": 0', '"n": 7').replace('"n":0', '"n":7')
        Path(led).write_text("\n".join(lines) + "\n")
    if which == "missing":
        led = str(tmp_path / "nope.jsonl")
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "ah"))
    off = _run_verify(capsys, led)
    monkeypatch.delenv("ARCAEON_NO_CHECKIN")
    on_ = _run_verify(capsys, led)
    assert off == on_
    assert "checkin" not in off[1]
    assert net.requests == []                 # verify never fetches
    assert not (tmp_path / "ah" / "checkin.json").exists()


def test_verify_never_fetches_even_when_the_cache_is_stale(on, trusted, net, tmp_path, capsys):
    net.answers[checkin.DEFAULT_URL] = raw(doc())
    checkin.maybe_fetch(now=T0)              # long ago
    n = len(net.requests)
    led = _ledger(tmp_path)
    _run_verify(capsys, led)
    assert len(net.requests) == n


def test_verify_reads_the_cache_for_its_header_and_json(on, trusted, net, tmp_path, capsys):
    led = _ledger(tmp_path)
    net.answers[checkin.DEFAULT_URL] = raw(doc())
    checkin.maybe_fetch()
    rc, out, err = _run_verify(capsys, led)
    assert rc == 0
    assert err.splitlines()[0] == UPDATE
    rep = json.loads(out)
    assert rep["verdict"] == "VERIFIED"
    assert rep["checkin"]["signature"] == "VERIFIED" and rep["checkin"]["line"] == UPDATE
    rc2, out2, err2 = _run_verify(capsys, led)        # a header, every report
    assert err2.splitlines()[0] == UPDATE and rc2 == 0


def test_verify_exit_code_does_not_move_with_the_line(on, trusted, net, tmp_path, capsys):
    led = _ledger(tmp_path)
    lines = Path(led).read_text().splitlines()
    Path(led).write_text(lines[0].replace("0", "5", 1) + "\n" + lines[1] + "\n")
    net.answers[checkin.DEFAULT_URL] = raw(doc(payload(minimum_supported="98")))
    checkin.maybe_fetch()
    rc, out, err = _run_verify(capsys, led)
    assert rc == 1 and json.loads(out)["verdict"] == "BROKEN"
    assert err.splitlines()[0] == UNSUPPORTED


def test_a_tampered_cache_gives_verify_no_header(on, trusted, net, tmp_path, capsys):
    led = _ledger(tmp_path)
    net.answers[checkin.DEFAULT_URL] = raw(doc())
    checkin.maybe_fetch()
    c = json.loads((on / "checkin.json").read_text())
    c["signed"]["doc"]["payload"]["notice"] = "edited"
    (on / "checkin.json").write_text(json.dumps(c))
    rc, out, err = _run_verify(capsys, led)
    assert UPDATE not in err and rc == 0
    assert json.loads(out)["checkin"]["signature"] == "BROKEN"


# --- the MCP face ----------------------------------------------------------------------

def test_mcp_status_carries_the_checkin_block(on, trusted, net):
    pytest.importorskip("mcp")
    from arcaeon.mcp import server
    net.answers[checkin.DEFAULT_URL] = raw(doc())
    checkin.maybe_fetch()
    b = server._status_payload()["checkin"]
    assert b["upgrade_command"] == "pip install -U arcaeon" and b["line"] == UPDATE
    assert UPDATE in server._instructions()


def test_mcp_status_says_when_checkin_is_off():
    pytest.importorskip("mcp")
    from arcaeon.mcp import server
    b = server._status_payload()["checkin"]
    assert b == {"off": True, "why": "ARCAEON_NO_CHECKIN is set"}
    assert "Update to" not in server._instructions()
