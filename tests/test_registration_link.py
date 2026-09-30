"""The witness registration link: one switch, every surface at once.

`arcaeon.remote.registration.registration_link()` is the one source of truth.
It returns the URL only when the offers document carries a top-level
`registration` object with `enabled: true` and an https `url`. Every surface
(`arcaeon buy`, `arcaeon --help`, the MCP server's instructions, tool
descriptions, status notes and keyless refusal) prints one sentence with the
link when it is on, and not a word about registration when it is off.
"""
import asyncio
import json
import webbrowser

import pytest

from arcaeon import cli, remote
from arcaeon.remote import offers as offers_mod
from arcaeon.remote.registration import registration_line, registration_link

URL = "https://witness.arcaeon.io/register?from=test"


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.setattr(webbrowser, "open", lambda *a, **k: pytest.fail("opened a browser"))
    monkeypatch.setattr(remote, "_request", lambda *a, **k: pytest.fail("network used"))
    monkeypatch.delenv("ARCAEON_OFFERS_FILE", raising=False)
    monkeypatch.delenv("ARCAEON_KEY", raising=False)


def _cat(registration=None, drop=False):
    cat = remote.load_offers()
    cat.pop("registration", None)
    if not drop and registration is not None:
        cat["registration"] = registration
    return cat


def _write(tmp_path, cat, name="offers.json"):
    f = tmp_path / name
    f.write_text(json.dumps(cat), encoding="utf-8")
    return f


@pytest.fixture
def live(tmp_path, monkeypatch):
    f = _write(tmp_path, _cat({"enabled": True, "url": URL}), "live.json")
    monkeypatch.setenv("ARCAEON_OFFERS_FILE", str(f))
    return f


@pytest.fixture(params=["missing", "disabled"])
def dark(request, tmp_path, monkeypatch):
    reg = None if request.param == "missing" else {"enabled": False, "url": URL}
    f = _write(tmp_path, _cat(reg), "dark.json")
    monkeypatch.setenv("ARCAEON_OFFERS_FILE", str(f))
    return f


def _no_regist(text):
    assert "regist" not in text.lower(), text
    assert URL not in text


# --- the helper -------------------------------------------------------------

def test_enabled_true_with_url_returns_the_url():
    assert registration_link(_cat({"enabled": True, "url": URL})) == URL


def test_enabled_false_returns_none():
    assert registration_link(_cat({"enabled": False, "url": URL})) is None


def test_missing_object_returns_none():
    assert registration_link(_cat(drop=True)) is None


@pytest.mark.parametrize("reg", [
    {"enabled": "true", "url": URL},        # a string is not the switch
    {"enabled": 1, "url": URL},
    {"enabled": True},                       # on, but no url
    {"enabled": True, "url": ""},
    {"enabled": True, "url": "http://witness.arcaeon.io/register"},
    {"enabled": True, "url": "https://"},
    {"enabled": True, "url": "https://a b"},
    {"enabled": True, "url": 5},
    "enabled",
    None,
])
def test_anything_short_of_the_switch_is_dark(reg):
    cat = _cat(drop=True)
    cat["registration"] = reg
    assert registration_link(cat) is None
    assert registration_line(cat) is None


def test_the_bundled_snapshot_is_dark_today():
    """Registration is not live: the shipped offers.json does not switch it on."""
    assert registration_link() is None
    assert registration_line() is None


def test_the_helper_reads_the_offers_file_env(live):
    assert registration_link() == URL


def test_an_unreadable_offers_file_is_dark(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_OFFERS_FILE", str(tmp_path / "nope.json"))
    assert registration_link() is None
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("ARCAEON_OFFERS_FILE", str(bad))
    assert registration_link() is None


def test_the_sentence_is_one_ascii_line_with_the_link_and_the_grant():
    line = registration_line(_cat({"enabled": True, "url": URL}))
    assert line is not None, f"registration_line returned {line!r} with the switch on"
    assert URL in line and "\n" not in line
    assert "500 credits, one time, per verified email" in line
    line.encode("ascii")


# --- arcaeon buy ------------------------------------------------------------

def test_buy_list_prints_the_link_when_live(live, capsys):
    assert cli.main(["buy", "--offers", str(live)]) == 0
    out = capsys.readouterr().out
    assert out.count(URL) == 1
    assert "buy.stripe.com" in out


def test_buy_list_says_nothing_of_registration_when_dark(dark, capsys):
    assert cli.main(["buy", "--offers", str(dark)]) == 0
    out = capsys.readouterr().out
    assert "buy.stripe.com" in out
    _no_regist(out)


def test_buy_list_default_snapshot_says_nothing_of_registration(capsys):
    assert cli.main(["buy"]) == 0
    _no_regist(capsys.readouterr().out)


def test_buy_evidence_pack_prints_the_link_when_live(live, capsys):
    assert cli.main(["buy", "evidence-pack", "--offers", str(live)]) == 0
    assert capsys.readouterr().out.count(URL) == 1


def test_buy_evidence_pack_says_nothing_of_registration_when_dark(dark, capsys):
    assert cli.main(["buy", "evidence-pack", "--offers", str(dark)]) == 0
    out = capsys.readouterr().out
    assert "50 credits" in out
    _no_regist(out)


def test_buy_one_plan_stays_one_url_either_way(live, capsys):
    assert cli.main(["buy", "mini", "--offers", str(live)]) == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith("https://buy.stripe.com/") and "\n" not in out


# --- arcaeon --help ---------------------------------------------------------

def test_help_prints_the_link_when_live(live):
    assert cli.help_text().count(URL) == 1


def test_help_says_nothing_of_registration_when_dark(dark):
    # `baseline`'s own summary ("register ... pre-registered probe sets") is a
    # verb description, not the witness registration; everything else is held.
    text = "\n".join(l for l in cli.help_text().splitlines()
                     if not l.lstrip().startswith("baseline "))
    _no_regist(text)


# --- the MCP server ---------------------------------------------------------

def _mcp_texts(monkeypatch, tmp_path):
    pytest.importorskip("mcp", reason="the connector IS an MCP server")
    from mcp import Client
    from arcaeon.mcp import server
    monkeypatch.setenv("ARCAEON_LEDGER_LOG", str(tmp_path / "agent.log.jsonl"))
    monkeypatch.setenv("ARCAEON_LEDGER_NS_DIR", str(tmp_path / "ledgers"))
    monkeypatch.setenv("ARCAEON_CALL_RECORD", str(tmp_path / "calls.jsonl"))
    srv = server.build_server()

    async def go():
        async with Client(srv) as client:
            return {t.name: t.description or "" for t in (await client.list_tools()).tools}

    return {
        "instructions": srv.instructions or "",
        "descriptions": asyncio.run(go()),
        "notes": "\n".join(server._status_payload()["notes"]),
        "refusal": offers_mod.upgrade_message("witness_pin"),
    }


def test_mcp_surfaces_carry_the_link_when_live(live, monkeypatch, tmp_path):
    t = _mcp_texts(monkeypatch, tmp_path)
    assert t["instructions"].count(URL) == 1
    assert t["notes"].count(URL) == 1
    assert t["refusal"].count(URL) == 1


def test_mcp_surfaces_say_nothing_of_registration_when_dark(dark, monkeypatch, tmp_path):
    t = _mcp_texts(monkeypatch, tmp_path)
    for name in ("instructions", "notes", "refusal"):
        _no_regist(t[name])
    for name in ("witness_pin", "witness_renew"):
        _no_regist(t["descriptions"][name])
    assert "500 credits, one time, per verified email" in t["refusal"]
