"""The front door: one object an agent reads first, and the same object on the CLI.

`arcaeon.mcp.front_door.front_door()` is what the `arcaeon_front_door` MCP tool
returns and what `arcaeon mcp --print-front-door` prints. Dark (the offers
document does not switch registration on) it carries no registration link and
not the substring "regist"; with a fixture offers.json that switches it on, it
carries the link. Its can and cannot list is held to the site page.
"""
import asyncio
import json
import os
import subprocess
import sys
import webbrowser
from html.parser import HTMLParser
from pathlib import Path

import pytest

from arcaeon import cli, remote
from arcaeon.mcp import front_door as fd
from arcaeon.mcp.front_door import CAN_AND_CANNOT, front_door

URL = "https://witness.arcaeon.io/register?from=test"


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.setattr(webbrowser, "open", lambda *a, **k: pytest.fail("opened a browser"))
    monkeypatch.setattr(remote, "_request", lambda *a, **k: pytest.fail("network used"))
    monkeypatch.delenv("ARCAEON_OFFERS_FILE", raising=False)
    monkeypatch.delenv("ARCAEON_KEY", raising=False)


def _cat(registration=None):
    cat = remote.load_offers()
    cat.pop("registration", None)
    if registration is not None:
        cat["registration"] = registration
    return cat


@pytest.fixture
def live(tmp_path, monkeypatch):
    f = tmp_path / "live.json"
    f.write_text(json.dumps(_cat({"enabled": True, "url": URL})), encoding="utf-8")
    monkeypatch.setenv("ARCAEON_OFFERS_FILE", str(f))
    return f


def _mini():
    for prod in remote.load_offers()["products"]:
        if prod.get("id") == "hosted-witness":
            return next(t for t in prod["tiers"] if t.get("plan") == "mini"), prod
    raise AssertionError("no hosted-witness in offers.json")


# --- dark (today) -------------------------------------------------------------

def test_dark_front_door_has_no_link_and_no_regist_substring():
    door = front_door()
    text = json.dumps(door)
    assert "regist" not in text.lower(), text
    assert URL not in text
    assert door["get_a_key"]["url"] == "https://arcaeon.io/pricing"


def test_dark_with_a_disabled_switch_is_still_dark():
    door = front_door(_cat({"enabled": False, "url": URL}))
    assert "regist" not in json.dumps(door).lower()
    assert door["get_a_key"]["url"] == "https://arcaeon.io/pricing"


def test_prices_and_grant_come_from_offers_json_and_carry_no_date():
    mini, witness = _mini()
    door = front_door()
    key = door["with_a_key"]
    assert key["price_per_pin_usd"] == mini["price_per_pin_usd"] == 0.005
    assert key["smallest_pack"]["checkout"] == mini["checkout"]
    assert witness["registration_grant"]["statement"] in key["grant"]
    assert key["tools"] == ["witness_pin", "witness_renew"]
    assert door["offers_url"] == "https://arcaeon.io/.well-known/offers.json"
    text = json.dumps(door)
    import re
    assert not re.search(r"\b20\d\d-\d\d-\d\d\b", text), "a date in the front door"
    assert not re.search(r"\b\d{1,2}/\d{1,2}\b", text), "a date in the front door"
    text.encode("ascii")


def test_a_changed_price_in_offers_json_shows_up():
    cat = _cat()
    for prod in cat["products"]:
        if prod.get("id") == "hosted-witness":
            for t in prod["tiers"]:
                if t.get("plan") == "mini":
                    t["price_per_pin_usd"] = 0.007
    assert front_door(cat)["with_a_key"]["price_per_pin_usd"] == 0.007


def test_the_no_key_groups_are_exactly_the_free_tools():
    pytest.importorskip("arcaeon.mcp.server")
    from arcaeon.mcp.server import FREE_TOOLS, PAID_TOOLS
    grouped = [t for g in fd.NO_KEY_GROUPS.values() for t in g["tools"]]
    assert len(grouped) == len(set(grouped)), grouped
    assert sorted(grouped) == sorted(FREE_TOOLS)
    assert list(PAID_TOOLS) == fd.KEY_TOOLS
    for name in ("record", "verify", "evidence_pack", "second_reader"):
        assert front_door()["no_key"][name]["tools"]


# --- live (fixture offers.json switches it on) --------------------------------

def test_live_front_door_carries_the_link(live):
    door = front_door()
    assert door["get_a_key"]["url"] == URL
    assert URL in door["get_a_key"]["how"]
    rest = {k: v for k, v in door.items() if k != "get_a_key"}
    assert URL not in json.dumps(rest)


# --- the can and cannot list, held to the site page -----------------------------

class _SiteList(HTMLParser):
    """The #cannot and #can sections of the site page: h3 headings and li text."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.section = None
        self.cannot, self.can = [], []
        self._li = self._h3 = None

    def handle_starttag(self, tag, attrs):
        if tag == "section":
            self.section = dict(attrs).get("id")
        if self.section in ("cannot", "can"):
            if tag == "li":
                self._li = []
            elif tag == "h3":
                self._h3 = []

    def handle_endtag(self, tag):
        if tag == "section":
            self.section = None
        elif tag == "li" and self._li is not None:
            text, self._li = "".join(self._li), None
            if self.section == "can":
                self.can.append(text)
            else:
                self.cannot[-1]["items"].append(text)
        elif tag == "h3" and self._h3 is not None:
            self.cannot.append({"heading": "".join(self._h3), "items": []})
            self._h3 = None

    def handle_data(self, data):
        if self._li is not None:
            self._li.append(data)
        if self._h3 is not None:
            self._h3.append(data)


def _first_difference(ours, site):
    a = [(s["heading"], None) for s in ours["cannot"]] + [
        (s["heading"], i) for s in ours["cannot"] for i in s["items"]] + [("can", i) for i in ours["can"]]
    b = [(s["heading"], None) for s in site["cannot"]] + [
        (s["heading"], i) for s in site["cannot"] for i in s["items"]] + [("can", i) for i in site["can"]]
    for n, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return f"entry {n}: package has {x!r}, site has {y!r}"
    if len(a) != len(b):
        return f"package has {len(a)} entries, site has {len(b)}"
    return None


def test_can_and_cannot_matches_the_site_page():
    raw = os.environ.get("ARCAEON_SITE_CAN_AND_CANNOT")
    if not raw and os.environ.get("ARCAEON_SITE_ROOT"):
        raw = str(Path(os.environ["ARCAEON_SITE_ROOT"]) / "can-and-cannot.html")
    if not raw:
        pytest.skip("neither ARCAEON_SITE_CAN_AND_CANNOT nor ARCAEON_SITE_ROOT is set; "
                    "no site page to compare")
    page = Path(raw)
    if not page.is_file():
        pytest.skip("ARCAEON_SITE_CAN_AND_CANNOT does not name a file")
    p = _SiteList()
    p.feed(page.read_text(encoding="utf-8"))
    site = {"cannot": p.cannot, "can": p.can}
    assert site["cannot"] and site["can"], "found no list on the site page"
    diff = _first_difference(CAN_AND_CANNOT, site)
    assert diff is None, diff
    assert front_door()["can_and_cannot"]["cannot"] == site["cannot"]
    assert front_door()["can_and_cannot"]["can"] == site["can"]


def test_the_difference_is_named():
    changed = json.loads(json.dumps(CAN_AND_CANNOT))
    changed["can"][1] = "something else"
    msg = _first_difference(CAN_AND_CANNOT, changed)
    assert msg and "something else" in msg


# --- the instructions -------------------------------------------------------------

def test_instructions_are_three_short_paragraphs_with_no_dashes_or_marketing():
    pytest.importorskip("arcaeon.mcp.server")
    from arcaeon.mcp.server import INSTRUCTIONS
    paras = INSTRUCTIONS.split("\n\n")
    assert len(paras) == 3, paras
    assert all(len(p) < 600 for p in paras)
    assert "arcaeon_front_door" in paras[0]
    for dash in ("-", chr(0x2013), chr(0x2014)):
        assert dash not in INSTRUCTIONS, dash
    low = INSTRUCTIONS.lower()
    for word in ("powerful", "seamless", "effortless", "revolutionary", "best", "ultimate",
                 "cutting edge", "unlock", "supercharge", "world class", "!"):
        assert word not in low, word
    INSTRUCTIONS.encode("ascii")


# --- the MCP tool ------------------------------------------------------------------

def _server_env(monkeypatch, tmp_path):
    pytest.importorskip("mcp", reason="the connector IS an MCP server")
    monkeypatch.setenv("ARCAEON_LEDGER_LOG", str(tmp_path / "agent.log.jsonl"))
    monkeypatch.setenv("ARCAEON_LEDGER_NS_DIR", str(tmp_path / "ledgers"))
    monkeypatch.setenv("ARCAEON_CALL_RECORD", str(tmp_path / "calls.jsonl"))


def _call_tool():
    from mcp import Client
    from arcaeon.mcp.server import build_server

    async def go():
        async with Client(build_server()) as client:
            names = {t.name for t in (await client.list_tools()).tools}
            res = await client.call_tool("arcaeon_front_door", {})
            return names, res

    return asyncio.run(go())


def _payload(res):
    sc = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
    if isinstance(sc, dict):
        return sc.get("result", sc) if set(sc) == {"result"} else sc
    return json.loads(res.content[0].text)


def test_the_mcp_tool_returns_the_front_door(monkeypatch, tmp_path):
    _server_env(monkeypatch, tmp_path)
    names, res = _call_tool()
    assert "arcaeon_front_door" in names
    assert _payload(res) == front_door()


def test_the_mcp_instructions_start_at_the_door(monkeypatch, tmp_path):
    _server_env(monkeypatch, tmp_path)
    from arcaeon.mcp.server import build_server
    instr = build_server().instructions
    assert instr.startswith("Start with arcaeon_front_door.")
    assert "regist" not in instr.lower()


def test_the_mcp_tool_carries_the_link_when_live(live, monkeypatch, tmp_path):
    _server_env(monkeypatch, tmp_path)
    _, res = _call_tool()
    assert _payload(res)["get_a_key"]["url"] == URL


# --- the CLI print -----------------------------------------------------------------

def test_cli_print_front_door_in_process(capsys):
    assert cli.main(["mcp", "--print-front-door"]) == 0
    assert json.loads(capsys.readouterr().out) == front_door()


def test_cli_print_front_door_subprocess(tmp_path):
    env = dict(os.environ)
    env.pop("ARCAEON_OFFERS_FILE", None)
    env.pop("ARCAEON_KEY", None)
    env["ARCAEON_LEDGER_LOG"] = str(tmp_path / "agent.log.jsonl")
    p = subprocess.run([sys.executable, "-m", "arcaeon", "mcp", "--print-front-door"],
                       capture_output=True, text=True, env=env, timeout=120)
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout)
    assert out == front_door()
    assert "regist" not in p.stdout.lower()


def test_cli_print_front_door_with_live_offers(live, capsys):
    assert cli.main(["mcp", "--print-front-door"]) == 0
    assert json.loads(capsys.readouterr().out)["get_a_key"]["url"] == URL
