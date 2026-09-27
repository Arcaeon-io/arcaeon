"""K128: `arcaeon buy evidence-pack` prints the offer and the credit-pack link
read from offers.json, and opens nothing."""
import datetime
import json
import webbrowser

import pytest

from arcaeon import cli, remote
from arcaeon.remote import offers as offers_mod


@pytest.fixture(autouse=True)
def _no_browser_no_network(monkeypatch):
    monkeypatch.setattr(webbrowser, "open", lambda *a, **k: pytest.fail("opened a browser"))
    monkeypatch.setattr(webbrowser, "open_new_tab", lambda *a, **k: pytest.fail("opened a browser"))
    monkeypatch.setattr(remote, "_request", lambda *a, **k: pytest.fail("network used"))


def _mini_link(cat):
    for p in cat["products"]:
        for t in p.get("tiers", []) or []:
            if t.get("plan") == "mini":
                return t["checkout"]
    raise AssertionError("no mini tier")


def test_buy_evidence_pack_prints_the_link_from_offers_json(capsys):
    assert cli.main(["buy", "evidence-pack"]) == 0
    out = capsys.readouterr().out
    cat = remote.load_offers()
    assert _mini_link(cat) in out
    assert "arcaeon-evidence-pack" in out
    assert "50 credits" in out
    assert "nothing was opened and nothing was charged" in out
    assert "free forever" in out
    out.encode("ascii")  # printed to a terminal: ASCII only


def test_the_link_comes_from_the_offers_file_it_was_handed(tmp_path, capsys):
    cat = remote.load_offers()
    for p in cat["products"]:
        for t in p.get("tiers", []) or []:
            if t.get("plan") == "mini":
                t["checkout"] = "https://buy.stripe.com/test_from_this_file"
    f = tmp_path / "offers.json"
    f.write_text(json.dumps(cat), encoding="utf-8")
    assert cli.main(["buy", "evidence-pack", "--offers", str(f)]) == 0
    assert "https://buy.stripe.com/test_from_this_file" in capsys.readouterr().out


def test_no_calendar_window_the_registration_grant_instead():
    """K125b: the price is the same on any date, and the grant is shown."""
    cat = remote.load_offers()
    before = "\n".join(offers_mod.evidence_pack_lines(cat, today=datetime.date(2026, 10, 31)))
    after = "\n".join(offers_mod.evidence_pack_lines(cat, today=datetime.date(2026, 11, 1)))
    assert before == after
    assert "free through" not in before
    assert "nothing to buy" not in before
    assert "50 credits ($0.25 at the mini rate)" in before
    hw = next(p for p in cat["products"] if p.get("id") == "hosted-witness")
    assert f"every new key: {hw['registration_grant']['statement']}." in before


def test_no_entry_is_a_usage_error_not_a_made_up_price(tmp_path, capsys):
    cat = remote.load_offers()
    cat["products"] = [p for p in cat["products"] if p.get("id") != "arcaeon-evidence-pack"]
    f = tmp_path / "offers.json"
    f.write_text(json.dumps(cat), encoding="utf-8")
    code = cli.main(["buy", "evidence-pack", "--offers", str(f)])
    assert code != 0
    captured = capsys.readouterr()
    assert "credits" not in captured.out
