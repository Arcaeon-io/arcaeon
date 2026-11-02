"""`arcaeon buy` reads the live price catalog, and only what it marks live.

The one fetch seam is arcaeon.remote.catalog._fetch; every test here stubs it,
so nothing leaves the machine. The suite runs with ARCAEON_OFFERS_OFFLINE=1
(root conftest); the fixture below clears it so the fetch path is exercised.
"""
import json
import time
import urllib.request
import webbrowser

import pytest

from arcaeon import cli
from arcaeon.remote import catalog

PRICING = "Prices and how to buy: https://arcaeon.io/pricing"


def _cat(tiers, description="pin your ledger head; the live service gives 100 free pins a month"):
    return {"schema": "arcaeon-offers/v1", "products": [
        {"id": "arcaeon", "price_usd": 0},
        {"id": "hosted-witness", "description": description, "tiers": tiers}]}


LIVE = [
    {"plan": "grant", "price_usd": 0, "credits": 500, "how": "registration (in the next release)"},
    {"plan": "pack-a", "price_usd": 7, "cap": "1,400 pins", "status": "live",
     "checkout": "https://buy.stripe.com/test_pack_a"},
    {"plan": "monthly", "price_usd_month": 11, "cap": "3,000 pins/month", "status": "live",
     "checkout": "https://buy.stripe.com/test_monthly"},
]


class Fetches:
    def __init__(self, body):
        self.body, self.calls = body, []

    def __call__(self, url=catalog.CATALOG_URL):
        self.calls.append(url)
        if isinstance(self.body, Exception):
            raise self.body
        return self.body


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.delenv(catalog.OFFLINE_ENV, raising=False)
    monkeypatch.delenv("ARCAEON_OFFERS_FILE", raising=False)
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(webbrowser, "open", lambda *a, **k: pytest.fail("opened a browser"))
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: pytest.fail("real network used; stub catalog._fetch"))
    catalog._memo.clear()
    yield
    catalog._memo.clear()


def _stub(monkeypatch, body):
    f = Fetches(json.dumps(body).encode() if isinstance(body, (dict, list)) else body)
    monkeypatch.setattr(catalog, "_fetch", f)
    return f


def _buy(capsys, *args):
    code = cli.main(["buy", *args])
    return code, capsys.readouterr().out


def test_live_packs_are_printed_with_the_free_line(monkeypatch, capsys):
    f = _stub(monkeypatch, _cat(LIVE))
    code, out = _buy(capsys)
    assert code == 0
    assert f.calls == [catalog.CATALOG_URL]
    lines = out.splitlines()
    assert lines[0] == "Free: 100 pins a month on the hosted witness."
    assert "https://buy.stripe.com/test_pack_a" in lines[1] and "$7" in lines[1]
    assert "https://buy.stripe.com/test_monthly" in lines[2] and "$11/month" in lines[2]
    assert lines[-1] == PRICING
    assert "grant" not in out and "500" not in out
    out.encode("ascii")


def test_one_plan_prints_its_link_only(monkeypatch, capsys):
    _stub(monkeypatch, _cat(LIVE))
    assert _buy(capsys, "pack-a") == (0, "https://buy.stripe.com/test_pack_a\n")


def test_retired_tiers_are_not_printed(monkeypatch, capsys):
    tiers = [
        {"plan": "old", "price_usd": 5, "status": "retired",
         "checkout": "https://buy.stripe.com/test_retired"},
        {"plan": "nostatus", "price_usd_month": 9, "checkout": "https://buy.stripe.com/test_nostatus"},
        {"plan": "soon", "price_usd": 15, "status": "in the next release",
         "checkout": "https://buy.stripe.com/test_soon"},
        LIVE[1],
    ]
    _stub(monkeypatch, _cat(tiers))
    code, out = _buy(capsys)
    assert code == 0
    for gone in ("test_retired", "test_nostatus", "test_soon", "old ", "nostatus", "soon"):
        assert gone not in out
    assert "test_pack_a" in out
    assert _buy(capsys, "old")[0] == 2


def test_null_checkouts_are_not_printed(monkeypatch, capsys):
    tiers = [{"plan": "a", "price_usd": 5, "status": "live", "checkout": None},
             {"plan": "b", "price_usd": 5, "status": "live"},
             {"plan": "c", "price_usd": 5, "status": "live", "checkout": ""}]
    _stub(monkeypatch, _cat(tiers, description="no free line here"))
    assert _buy(capsys) == (0, PRICING + "\n")


@pytest.mark.parametrize("link", [
    "http://buy.stripe.com/test_plain_http",
    "https://evil.example/buy.stripe.com/x",
    "https://buy.stripe.com.evil.example/x",
    "https://user@buy.stripe.com/x",
    "https://buy.stripe.com:8443/x",
    "https://checkout.stripe.com/x",
    "https://buy.stripe.com/",
    "https://buy.stripe.com",
    " https://buy.stripe.com/x",
    "javascript:alert(1)",
    42,
    ["https://buy.stripe.com/x"],
])
def test_bad_links_are_not_printed(monkeypatch, capsys, link):
    _stub(monkeypatch, _cat([{"plan": "x", "price_usd": 5, "status": "live", "checkout": link}],
                            description="nothing free"))
    assert _buy(capsys) == (0, PRICING + "\n")


@pytest.mark.parametrize("failure", [
    None,                           # _fetch's own answer for timeouts, errors, non-200
    OSError("connection refused"),  # the real _fetch, with urlopen failing underneath
    TimeoutError("timed out"),
])
def test_fetch_failure_prints_only_the_pricing_line(monkeypatch, capsys, failure):
    if isinstance(failure, Exception):
        def boom(*a, **k):
            raise failure
        monkeypatch.setattr(urllib.request, "urlopen", boom)
    else:
        _stub(monkeypatch, failure)
    assert _buy(capsys) == (0, PRICING + "\n")
    assert _buy(capsys, "pack-a") == (0, PRICING + "\n")


def test_fetch_uses_the_timeout_and_the_size_cap(monkeypatch):
    seen = {}

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=-1):
            seen["read"] = n
            return b"x" * (catalog.MAX_BYTES + 1)

    def fake_urlopen(req, timeout=None):
        seen.update(url=req.full_url, timeout=timeout)
        return Resp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert catalog._fetch() is None  # over 1 MB: refused
    assert seen == {"url": "https://arcaeon.io/.well-known/offers.json", "timeout": 3.0,
                    "read": 1024 * 1024 + 1}


@pytest.mark.parametrize("body", [
    b"not json",
    b"",
    b"\xff\xfe",
    json.dumps([1, 2, 3]).encode(),
    json.dumps({"products": "mini"}).encode(),
    json.dumps({"products": ["mini"]}).encode(),
    json.dumps({"tiers": LIVE}).encode(),
])
def test_wrong_shaped_catalog_prints_only_the_pricing_line(monkeypatch, capsys, body):
    _stub(monkeypatch, body)
    assert _buy(capsys) == (0, PRICING + "\n")
    # and a bad answer is never kept
    assert not (catalog._cache_path()).exists()


def test_wrong_shaped_tiers_are_skipped_not_fatal(monkeypatch, capsys):
    _stub(monkeypatch, _cat(["mini", None, {"status": "live", "checkout":
                                            "https://buy.stripe.com/test_noplan"}, LIVE[1]]))
    code, out = _buy(capsys)
    assert code == 0 and "test_noplan" not in out and "test_pack_a" in out


def test_the_opt_out_makes_no_request(monkeypatch, capsys):
    monkeypatch.setenv(catalog.OFFLINE_ENV, "1")
    monkeypatch.setattr(catalog, "_fetch", lambda *a, **k: pytest.fail("fetched while offline"))
    assert _buy(capsys) == (0, PRICING + "\n")
    assert _buy(capsys, "pack-a") == (0, PRICING + "\n")


def test_a_good_result_is_kept_ten_minutes(monkeypatch, capsys):
    f = _stub(monkeypatch, _cat(LIVE))
    clock = [1_000_000.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    assert "test_pack_a" in _buy(capsys)[1]
    assert "test_pack_a" in _buy(capsys)[1]
    catalog._memo.clear()  # a new process: the disk copy answers
    clock[0] += 599
    assert "test_pack_a" in _buy(capsys)[1]
    assert len(f.calls) == 1
    clock[0] += 2  # past ten minutes
    catalog._memo.clear()
    f.body = json.dumps(_cat([LIVE[2]])).encode()
    out = _buy(capsys)[1]
    assert len(f.calls) == 2
    assert "test_pack_a" not in out and "test_monthly" in out


def test_a_failure_is_not_kept(monkeypatch, capsys):
    f = _stub(monkeypatch, None)
    assert _buy(capsys)[1] == PRICING + "\n"
    f.body = json.dumps(_cat(LIVE)).encode()
    assert "test_pack_a" in _buy(capsys)[1]
    assert len(f.calls) == 2


def test_the_opt_out_wins_over_a_kept_result(monkeypatch, capsys):
    _stub(monkeypatch, _cat(LIVE))
    assert "test_pack_a" in _buy(capsys)[1]
    monkeypatch.setenv(catalog.OFFLINE_ENV, "1")
    assert _buy(capsys) == (0, PRICING + "\n")


def test_free_line_reads_a_structured_field_first(monkeypatch, capsys):
    cat = _cat([], description="nothing here")
    cat["products"][1]["free_pins_per_month"] = 250
    _stub(monkeypatch, cat)
    assert _buy(capsys)[1].splitlines() == ["Free: 250 pins a month on the hosted witness.", PRICING]


def test_no_free_line_when_the_catalog_states_none(monkeypatch, capsys):
    _stub(monkeypatch, _cat([LIVE[1]], description="no allowance stated"))
    out = _buy(capsys)[1]
    assert "Free" not in out and "test_pack_a" in out


def test_a_catalog_file_follows_the_same_rules(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(catalog, "_fetch", lambda *a, **k: pytest.fail("fetched with --offers"))
    f = tmp_path / "offers.json"
    f.write_text(json.dumps(_cat([{**LIVE[1], "status": "retired"}, LIVE[2]])), encoding="utf-8")
    out = _buy(capsys, "--offers", str(f))[1]
    assert "test_pack_a" not in out and "test_monthly" in out
    assert _buy(capsys, "--offers", str(tmp_path / "missing.json")) == (0, PRICING + "\n")


@pytest.mark.parametrize("value,shown", [(5, "$5"), (5.0, "$5"), (4.5, "$4.50"),
                                         (0.0042, "$0.0042"), (1500, "$1,500")])
def test_prices_are_shown_as_written(value, shown):
    assert catalog._money(value) == shown
