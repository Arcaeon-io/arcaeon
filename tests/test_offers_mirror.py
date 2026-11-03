"""The package carries no copy of the price catalog and no payment link.

The one place of record is https://arcaeon.io/.well-known/offers.json, read
live by `arcaeon buy`. A bundled copy quoted links after the site retired them,
so there is none, and these tests keep it that way.
"""
import re
from pathlib import Path

from arcaeon.remote import offers

SRC = Path(offers.__file__).resolve().parents[1]


def test_no_bundled_catalog():
    assert not Path(offers.__file__).with_name("offers.json").exists()
    assert list(SRC.rglob("offers.json")) == []


def test_no_payment_link_anywhere_in_the_package():
    hits = []
    for f in SRC.rglob("*"):
        if f.is_file() and f.suffix in {".py", ".json", ".md", ".txt", ".html", ".js", ".toml"}:
            if "buy.stripe.com/" in f.read_text(encoding="utf-8", errors="replace").replace(
                    "buy.stripe.com/test", ""):
                hits.append(str(f.relative_to(SRC)))
    assert hits == []


def test_upgrade_message_names_no_price_and_no_link():
    msg = offers.upgrade_message("witness_pin")
    assert offers.KEY_SENTENCES in msg
    assert "ARCAEON_KEY" in msg
    assert "http" not in msg and "server's environment" not in msg
    assert "$" not in msg and "buy.stripe.com" not in msg
    assert not re.search(r"\bcredits?\b", msg)
    assert not hasattr(offers, "MINI_PACK")
    assert not hasattr(offers, "REGISTRATION_GRANT")
    msg.encode("ascii")
