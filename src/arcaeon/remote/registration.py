"""The witness registration link: one source of truth, one switch.

Registration for the hosted witness is built but DARK (it answers 501 until
its mail and store exist). When it goes live, the link has to appear on every
surface at once: `arcaeon buy`, `arcaeon --help`, the MCP server's
instructions, status notes and keyless refusal. So no surface types the URL.
Each one asks `registration_link()` and prints the one sentence from
`registration_line()` when it is not None, and says nothing about registration
at all when it is None.

THE SWITCH is the offers document itself: a top-level object

    "registration": {"enabled": true, "url": "https://..."}

in the site's `.well-known/offers.json`, copied byte for byte into the bundled
snapshot (tests/test_offers_mirror.py holds the copy to the site). Anything
short of `enabled` being literally true and `url` an https URL reads as dark:
a missing object, `enabled: false`, a string "true", an empty or http URL, an
unreadable file. The document read is the one handed in, else
`$ARCAEON_OFFERS_FILE`, else the bundled snapshot (`arcaeon.remote.load_offers`).
Nothing here opens a connection.
"""
from __future__ import annotations

from typing import Any

__all__ = ["registration_link", "registration_line"]


def _offers(offers: dict | None) -> Any:
    if offers is not None:
        return offers
    from arcaeon.remote import load_offers
    try:
        return load_offers()
    except (OSError, ValueError):
        return None


def registration_link(offers: dict | None = None) -> str | None:
    """The registration URL when the offers document switches it on, else None."""
    doc = _offers(offers)
    if not isinstance(doc, dict):
        return None
    reg = doc.get("registration")
    if not isinstance(reg, dict) or reg.get("enabled") is not True:
        return None
    url = reg.get("url")
    if not isinstance(url, str):
        return None
    url = url.strip()
    if not url.startswith("https://") or len(url) <= len("https://") or any(c.isspace() for c in url):
        return None
    return url


def registration_line(offers: dict | None = None) -> str | None:
    """The one sentence every surface prints, ASCII only, or None when dark."""
    doc = _offers(offers)
    url = registration_link(doc)
    if url is None:
        return None
    statement = None
    for prod in doc.get("products", []) or []:
        if isinstance(prod, dict) and prod.get("id") == "hosted-witness":
            grant = prod.get("registration_grant")
            if isinstance(grant, dict) and isinstance(grant.get("statement"), str):
                statement = grant["statement"].strip()
    if statement:
        return f"Register for a witness key at {url}; every new key comes with {statement}."
    return f"Register for a witness key at {url}."
