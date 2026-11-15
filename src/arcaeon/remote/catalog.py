# SPDX-License-Identifier: MIT
"""The live price catalog, read only when `arcaeon buy` runs.

The one place of record for what Arcaeon sells is
https://arcaeon.io/.well-known/offers.json. This module reads it; the package
carries no copy and no payment link of its own, so a link retired on the site
is never printed from an old install.

Rules, all on purpose:

* One GET, 3 second timeout, at most 1 MB read. Nothing on import.
* A good result is kept for 10 minutes (in memory, and in
  <ARCAEON_HOME or ~/.arcaeon>/offers-cache.json so a second `buy` within
  the window makes no request). A bad result is never kept.
* Only tiers marked `"status": "live"` whose checkout link is https on
  buy.stripe.com are shown. Anything else in the catalog is not printed.
* On any failure, or when ARCAEON_OFFERS_OFFLINE=1, the only thing printed is
  FALLBACK_LINE. No price is ever made up or remembered past the cache.
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path

CATALOG_URL = "https://arcaeon.io/.well-known/offers.json"
PRICING_URL = "https://arcaeon.io/pricing"
FALLBACK_LINE = f"Prices and how to buy: {PRICING_URL}"

OFFLINE_ENV = "ARCAEON_OFFERS_OFFLINE"
TIMEOUT_S = 3.0
MAX_BYTES = 1024 * 1024
TTL_S = 600.0
CHECKOUT_HOST = "buy.stripe.com"
CACHE_NAME = "offers-cache.json"

_memo: dict = {}


def offline() -> bool:
    """True when ARCAEON_OFFERS_OFFLINE is set to 1 (or true/yes/on)."""
    return os.environ.get(OFFLINE_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def _get(url: str, out: list) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "arcaeon",
                                               "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            if getattr(resp, "status", 200) != 200:
                return
            out.append(resp.read(MAX_BYTES + 1))
    except Exception:  # noqa: BLE001 - every failure means "print the pricing line"
        return


def _fetch(url: str = CATALOG_URL) -> bytes | None:
    """One GET of the catalog. Returns the body, or None on any failure, when
    the body is larger than MAX_BYTES, or when the whole request (name lookup,
    proxy, TLS, headers and body together) takes longer than TIMEOUT_S.

    urllib's own timeout applies to each socket step, so a server sending one
    byte at a time could hold it far past TIMEOUT_S; the request runs on a
    daemon thread and is abandoned at the deadline. Tests stub exactly this."""
    import threading

    out: list = []
    t = threading.Thread(target=_get, args=(url, out), daemon=True,
                         name="arcaeon-offers-fetch")
    t.start()
    t.join(TIMEOUT_S)
    if t.is_alive() or not out:
        return None
    body = out[0]
    if len(body) > MAX_BYTES:
        return None
    return body


def well_shaped(cat) -> bool:
    """A catalog worth reading: an object whose `products` is a list of objects."""
    return (isinstance(cat, dict) and isinstance(cat.get("products"), list)
            and all(isinstance(p, dict) for p in cat["products"]))


def parse(body: bytes | str | None) -> dict | None:
    """The catalog from raw bytes, or None when it is not JSON of the right shape."""
    if body is None:
        return None
    try:
        cat = json.loads(body)
    except (ValueError, UnicodeDecodeError, TypeError):
        return None
    return cat if well_shaped(cat) else None


def _cache_path() -> Path:
    home = os.environ.get("ARCAEON_HOME", "").strip()
    return (Path(home) if home else Path.home() / ".arcaeon") / CACHE_NAME


def _read_disk_cache(now: float) -> dict | None:
    try:
        raw = json.loads(_cache_path().read_text(encoding="utf-8"))
        at = float(raw["fetched_at"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not (0 <= now - at < TTL_S):
        return None
    cat = raw.get("catalog")
    return cat if well_shaped(cat) else None


def _write_disk_cache(cat: dict, now: float) -> None:
    p = _cache_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_text(json.dumps({"fetched_at": now, "source": CATALOG_URL,
                                   "catalog": cat}), encoding="utf-8")
        os.replace(tmp, p)
    except OSError:
        pass  # a cache that cannot be written only costs one more request


def clear_cache() -> None:
    """Forget any kept catalog, in memory and on disk."""
    _memo.clear()
    try:
        _cache_path().unlink()
    except OSError:
        pass


def load() -> dict | None:
    """The live catalog, or None (offline, unreachable, too big, wrong shape)."""
    if offline():
        return None
    now = time.time()
    if _memo and 0 <= now - _memo["at"] < TTL_S:
        return _memo["catalog"]
    cat = _read_disk_cache(now)
    if cat is None:
        cat = parse(_fetch(CATALOG_URL))
        if cat is None:
            return None
        _write_disk_cache(cat, now)
    _memo.update(at=now, catalog=cat)
    return cat


def load_file(path: str | os.PathLike) -> dict | None:
    """A catalog from a local file (for `arcaeon buy --offers FILE`), or None."""
    try:
        return parse(Path(path).read_bytes())
    except OSError:
        return None


def good_checkout(link) -> bool:
    """True only for an https link on buy.stripe.com, with no user, password or port."""
    if not isinstance(link, str) or link != link.strip():
        return False
    try:
        u = urllib.parse.urlsplit(link)
        port = u.port
    except ValueError:
        return False
    return (u.scheme == "https" and u.hostname == CHECKOUT_HOST and u.netloc == CHECKOUT_HOST
            and port is None and u.path not in ("", "/"))


def _number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0


def _money(v) -> str:
    if v == int(v):
        return f"${int(v):,}"
    return f"${v:,.2f}" if round(v, 2) == v else f"${v:g}"


def _text(v) -> str:
    """Catalog text, printable on any terminal: ASCII only, one line."""
    s = str(v).replace("—", "-").replace("–", "-")
    return " ".join(s.encode("ascii", "replace").decode("ascii").split())


def live_tiers(cat: dict | None) -> list[dict]:
    """Every tier marked live with a good checkout link, in catalog order:
    [{"product", "plan", "price", "cap", "checkout"}]."""
    out = []
    if not well_shaped(cat):
        return out
    for product in cat["products"]:
        tiers = product.get("tiers")
        if not isinstance(tiers, list):
            continue
        for tier in tiers:
            if not isinstance(tier, dict) or tier.get("status") != "live":
                continue
            plan, link = tier.get("plan"), tier.get("checkout")
            if not isinstance(plan, str) or not plan.strip() or not good_checkout(link):
                continue
            if _number(tier.get("price_usd_month")):
                price = f"{_money(tier['price_usd_month'])}/month"
            elif _number(tier.get("price_usd")):
                price = _money(tier["price_usd"])
            else:
                price = ""
            cap = tier.get("cap")
            out.append({"product": product.get("id"), "plan": _text(plan),
                        "price": price, "cap": _text(cap) if isinstance(cap, str) else "",
                        "checkout": link})
    return out


def free_pins_per_month(cat: dict | None) -> int | None:
    """The free pins a month the catalog states, or None when it states none.

    Read from a `free_pins_per_month` number on a product or a tier marked
    live (the structured field), else from the hosted witness description's
    own words "N free pins a month". Never assumed."""
    import re

    if not well_shaped(cat):
        return None
    for product in cat["products"]:
        n = product.get("free_pins_per_month")
        if _number(n) and int(n) == n and n > 0:
            return int(n)
        for tier in product.get("tiers") or []:
            if isinstance(tier, dict) and tier.get("status") == "live":
                n = tier.get("free_pins_per_month")
                if _number(n) and int(n) == n and n > 0:
                    return int(n)
    for product in cat["products"]:
        desc = product.get("description")
        if product.get("id") == "hosted-witness" and isinstance(desc, str):
            m = re.search(r"\b(\d[\d,]*) free pins a month\b", desc)
            if m:
                return int(m.group(1).replace(",", ""))
    return None


def buy_lines(cat: dict | None) -> list[str]:
    """What `arcaeon buy` prints. Plain ASCII. FALLBACK_LINE alone when the
    catalog could not be read or names nothing to buy and nothing free."""
    tiers = live_tiers(cat)
    free = free_pins_per_month(cat)
    if not tiers and free is None:
        return [FALLBACK_LINE]
    lines = []
    if free is not None:
        lines.append(f"Free: {free:,} pins a month on the hosted witness.")
    for t in tiers:
        lines.append(f"{t['plan']:<10} {t['price']:<10} {t['cap']:<24} {t['checkout']}".rstrip())
    lines.append(FALLBACK_LINE)
    return lines
