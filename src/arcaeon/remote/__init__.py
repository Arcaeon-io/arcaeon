# SPDX-License-Identifier: MIT
"""arcaeon.remote: the hosted pieces, reached over HTTPS, only when asked.

The hosted witness (witness.arcaeon.io) is Node.js on Vercel and stays there;
this module is the only part of `arcaeon` that talks to it. No network on
import: importing this module opens no socket, and every function below makes
exactly one request, when it is called.

One setting: ARCAEON_KEY (the witness key, a bearer credential; treat it like
a password). ARCAEON_WITNESS_URL overrides the endpoint for a self-hoster.

    pin(ns, rows, chain, key)       POST /api/pin      (was arcaeon_connector.witness)
    renew(ns, rows, chain, key)     POST /api/renew    (was arcaeon_connector.witness)
    balance(key)                    GET  /api/balance  read-only, consumes nothing
    stamp(sha256_hex, size, key)    POST /api/stamp    a file's hash, not its bytes
    latest(ns)                      GET  /api/latest   the newest public pin
    check_head(ns, rows, chain)     GET  /api/verify   does the witness hold this head
    reconcile_tapes(a, b)           POST /api/reconcile  the hosted two-tape verdict

Failure is DATA, never an exception: every function returns a dict with
`ok`, `status` (0 = the request never completed) and the server's own words.
The paid step lives on Stripe: `checkout_links()` reads the live catalog at
arcaeon.io/.well-known/offers.json (arcaeon.remote.catalog: one GET, 3 s,
1 MB, kept 10 minutes, never with ARCAEON_OFFERS_OFFLINE=1) and returns the
links it marks live; nothing here opens a browser or takes a card.

Also here, moved from the connector: `offers` (the upgrade message, which
names no price), `sealed_scan` (the paid mcp-vet seal) and `licensing` (the
optional, default-off license gate).
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .witness import BLANK_KEY_ERROR, DEFAULT_TIMEOUT, base_url, pin, renew

__all__ = ["pin", "renew", "balance", "stamp", "latest", "check_head", "reconcile_tapes",
           "key", "base_url", "load_offers", "checkout_links", "BLANK_KEY_ERROR"]

KEY_ENV = "ARCAEON_KEY"
OFFERS_ENV = "ARCAEON_OFFERS_FILE"


def key() -> str | None:
    """ARCAEON_KEY, with blank or whitespace read as unset."""
    return os.environ.get(KEY_ENV, "").strip() or None


def _request(method: str, url: str, body: dict | None = None, key: str | None = None,
             timeout: float = DEFAULT_TIMEOUT) -> tuple[int, dict]:
    """One HTTP request. Returns (status, payload); status 0 = never completed.

    Tests stub exactly this function, so "our code decided" and "the network
    happened" meet at one named seam."""
    headers = {"User-Agent": "arcaeon", "Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, _parse(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace") if e.fp else ""
        return e.code, _parse(raw)
    except (urllib.error.URLError, OSError) as e:
        return 0, {"error": f"witness unreachable: {getattr(e, 'reason', e)}"}


def _parse(raw: str) -> dict:
    if not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {"error": raw[:800]}
    return parsed if isinstance(parsed, dict) else {"result": parsed}


def _result(status: int, payload: dict, endpoint: str) -> dict:
    out = {"ok": 200 <= status < 300, "status": status, "endpoint": endpoint}
    out.update(payload)
    if not out["ok"] and "error" not in out:
        out["error"] = f"witness returned {status}"
    return out


def balance(key_: str | None = None) -> dict:
    """The key-holder's own balance: prepaid credits plus free-tier use this
    month. Read-only: looking never consumes a credit."""
    key_ = (key_ if key_ is not None else key()) or ""
    endpoint = base_url() + "/api/balance"
    if not key_.strip():
        return {"ok": False, "status": 0, "endpoint": endpoint, "error": BLANK_KEY_ERROR}
    return _result(*_request("GET", endpoint, key=key_), endpoint)


def stamp(sha256_hex: str, size: int | None = None, key_: str | None = None) -> dict:
    """Stamp a file's sha256 with the witness. The file's bytes never leave
    this machine; only the hash (and, if given, the size) is sent. A key is
    optional: without one the witness's free daily allowance applies."""
    endpoint = base_url() + "/api/stamp"
    body: dict[str, Any] = {"sha256": sha256_hex}
    if size is not None:
        body["size"] = size
    return _result(*_request("POST", endpoint, body, key=key_ if key_ is not None else key()),
                   endpoint)


def latest(namespace: str) -> dict:
    """The newest public pin for a namespace. No key: pins are public."""
    endpoint = base_url() + "/api/latest?" + urllib.parse.urlencode({"ns": namespace})
    return _result(*_request("GET", endpoint), endpoint)


def check_head(namespace: str, rows: int, chain: str) -> dict:
    """Ask the witness whether it holds this head. No key."""
    endpoint = base_url() + "/api/verify?" + urllib.parse.urlencode(
        {"ns": namespace, "rows": rows, "chain": chain})
    return _result(*_request("GET", endpoint), endpoint)


def reconcile_tapes(agent_tape: str, tool_tape: str) -> dict:
    """The hosted two-tape verdict. Sends both tapes' text; the service keeps
    neither (it returns their digests). Prefer the local `arcaeon reconcile`,
    which sends nothing anywhere."""
    endpoint = base_url() + "/api/reconcile"
    return _result(*_request("POST", endpoint, {"agent_tape": agent_tape, "tool_tape": tool_tape}),
                   endpoint)


def load_offers(path: str | os.PathLike | None = None) -> dict:
    """The price catalog: the file at `path`, else $ARCAEON_OFFERS_FILE, else the
    live arcaeon.io/.well-known/offers.json (arcaeon.remote.catalog.load).

    Raises ValueError when none of those yields a catalog of the right shape.
    The package carries no copy of its own."""
    from . import catalog

    named = path or os.environ.get(OFFERS_ENV)
    cat = catalog.load_file(named) if named else catalog.load()
    if cat is None:
        where = str(named) if named else catalog.CATALOG_URL
        raise ValueError(f"no price catalog could be read from {where}")
    return cat


def checkout_links(offers: dict | None = None) -> list[dict]:
    """Every tier the catalog marks live with an https buy.stripe.com link, in
    catalog order: [{"product", "plan", "price", "cap", "checkout"}]. Empty when
    the catalog cannot be read. Prints nothing, opens nothing."""
    from . import catalog

    if offers is None:
        try:
            offers = load_offers()
        except ValueError:
            return []
    return catalog.live_tiers(offers)
