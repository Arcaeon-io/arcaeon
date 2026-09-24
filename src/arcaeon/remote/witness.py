"""The hosted witness's write endpoints, wrapped thin.

`POST /api/pin` and `POST /api/renew` are bearer-key HTTP. There is no Python
client to import, so this is the one place in the connector that speaks a
protocol rather than re-exporting a package — kept to stdlib urllib, kept to
one function, and kept honest about what it returns.

Failure is DATA here, not an exception: a 401, a 409 monotonic rejection, a 429
over-cap, an unreachable host — every one of them comes back as a dict with the
status and the server's own reason in it. A tool that raises on a 429 hands the
agent a stack trace where the agent needed the sentence "you are out of pins".

AUTH HONESTY, carried through from the witness's own README: this is bearer-key
auth (`auth_level: "bearer-stage0"`), not owner-signature auth. A leaked key can
pin and can renew in your name. Owner-signature auth is designed (STAGE1) and
not built. Treat ARCAEON_KEY like a password, not like an identity.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .offers import WITNESS_ENDPOINT

DEFAULT_TIMEOUT = 20.0


def base_url() -> str:
    """The witness to talk to. Overridable so a self-hoster (the library is free
    forever) can point the same tools at their own deployment."""
    return os.environ.get("ARCAEON_WITNESS_URL", WITNESS_ENDPOINT).rstrip("/")


def _http_post(url: str, body: dict, key: str, timeout: float = DEFAULT_TIMEOUT):
    """POST JSON with a bearer key. Returns (status, payload).

    Never raises for an HTTP-level failure: status 0 means the request did not
    complete at all, and the payload says why in words. Tests stub exactly this
    function, so the seam between "our gate let it through" and "the network
    happened" is one named thing.
    """
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "User-Agent": "arcaeon-connector",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return resp.status, _json_or_text(raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace") if e.fp else ""
        return e.code, _json_or_text(raw)
    except urllib.error.URLError as e:
        return 0, {"error": f"witness unreachable: {e.reason}"}
    except OSError as e:
        return 0, {"error": f"witness unreachable: {e}"}


def _json_or_text(raw: str) -> dict:
    if not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {"error": raw[:800]}
    return parsed if isinstance(parsed, dict) else {"result": parsed}


#: The refusal a blank credential gets here. Names the env var, because the
#: caller's next action is to set it.
BLANK_KEY_ERROR = (
    "refused before sending: no ARCAEON_KEY. The witness key was empty or "
    "whitespace, and an empty bearer token is a credential-shaped thing that is "
    "not a credential. Set ARCAEON_KEY=<your witness key> and call again."
)


def _write(path: str, namespace: str, rows: int, chain: str, key: str) -> dict:
    # SECOND GATE, on purpose (board item 39, 2026-09-05). `server._key()`
    # already turns an empty or whitespace-only ARCAEON_KEY into None and the
    # paid-lane handler refuses before it ever gets here, so through the MCP
    # server this branch is unreachable. It exists for the OTHER caller: this is
    # an importable module, and `witness.pin(ns, rows, chain, "")` called
    # straight from Python would otherwise put `Authorization: Bearer ` on the
    # wire and let the server decide what an unauthenticated caller is. The
    # guard sits at the layer that owns the credential rather than only at the
    # layer that owns the product decision. Returned as data, not raised, which
    # is this module's whole contract.
    if not (key or "").strip():
        return {"ok": False, "status": 0, "endpoint": base_url() + path,
                "error": BLANK_KEY_ERROR}
    status, payload = _http_post(
        f"{base_url()}{path}", {"namespace": namespace, "rows": rows, "chain": chain}, key)
    out = {"ok": status in (200, 201), "status": status, "endpoint": base_url() + path}
    out.update(payload if isinstance(payload, dict) else {"result": payload})
    if not out["ok"] and "error" not in out:
        # A non-2xx with no error text is still a refusal; say so rather than
        # letting `ok:false` sit next to a body that reads like a success.
        out["error"] = f"witness returned {status}"
    return out


def pin(namespace: str, rows: int, chain: str, key: str) -> dict:
    """Record this ledger head with the witness. 201 on a new pin."""
    return _write("/api/pin", namespace, rows, chain, key)


def renew(namespace: str, rows: int, chain: str, key: str) -> dict:
    """Restate an unchanged head so a finished log stops looking abandoned.
    `rows`/`chain` must match the current head exactly — the witness rejects a
    renewal that tries to advance one (409 renewal_head_mismatch)."""
    return _write("/api/renew", namespace, rows, chain, key)
