# SPDX-License-Identifier: MIT
"""arcaeon.client: a stdlib Python client for `arcaeon serve` (K016).

    from arcaeon.client import Client
    c = Client()                       # reads serve.json and serve.token
    r = c.verify(ledger="calls.jsonl")
    r["verdict"], r["exit"]            # "VERIFIED", 0

`Client(url=None, token=None)`: with no url it reads the url from
<ARCAEON_HOME or ~/.arcaeon>/serve.json (written by a running `arcaeon
serve`); with no token it reads serve.token beside it. It never creates a
token: a missing one simply goes unsent, and the server answers 401.

One method per route (ROUTE_METHODS below). Each takes the request body as
a dict, as keyword fields, or both (keywords win), and returns the server's
JSON as a dict. Verdicts come back as dicts, never as exceptions.

NEVER A PASS BY ACCIDENT. A server that cannot be reached (no serve.json,
a refused connection, a timeout, a reset) is COULD NOT LOOK, exit 3, with
`reason_word: "network"`. A reply that is not JSON is COULD NOT LOOK with
`reason_word: "unreadable"`. A refusal the server sent (400, 401, 404, 405,
413) comes back as its body plus `http_status`, and always carries a
non-zero `exit` (2, bad usage, when the body names none), so no branch on
`exit == 0` can read a refused call as a pass.

THE TOKEN NEVER LEAVES LOOPBACK (K016R). The serve token read from the home
directory goes only to a loopback host (127.0.0.1 or any 127.x, ::1,
localhost). To any other host the client sends no token unless the caller
passed `token=` itself, and it refuses a plain http:// url to a non-loopback
host outright (exit 2, `reason_word: "insecure"`, nothing sent) unless
`allow_insecure=True` is passed. Stdlib only.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

__all__ = ["Client", "ROUTE_METHODS", "DEFAULT_TIMEOUT"]

COULD_NOT_LOOK = "COULD NOT LOOK"
EXIT_USAGE = 2
EXIT_COULD_NOT_LOOK = 3
DEFAULT_TIMEOUT = 60.0
SERVE_JSON = "serve.json"
TOKEN_FILE = "serve.token"

#: Client method name -> (HTTP method, route path). The dashboard (GET /) is
#: a page for a browser, not a call, and has no method.
ROUTE_METHODS: dict[str, tuple[str, str]] = {
    "health": ("GET", "/health"),
    "openapi": ("GET", "/openapi.json"),
    "log": ("POST", "/v1/log"),
    "verify": ("POST", "/v1/verify"),
    "reconcile": ("POST", "/v1/reconcile"),
    "audit_verify": ("POST", "/v1/audit/verify"),
    "audit_export": ("POST", "/v1/audit/export"),
    "receipt_verify": ("POST", "/v1/receipt/verify"),
    "status": ("GET", "/v1/status"),
    "pin": ("POST", "/v1/pin"),
    "seal": ("POST", "/v1/seal"),
    "evidence_pack": ("POST", "/v1/evidence-pack"),
    "evidence_pack_verify": ("POST", "/v1/evidence-pack/verify"),
    "export_aat": ("POST", "/v1/export/aat"),
    "mandate_check": ("POST", "/v1/mandate/check"),
    "readings": ("POST", "/v1/readings"),
    "second_read_compare": ("POST", "/v1/second-read/compare"),
    "handshake_propose": ("POST", "/v1/handshake/propose"),
    "handshake_accept": ("POST", "/v1/handshake/accept"),
    "handshake_verify": ("POST", "/v1/handshake/verify"),
}


def _home() -> Path:
    override = os.environ.get("ARCAEON_HOME", "").strip()
    return Path(override) if override else Path.home() / ".arcaeon"


def _read_url() -> str | None:
    try:
        url = json.loads((_home() / SERVE_JSON).read_text(encoding="utf-8")).get("url")
    except (OSError, ValueError, AttributeError):
        return None
    return url if isinstance(url, str) and url else None


def _read_token() -> str | None:
    try:
        t = (_home() / TOKEN_FILE).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return t or None


def is_loopback(host: str | None) -> bool:
    """True for localhost, 127.0.0.0/8 and ::1."""
    if not host:
        return False
    if host.lower().rstrip(".") == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _could_not_look(where, reason_word: str, reason: str) -> dict:
    return {"verdict": COULD_NOT_LOOK, "exit": EXIT_COULD_NOT_LOOK,
            "looked_for": "an arcaeon serve answer", "where": where,
            "reason_word": reason_word, "reason": reason}


class Client:
    """A caller for one `arcaeon serve`. Every method returns a dict."""

    def __init__(self, url: str | None = None, token: str | None = None,
                 timeout: float = DEFAULT_TIMEOUT, allow_insecure: bool = False):
        self.url = (url or _read_url() or "").rstrip("/") or None
        self._token_given = token is not None
        self.token = token if token is not None else _read_token()
        self.timeout = timeout
        self.allow_insecure = bool(allow_insecure)

    def __repr__(self) -> str:        # never the token
        return f"Client(url={self.url!r})"

    def call(self, method: str, path: str, body: dict | None = None) -> dict:
        """One request. The answer as a dict; see the module doc for the rules."""
        if not self.url:
            return _could_not_look(None, "network",
                                   "no server found: serve.json is absent (start "
                                   "`arcaeon serve`, or pass url=)")
        where = self.url + path
        parts = urlsplit(self.url)
        if parts.scheme != "http" or not parts.hostname:
            return _could_not_look(where, "network",
                                   f"not an http:// server url: {self.url!r}")
        loopback = is_loopback(parts.hostname)
        if not loopback and not self.allow_insecure:
            return {"error": f"refusing plain http:// to a non-loopback host "
                             f"{parts.hostname!r}: pass allow_insecure=True to send anyway",
                    "exit": EXIT_USAGE, "reason_word": "insecure", "where": where}
        headers = {"Accept": "application/json"}
        data = None
        if method != "GET":
            data = json.dumps(body or {}, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.token and (loopback or self._token_given):
            headers["Authorization"] = f"Bearer {self.token}"
        conn = http.client.HTTPConnection(parts.hostname, parts.port or 80,
                                          timeout=self.timeout)
        try:
            conn.request(method, (parts.path or "") + path, body=data, headers=headers)
            resp = conn.getresponse()
            status, raw = resp.status, resp.read()
        except (OSError, http.client.HTTPException) as e:
            return _could_not_look(where, "network",
                                   f"could not reach the server ({type(e).__name__})")
        finally:
            conn.close()
        try:
            out = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            out = None
        if not isinstance(out, dict):
            return _could_not_look(where, "unreadable",
                                   f"the server's answer (HTTP {status}) is not a JSON object")
        if status != 200:
            out["http_status"] = status
            if not isinstance(out.get("exit"), int) or out["exit"] == 0:
                out["exit"] = EXIT_USAGE
        return out

    def _route(self, name: str, body: dict | None, fields: dict) -> dict:
        method, path = ROUTE_METHODS[name]
        merged = {**(body or {}), **fields}
        return self.call(method, path, merged if method == "POST" else None)


def _make(name: str):
    method, path = ROUTE_METHODS[name]

    def fn(self, body: dict | None = None, **fields) -> dict:
        return self._route(name, body, fields)

    fn.__name__ = name
    fn.__qualname__ = f"Client.{name}"
    fn.__doc__ = f"{method} {path}"
    return fn


for _name in ROUTE_METHODS:
    setattr(Client, _name, _make(_name))
del _name
