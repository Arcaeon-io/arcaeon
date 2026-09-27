# SPDX-License-Identifier: MIT
"""Token auth for `arcaeon serve` (K005).

The first run creates <ARCAEON_HOME or ~/.arcaeon>/serve.token holding
`secrets.token_urlsafe(32)`, created owner-only (mode 0600 where the OS
honors it; on Windows the file inherits the user profile's ACL, which is
already private to that user). Every later run reuses it, so a client
configured once keeps working across restarts.

A request carries it as `Authorization: Bearer <token>` or as
`X-Arcaeon-Token: <token>`. `/health` and `/openapi.json` stay open (the
route table's OPEN_PATHS). `arcaeon serve --print-token` prints it.

The token never reaches a log, the journal or an error body: the request log
carries only method, path and status; a 401 says which header to send and
never echoes what was sent; the comparison is constant-time.

Browser-origin guard (K108). A browser signed in to the dashboard carries a
session cookie, and a browser sends cookies wherever a page tells it to post.
So a POST the dashboard accepts on its cookie must carry `Origin` equal to
the origin the server answers on (`served_origins`: http://127.0.0.1:<port>
and http://localhost:<port>); a missing, `null` or other Origin is refused
with 403 before the form is read. SameSite=Strict already keeps the cookie
off cross-site posts; this is the second lock, and it holds in a browser that
ignores SameSite. A call carrying the bearer token (an agent) is not checked:
a web page cannot attach that header without the token, and agents send no
Origin.
"""
from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path

TOKEN_FILE = "serve.token"
HEADER = "X-Arcaeon-Token"

ORIGIN_REFUSED = ("this form did not come from this dashboard's own page, so it was not "
                  "read; open the page from `arcaeon open` and send it from there")

NO_TOKEN = ("no token: send `Authorization: Bearer <token>` or `X-Arcaeon-Token: <token>` "
            "(`arcaeon serve --print-token` shows it)")
WRONG_TOKEN = "wrong token"


def token_path() -> Path:
    from arcaeon import journal
    return journal.home() / TOKEN_FILE


def _read(p: Path) -> str | None:
    try:
        t = p.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return None
    return t or None


def _create(p: Path) -> str:
    """Write a fresh token, owner-only from the first byte (no chmod after)."""
    tok = secrets.token_urlsafe(32)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + f".{os.getpid()}.tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0),
                 0o600)
    try:
        os.write(fd, (tok + "\n").encode("ascii"))
    finally:
        os.close(fd)
    try:
        # Create-if-absent: if another process made a good one first, keep it.
        try:
            os.link(tmp, p)
        except FileExistsError:
            if _read(p) is None:            # empty or unreadable: replace it
                os.replace(tmp, p)
        except OSError:                     # no hard links here
            if _read(p) is None:
                os.replace(tmp, p)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
    return _read(p) or tok


def load_or_create() -> str:
    """The server's token, created on first run."""
    p = token_path()
    return _read(p) or _create(p)


def presented(headers) -> str | None:
    """The token a request carries, from either header, or None."""
    auth = (headers.get("Authorization") or "").strip()
    if auth[:7].lower() == "bearer " and auth[7:].strip():
        return auth[7:].strip()
    alt = (headers.get(HEADER) or "").strip()
    return alt or None


def check(token: str, headers) -> str | None:
    """None if the request carries `token`; else the 401 sentence to send."""
    got = presented(headers)
    if got is None:
        return NO_TOKEN
    if not hmac.compare_digest(got.encode("utf-8", "replace"), token.encode("utf-8")):
        return WRONG_TOKEN
    return None


def served_origins(port: int) -> frozenset[str]:
    """The origins a browser shows for this server's own pages."""
    return frozenset({f"http://127.0.0.1:{port}", f"http://localhost:{port}"})


def origin_ok(headers, port: int) -> bool:
    """True if the request's Origin is exactly one of this server's origins.
    A missing Origin, "null", a different scheme, host or port is False."""
    got = headers.get("Origin")
    if got is None:
        return False
    return got.strip().rstrip("/").lower() in served_origins(port)
