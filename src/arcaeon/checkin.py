# SPDX-License-Identifier: MIT
"""arcaeon.checkin: once a day, ask which arcaeon version is current.

WHAT IT DOES. At most once per 24 hours the command line (and the MCP server,
at start) GETs a signed `latest.json` from arcaeon.io. The answer is checked
and cached; from the cache come exactly two possible lines for a person:

    Update to the latest version.            installed < latest
    This version is no longer supported.     installed < minimum_supported (wins)

and the full detail for an agent (block()): latest, minimum_supported,
block_after, notice, the upgrade command, the signature word, source, time.

WHAT IT SENDS. A plain GET whose only identifying content is the
User-Agent `arcaeon/<version>`. No id, no path, no host name, no account, no
cookie, no query string.

THE SIGNATURE. latest.json is

    {"payload": {"kind": "arcaeon.latest", "schema": 1, "latest": "...",
                 "minimum_supported": "...", "block_after": {"version": "...",
                 "date": "..."} | null, "notice": "..." | null, "issued_at": "...Z"},
     "signatures": [{"keyid": "did:key:z6Mk...", "sig": "<base64>"}]}

signed with Ed25519 over the JCS (RFC 8785) canonical bytes of `payload`. The
keys trusted to sign it are CHECKIN_KEYS below, a constant in this file:
nothing in the environment or any config can add or swap one. An answer that
does not verify against one of them (bad signature, unknown key, edited
payload, malformed file) is IGNORED: no line, and the agent block says why.
Ed25519 runs on `cryptography` when it is installed, else on a small
pure-Python verifier (RFC 8032 section 6, verify only), so the base install
needs no extra. That verifier stays only while it passes the RFC 8032 section
7.1 vectors and refuses S >= L and non-canonical points
(tests/test_checkin_ed25519_rfc8032.py).

THE FALLBACK. Only when arcaeon.io cannot be reached at all, PyPI's JSON for
the project is asked instead. It is unsigned: it can only ever produce
"Update to the latest version.", it is labelled `unsigned`, and a signed
answer in the cache always wins over it.

NEVER IN THE WAY. Every function here swallows every error. Offline, a
broken cache, an unwritable home: nothing is printed, nothing fails.
`arcaeon verify` never fetches; it only reads the cache (block()).

OFF SWITCH. ARCAEON_NO_CHECKIN=1: no fetch, no line, no cache write.

CACHE. <ARCAEON_HOME or ~/.arcaeon>/checkin.json (the journal's directory).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arcaeon import __version__

__all__ = ["CHECKIN_KEYS", "DEFAULT_URL", "PYPI_URL", "OFF_ENV", "LINES", "UPDATE_LINE",
           "UNSUPPORTED_LINE", "UPGRADE_COMMAND", "enabled", "cache_path", "parse_version",
           "line_for", "verify_document", "maybe_fetch", "block", "cli_notice", "human_line"]

#: The did:key ids trusted to sign latest.json. EMPTY ON PURPOSE: the release
#: owner's key does not exist yet. Until a real Ed25519 did:key is written
#: here (and only here, in a release), every signed answer reads COULD NOT
#: LOOK and is ignored: no line. There is deliberately no environment
#: variable or config file that adds or replaces a key; tests patch this
#: constant with a TEST key from tests/fixtures/checkin.
CHECKIN_KEYS: tuple[str, ...] = ()

DEFAULT_URL = "https://arcaeon.io/latest.json"
PYPI_URL = "https://pypi.org/pypi/arcaeon/json"
OFF_ENV = "ARCAEON_NO_CHECKIN"
HOME_ENV = "ARCAEON_HOME"
CACHE_NAME = "checkin.json"

UPDATE_LINE = "Update to the latest version."
UNSUPPORTED_LINE = "This version is no longer supported."
#: Every line a person can ever be shown. Nothing else, ever.
LINES = (UPDATE_LINE, UNSUPPORTED_LINE)
UPGRADE_COMMAND = "pip install -U arcaeon"

INTERVAL = 24 * 3600            # at most one fetch per this many seconds
TIMEOUT = 3.0                   # seconds per request
MAX_BYTES = 64 * 1024           # latest.json is a few hundred bytes
MAX_PYPI_BYTES = 8 * 1024 * 1024
MAX_NOTICE = 1000
KIND = "arcaeon.latest"
SCHEMA = 1

VERIFIED, BROKEN, COULD_NOT_LOOK, UNSIGNED = "VERIFIED", "BROKEN", "COULD NOT LOOK", "unsigned"


def enabled() -> bool:
    """False when ARCAEON_NO_CHECKIN is set to anything but empty or 0."""
    return os.environ.get(OFF_ENV, "").strip() in ("", "0")


def cache_path() -> Path:
    override = os.environ.get(HOME_ENV, "").strip()
    return (Path(override) if override else Path.home() / ".arcaeon") / CACHE_NAME


# --- versions: a PEP 440 subset ---------------------------------------------------------

_VER = re.compile(r"^v?(\d+(?:\.\d+)*)(?:(a|b|rc)(\d+))?(?:\.post(\d+))?(?:\.dev(\d+))?$")
_PRE_RANK = {"a": 0, "b": 1, "rc": 2}


def parse_version(s: Any) -> tuple | None:
    """A sortable key for N(.N)*[{a|b|rc}N][.postN][.devN], or None."""
    if not isinstance(s, str) or len(s) > 64:
        return None
    m = _VER.match(s.strip().lower())
    if not m:
        return None
    rel = [int(x) for x in m.group(1).split(".")]
    while len(rel) > 1 and rel[-1] == 0:
        rel.pop()
    pre_l, pre_n, post, dev = m.group(2), m.group(3), m.group(4), m.group(5)
    if pre_l:
        pre = (0, _PRE_RANK[pre_l], int(pre_n))
    elif dev is not None and post is None:
        pre = (-1, 0, 0)                    # 1.0.dev1 sorts before 1.0a1
    else:
        pre = (1, 0, 0)
    return (tuple(rel), pre, -1 if post is None else int(post),
            float("inf") if dev is None else int(dev))


def line_for(installed: Any, latest: Any, minimum: Any) -> str | None:
    """One of LINES, or None. Past support wins; anything unparseable is no line."""
    iv = parse_version(installed)
    if iv is None:
        return None
    mv = parse_version(minimum)
    if mv is not None and iv < mv:
        return UNSUPPORTED_LINE
    lv = parse_version(latest)
    if lv is not None and iv < lv:
        return UPDATE_LINE
    return None


# --- Ed25519 verify -----------------------------------------------------------------------
# RFC 8032 section 6 reference arithmetic, verify only. Public inputs only, so
# timing does not matter. Used when `cryptography` is not installed.

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _pt_add(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % _P
    B = (a[1] + a[0]) * (b[1] + b[0]) % _P
    C = 2 * a[3] * b[3] * _D % _P
    D = 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _pt_mul(s: int, pt):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _pt_add(q, pt)
        pt = _pt_add(pt, pt)
        s >>= 1
    return q


def _pt_equal(a, b) -> bool:
    return ((a[0] * b[2] - b[0] * a[2]) % _P == 0
            and (a[1] * b[2] - b[1] * a[2]) % _P == 0)


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _ed25519_verify_pure(pub: bytes, msg: bytes, sig: bytes) -> bool:
    if len(pub) != 32 or len(sig) != 64:
        return False
    a = _decompress(pub)
    r = _decompress(sig[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _L
    return _pt_equal(_pt_mul(s, _G), _pt_add(r, _pt_mul(h, a)))


def _ed25519_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return _ed25519_verify_pure(pub, msg, sig)
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_DID_LEN = 56                   # "did:key:z" + 47 base58 digits of 0xed01 + 32 bytes


def _pub_from_did(did: Any) -> bytes | None:
    if not isinstance(did, str) or len(did) != _DID_LEN or not did.startswith("did:key:z"):
        return None
    n = 0
    for ch in did[9:]:
        i = _B58.find(ch)
        if i < 0:
            return None
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    raw = b"\x00" * (len(did[9:]) - len(did[9:].lstrip("1"))) + raw
    if len(raw) != 34 or raw[:2] != b"\xed\x01":
        return None
    return raw[2:]


# --- the signed document ------------------------------------------------------------------

def _payload_problem(p: Any) -> str | None:
    if not isinstance(p, dict):
        return "payload is not an object"
    if p.get("kind") != KIND:
        return f"payload kind is not {KIND}"
    if p.get("schema") != SCHEMA:
        return f"payload schema is not {SCHEMA}"
    for f in ("latest", "minimum_supported"):
        if parse_version(p.get(f)) is None:
            return f"payload {f} is not a version"
    ba = p.get("block_after")
    if ba is not None:
        if not isinstance(ba, dict) or set(ba) - {"version", "date"}:
            return "payload block_after is not {version, date}"
        if ba.get("version") is not None and parse_version(ba.get("version")) is None:
            return "payload block_after.version is not a version"
        if ba.get("date") is not None and not isinstance(ba.get("date"), str):
            return "payload block_after.date is not text"
    n = p.get("notice")
    if n is not None and (not isinstance(n, str) or len(n) > MAX_NOTICE):
        return "payload notice is not short text"
    ia = p.get("issued_at")
    if ia is not None and not isinstance(ia, str):
        return "payload issued_at is not text"
    return None


def verify_document(data: Any) -> tuple[str, dict | None, str | None]:
    """(word, payload, why). word VERIFIED gives the payload and why None;
    BROKEN or COULD NOT LOOK give no payload and say why. Never raises."""
    try:
        return _verify_document(data)
    except Exception as e:  # noqa: BLE001
        return BROKEN, None, f"malformed ({type(e).__name__})"


def _verify_document(data: Any) -> tuple[str, dict | None, str | None]:
    if isinstance(data, (bytes, bytearray)):
        if len(data) > MAX_BYTES:
            return BROKEN, None, "larger than a latest.json can be"
        try:
            data = json.loads(bytes(data).decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            return BROKEN, None, "malformed: not JSON"
    if not isinstance(data, dict) or not isinstance(data.get("payload"), dict) \
            or not isinstance(data.get("signatures"), list) or not data["signatures"]:
        return BROKEN, None, "malformed: not {payload, signatures}"
    keys = tuple(CHECKIN_KEYS)
    if not keys:
        return COULD_NOT_LOOK, None, "no trusted key in this version of arcaeon"
    payload = data["payload"]
    try:
        msg = _jcs(payload)
    except Exception:  # noqa: BLE001
        return BROKEN, None, "malformed: the payload cannot be canonicalized"
    trusted_seen = False
    for s in data["signatures"][:8]:
        if not isinstance(s, dict) or s.get("keyid") not in keys:
            continue
        trusted_seen = True
        pub = _pub_from_did(s["keyid"])
        try:
            sig = base64.b64decode(s.get("sig") if isinstance(s.get("sig"), str) else "",
                                   validate=True)
        except (binascii.Error, ValueError):
            continue
        if pub is not None and _ed25519_verify(pub, msg, sig):
            problem = _payload_problem(payload)
            if problem:
                return BROKEN, None, f"signed, but {problem}"
            return VERIFIED, payload, None
    if not trusted_seen:
        return BROKEN, None, "not signed by a key this version trusts"
    return BROKEN, None, "the signature does not match the payload"


def _jcs(v: Any) -> bytes:
    from arcaeon.prove import jcs
    return jcs.canonicalize(v)


# --- fetch -----------------------------------------------------------------------------

def _request(url: str) -> urllib.request.Request:
    """The whole request: a GET, the version in the User-Agent, nothing else."""
    return urllib.request.Request(url, method="GET", headers={
        "User-Agent": f"arcaeon/{__version__}", "Accept": "application/json"})


_OPENER = None


def _open(req, timeout):
    """The one network call (tests replace this). No cookie jar, no auth."""
    global _OPENER
    if _OPENER is None:
        _OPENER = urllib.request.build_opener()
    return _OPENER.open(req, timeout=timeout)


def _get(url: str, limit: int) -> bytes | None:
    try:
        resp = _open(_request(url), TIMEOUT)
        try:
            body = resp.read(limit + 1)
        finally:
            close = getattr(resp, "close", None)
            if close:
                close()
    except Exception:  # noqa: BLE001  offline is not an error
        return None
    if not isinstance(body, (bytes, bytearray)):
        return None
    return bytes(body)


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _day(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d")


def _load() -> dict:
    try:
        c = json.loads(cache_path().read_text(encoding="utf-8"))
        return c if isinstance(c, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _save(c: dict) -> bool:
    try:
        p = cache_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_text(json.dumps(c, sort_keys=True), encoding="utf-8")
        os.replace(tmp, p)
        return True
    except Exception:  # noqa: BLE001
        return False


def maybe_fetch(now: float | None = None) -> bool:
    """Fetch and cache, if on and the last attempt is 24h old. True when a
    fetch was attempted. Never raises, never prints."""
    try:
        return _maybe_fetch(time.time() if now is None else now)
    except Exception:  # noqa: BLE001
        return False


def _maybe_fetch(now: float) -> bool:
    if not enabled():
        return False
    c = _load()
    last = c.get("last_attempt") if isinstance(c.get("last_attempt"), dict) else {}
    at = last.get("at")
    if isinstance(at, (int, float)) and 0 <= now - at < INTERVAL:
        return False
    # claim the slot first: a cache that cannot be written means no fetch at all
    c["last_attempt"] = {"at": now, "source": DEFAULT_URL, "signature": COULD_NOT_LOOK,
                         "reason": "fetch in progress"}
    if not _save(c):
        return True
    body = _get(DEFAULT_URL, MAX_BYTES)
    if body is not None:
        word, payload, why = verify_document(body)
        attempt = {"at": now, "source": DEFAULT_URL, "signature": word, "reason": why}
        if word == VERIFIED:
            old = _cached_signed(c)
            if old is not None and old[0] == VERIFIED and str(payload.get("issued_at") or "") \
                    < str(old[1].get("issued_at") or ""):
                attempt["reason"] = "older than the signed answer already cached; kept that one"
            else:
                c["signed"] = {"doc": json.loads(body.decode("utf-8")), "fetched_at": _iso(now),
                               "source": DEFAULT_URL}
        c["last_attempt"] = attempt
        _save(c)
        return True
    # arcaeon.io could not be reached: PyPI, unsigned, may only say "update"
    attempt = {"at": now, "source": DEFAULT_URL, "signature": COULD_NOT_LOOK,
               "reason": "arcaeon.io could not be reached"}
    pb = _get(PYPI_URL, MAX_PYPI_BYTES)
    latest = None
    if pb is not None and len(pb) <= MAX_PYPI_BYTES:
        try:
            info = json.loads(pb.decode("utf-8")).get("info") or {}
            v = info.get("version")
            latest = v if parse_version(v) is not None else None
        except Exception:  # noqa: BLE001
            latest = None
    if latest is not None:
        c["pypi"] = {"latest": latest, "fetched_at": _iso(now), "source": PYPI_URL}
    c["last_attempt"] = attempt
    _save(c)
    return True


def _cached_signed(c: dict):
    """(word, payload, why, entry) for the cached signed answer, re-verified now."""
    s = c.get("signed")
    if not isinstance(s, dict) or "doc" not in s:
        return None
    word, payload, why = verify_document(s["doc"])
    if word != VERIFIED:
        return (word, None, why, s)
    return (word, payload, why, s)


# --- the faces --------------------------------------------------------------------------

def block(now: float | None = None) -> dict | None:
    """The agent's view of the cached answer, or None when check-in is off or
    nothing is cached. Reads only; never fetches, never raises."""
    try:
        return _block()
    except Exception:  # noqa: BLE001
        return None


def _empty(signature: str, source: str | None, fetched_at: str | None, why: str | None) -> dict:
    return {"installed": __version__, "latest": None, "minimum_supported": None,
            "block_after": None, "notice": None, "upgrade_command": UPGRADE_COMMAND,
            "signature": signature, "source": source, "fetched_at": fetched_at, "line": None,
            "ignored_because": why}


def _block() -> dict | None:
    if not enabled():
        return None
    p = cache_path()
    if not p.is_file():
        return None
    c = _load()
    if not c:
        return None
    signed = _cached_signed(c)
    last = c.get("last_attempt") if isinstance(c.get("last_attempt"), dict) else {}
    if signed is not None:
        word, payload, why, entry = signed
        if word == VERIFIED:
            # a later fetch that was refused does not erase this answer; say so
            later = (f"the latest fetch was ignored: {last.get('reason')}"
                     if last.get("signature") == BROKEN else None)
            return {"installed": __version__, "latest": payload["latest"],
                    "minimum_supported": payload["minimum_supported"],
                    "block_after": payload.get("block_after"), "notice": payload.get("notice"),
                    "upgrade_command": UPGRADE_COMMAND, "signature": VERIFIED,
                    "source": entry.get("source"), "fetched_at": entry.get("fetched_at"),
                    "line": line_for(__version__, payload["latest"],
                                     payload["minimum_supported"]),
                    "ignored_because": later}
        return _empty(word, entry.get("source"), entry.get("fetched_at"),
                      f"the cached answer: {why}")
    pypi = c.get("pypi")
    if isinstance(pypi, dict) and last.get("signature") == COULD_NOT_LOOK \
            and last.get("reason") == "arcaeon.io could not be reached":
        b = _empty(UNSIGNED, pypi.get("source"), pypi.get("fetched_at"), None)
        b["latest"] = pypi.get("latest") if parse_version(pypi.get("latest")) else None
        b["line"] = UPDATE_LINE if line_for(__version__, b["latest"], None) else None
        return b
    when = last.get("at")
    return _empty(str(last.get("signature") or COULD_NOT_LOOK), last.get("source"),
                  _iso(when) if isinstance(when, (int, float)) else None,
                  str(last.get("reason") or "no answer yet"))


def human_line() -> str | None:
    """The one line for a person, from the cache, or None. Not rate-limited
    (the verify report header and the MCP instructions use it)."""
    b = block()
    line = b.get("line") if b else None
    return line if line in LINES else None


def cli_notice(now: float | None = None) -> str | None:
    """The line for the CLI's stderr, at most once per (UTC) day, or None."""
    try:
        now = time.time() if now is None else now
        line = human_line()
        if line is None:
            return None
        c = _load()
        if c.get("line_shown_on") == _day(now):
            return None
        c["line_shown_on"] = _day(now)
        return line if _save(c) else None
    except Exception:  # noqa: BLE001
        return None
