# SPDX-License-Identifier: MIT
"""arcaeon.prove.account_server: the account-as-ID stub and the register of
named operators, over real HTTP, on loopback only (L3-06).

    python -m arcaeon.prove.account_server serve --auth AUTH.json [--port N]
        [--store FILE] [--register FILE] [--binding-key FILE] [--register-key FILE]
    python -m arcaeon.prove.account_server fetch URL --did DID... --out FILE
    python -m arcaeon.prove.account_server fetch-register URL --out FILE

A reference server for trying the design end to end, not the hosted service.
`serve` binds 127.0.0.1 only (port 0 picks a free one) and prints one JSON
line, {"url", "binding_key", "register_key", "throwaway_keys"}, then serves:

  the account API     every route in docs/ACCOUNT_ID_API.md, answered by
                      account_id.handle (the same code the library tests use)
  GET  /v1/register          {"rows": [...]}: the register, public
  POST /v1/register/add      {"member", "what", "value"}           (operator)
  POST /v1/register/revoke   {"member", "what", "digest", "reason",
                              "compromised_since"}                  (operator)

AUTH.json is {"owners": {"TOKEN": "acct:OWNER@arcaeon.io", ...},
"register_operator": "TOKEN"}; a caller sends "Authorization: Bearer TOKEN".
An owner token is an owner API key; the operator token may write the register.
Tokens stay in the file, never on the command line. Without --binding-key /
--register-key (32-byte seed files, base64, as `exchange bind` reads) the
server makes throwaway seeds in memory that die with it. Without --store /
--register the data lives in memory only.

`fetch` asks the server for each did's public binding statement and writes
{"fetched_at", "source", "statements"}: the FILE `exchange pair --accounts`
and `tally build --accounts` read. fetched_at is taken before the first
request, so the file never claims to be fresher than it is. `fetch-register`
writes the register rows as JSONL for `arcaeon register page`. Both fetch
from an https URL or a loopback http URL only, follow no redirect, and never
overwrite --out. The trusted keys never come from the server's answers: name
them yourself (--account-key, --operator-key).
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from arcaeon import verdict as V
from arcaeon.prove import account_id as A
from arcaeon.prove import register as G

__all__ = ["MAX_BODY", "USAGE", "make_server", "fetch_statements", "fetch_register", "main"]

MAX_BODY = 1 << 20
MAX_ANSWER = 64 << 20
LOOPBACK = ("127.0.0.1", "localhost", "::1")
USAGE = """usage: python -m arcaeon.prove.account_server serve --auth AUTH.json [--port N]
           [--store FILE] [--register FILE] [--binding-key FILE] [--register-key FILE]
       python -m arcaeon.prove.account_server fetch URL --did DID... --out FILE
       python -m arcaeon.prove.account_server fetch-register URL --out FILE"""


class _Usage(Exception):
    pass


def _seed(path: Any) -> bytes:
    if path is None:
        return secrets.token_bytes(32)
    from arcaeon.prove.envelope import _load_seed
    return _load_seed(path)


def _did(seed: bytes) -> str:
    from arcaeon.prove.vet import receipts as R
    return R.did_key(R.public_key_from_seed(seed))


def _load_auth(path: Any) -> tuple[dict, str | None]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    owners = data.get("owners") if isinstance(data, dict) else None
    op = data.get("register_operator") if isinstance(data, dict) else None
    if not isinstance(owners, dict) or not all(isinstance(k, str) and len(k) >= 16
                                               for k in owners):
        raise _Usage("--auth: owners is not {TOKEN: OWNER} with tokens of 16+ characters")
    if op is not None and not (isinstance(op, str) and len(op) >= 16):
        raise _Usage("--auth: register_operator is not a token of 16+ characters")
    return owners, op


def _save_rows(rows: list, path: Path) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.writelines(json.dumps(r, sort_keys=True) + "\n" for r in rows)
    os.replace(tmp, path)


class _State:
    def __init__(self, *, owners: dict, operator: str | None, binding_seed: bytes,
                 register_seed: bytes, store_path: Any = None, register_path: Any = None):
        self.owners, self.operator = owners, operator
        self.binding_seed, self.register_seed = binding_seed, register_seed
        self.store_path = Path(store_path) if store_path else None
        self.register_path = Path(register_path) if register_path else None
        self.store = A.load_store(self.store_path) if self.store_path else A.new_store()
        self.register: list = []
        if self.register_path and self.register_path.exists():
            from arcaeon.prove.register_page import load_rows
            self.register = load_rows(self.register_path)
        self.lock = threading.Lock()

    def caller(self, header: Any) -> Any:
        tok = header[7:].strip() if isinstance(header, str) and header.startswith("Bearer ") \
            else None
        if not tok:
            return None
        for t, owner in self.owners.items():
            if hmac.compare_digest(t.encode("utf-8"), tok.encode("utf-8")):
                return {"kind": "owner_api_key", "owner": owner}
        if self.operator and hmac.compare_digest(self.operator.encode("utf-8"),
                                                 tok.encode("utf-8")):
            return {"kind": "register_operator"}
        return None

    def register_route(self, caller: Any, method: str, parts: list, body: dict):
        if parts == ["v1", "register"]:
            if method != "GET":
                return 405, {"error": "GET only"}
            return 200, {"rows": list(self.register)}
        if method != "POST":
            return 405, {"error": "POST only"}
        if not (isinstance(caller, dict) and caller.get("kind") == "register_operator"):
            return 401, {"error": "the register is written by the register operator only"}
        try:
            if parts[2] == "add":
                row = G.add(self.register, self.register_seed, member=body.get("member"),
                            what=body.get("what"), value=body.get("value"))
            else:
                row = G.revoke(self.register, self.register_seed, member=body.get("member"),
                               what=body.get("what"), digest=body.get("digest"),
                               reason=body.get("reason"),
                               compromised_since=body.get("compromised_since"))
        except G.RegisterError as e:
            return 400, {"error": str(e)}
        if self.register_path:
            _save_rows(self.register, self.register_path)
        return 201, {"row": row}

    def answer(self, method: str, raw_path: str, auth: Any, body: Any) -> tuple[int, dict]:
        path = urllib.parse.unquote(urllib.parse.urlsplit(raw_path).path)
        parts = path.strip("/").split("/")
        caller = self.caller(auth)
        with self.lock:
            if parts[:2] == ["v1", "register"] and (len(parts) == 2 or (
                    len(parts) == 3 and parts[2] in ("add", "revoke"))):
                return self.register_route(caller, method, parts,
                                           body if isinstance(body, dict) else {})
            if isinstance(caller, dict) and caller.get("kind") == "register_operator":
                caller = None                   # not an owner: the account API says 401
            status, out = A.handle(self.store, caller, method, path, body,
                                   server_seed=self.binding_seed)
            if self.store_path and method == "POST" and status in (200, 201):
                A.save_store(self.store, self.store_path)
            return status, out


def make_server(state: _State, port: int = 0) -> ThreadingHTTPServer:
    """A ThreadingHTTPServer on 127.0.0.1:port serving `state`."""

    class H(BaseHTTPRequestHandler):
        server_version = "arcaeon-account-server/1"

        def _reply(self, status: int, out: dict) -> None:
            data = (json.dumps(out, sort_keys=True) + "\n").encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _go(self, method: str) -> None:
            body = None
            if method == "POST":
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    n = -1
                if n < 0 or n > MAX_BODY:
                    return self._reply(413, {"error": "the body is over the size cap"})
                try:
                    body = json.loads(self.rfile.read(n).decode("utf-8")) if n else {}
                except (UnicodeDecodeError, ValueError):
                    return self._reply(400, {"error": "the body is not JSON"})
            self._reply(*state.answer(method, self.path, self.headers.get("Authorization"),
                                      body))

        def do_GET(self):  # noqa: N802
            self._go("GET")

        def do_POST(self):  # noqa: N802
            self._go("POST")

        def log_message(self, *a):
            pass

    return ThreadingHTTPServer(("127.0.0.1", port), H)


# --- fetch -------------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _base(url: Any) -> str:
    u = urllib.parse.urlsplit(str(url))
    host = (u.hostname or "").lower()
    if not (u.scheme == "https" and host) and not (u.scheme == "http" and host in LOOPBACK):
        raise _Usage("URL is not https, or http on loopback (127.0.0.1, localhost, ::1)")
    return str(url).rstrip("/")


def _get(url: str) -> tuple[int, Any]:
    handlers: list = [_NoRedirect]
    if (urllib.parse.urlsplit(url).hostname or "").lower() in LOOPBACK:
        handlers.append(urllib.request.ProxyHandler({}))   # loopback never goes via a proxy
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(urllib.request.Request(url, method="GET"), timeout=30) as r:
            return r.status, json.loads(r.read(MAX_ANSWER + 1)[:MAX_ANSWER].decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, None


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch_statements(url: str, dids: list) -> dict:
    """{"fetched_at", "source", "statements", "not_bound"} from GET
    /v1/keys/{did}/binding per did. OSError / ValueError when the server
    cannot be read; a 404 (a key never bound) is listed in not_bound."""
    base, fetched_at = _base(url), _now()
    out, missing = [], []
    for did in dids:
        status, st = _get(f"{base}/v1/keys/{urllib.parse.quote(str(did), safe=':')}/binding")
        if status == 404:
            missing.append(did)
        elif status != 200 or not isinstance(st, dict):
            raise ValueError(f"the server answered {status} for {did}")
        else:
            out.append(st)
    return {"fetched_at": fetched_at, "source": base, "statements": out, "not_bound": missing}


def fetch_register(url: str) -> list:
    status, body = _get(f"{_base(url)}/v1/register")
    if status != 200 or not isinstance(body, dict) or not isinstance(body.get("rows"), list):
        raise ValueError(f"the server answered {status} for /v1/register")
    return body["rows"]


# --- CLI ---------------------------------------------------------------------------------

def _serve(o: dict) -> int:
    if "--auth" not in o:
        raise _Usage("serve needs --auth AUTH.json")
    try:
        port = int(o.get("--port", "0"))
    except ValueError:
        raise _Usage("--port is not a number") from None
    from arcaeon.prove.envelope import SealError
    from arcaeon.prove.register_page import RegisterPageError
    try:
        owners, op = _load_auth(o["--auth"])
        state = _State(owners=owners, operator=op, binding_seed=_seed(o.get("--binding-key")),
                       register_seed=_seed(o.get("--register-key")),
                       store_path=o.get("--store"), register_path=o.get("--register"))
    except (OSError, ValueError, SealError, RegisterPageError, A.AccountError) as e:
        raise _Usage(f"cannot start: {e}") from None
    srv = make_server(state, port)
    print(json.dumps({"url": f"http://127.0.0.1:{srv.server_address[1]}",
                      "binding_key": _did(state.binding_seed),
                      "register_key": _did(state.register_seed),
                      "throwaway_keys": "--binding-key" not in o or "--register-key" not in o}),
          flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return V.EXIT_GOOD


def _write_new(out: Any, text: str) -> None:
    with open(out, "x", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _fetch(pos: list, o: dict, register: bool) -> int:
    if len(pos) != 1 or not o.get("--out"):
        raise _Usage("fetch takes one URL and --out FILE")
    if not register and not o.get("--did"):
        raise _Usage("fetch needs --did DID (repeatable)")
    if Path(o["--out"]).exists():
        raise _Usage(f"--out {Path(o['--out']).name} exists; it is never overwritten")
    _base(pos[0])
    try:
        if register:
            rows = fetch_register(pos[0])
            _write_new(o["--out"], "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))
            print(f"wrote {len(rows)} register row(s) to {Path(o['--out']).name}")
            return V.EXIT_GOOD
        doc = fetch_statements(pos[0], o["--did"])
    except (OSError, ValueError) as e:
        print(f"account_server fetch: {V.COULD_NOT_LOOK}: {e}; nothing written", file=sys.stderr)
        return V.EXIT_COULD_NOT_LOOK
    _write_new(o["--out"], json.dumps(doc, indent=1, sort_keys=True) + "\n")
    for did in doc["not_bound"]:
        print(f"no binding for {did} (404)", file=sys.stderr)
    print(f"wrote {len(doc['statements'])} statement(s) to {Path(o['--out']).name}, "
          f"fetched_at {doc['fetched_at']}")
    return V.EXIT_GOOD


def main(argv: list[str] | None = None) -> int:
    from arcaeon.prove.envelope import _parse, _Usage as EU
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return V.EXIT_GOOD if argv else V.EXIT_USAGE
    if argv[0].startswith("--"):
        argv = ["serve", *argv]
    spec = {"--port": "value", "--auth": "value", "--store": "value", "--register": "value",
            "--binding-key": "value", "--register-key": "value", "--did": "list",
            "--out": "value"}
    try:
        try:
            pos, o = _parse(argv[1:], spec)
        except EU as e:
            raise _Usage(str(e)) from None
        if argv[0] == "serve":
            if pos:
                raise _Usage("serve takes no positional argument")
            return _serve(o)
        if argv[0] in ("fetch", "fetch-register"):
            return _fetch(pos, o, argv[0] == "fetch-register")
        raise _Usage(f"unknown subcommand {argv[0]!r} (serve, fetch, fetch-register)")
    except _Usage as e:
        print(f"account_server: {e}\n{USAGE}", file=sys.stderr)
        return V.EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
