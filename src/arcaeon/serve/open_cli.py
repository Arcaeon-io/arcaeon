# SPDX-License-Identifier: MIT
"""`arcaeon open`: open the local dashboard in a browser (K107).

    arcaeon open                 # find a running serve, or start one, then open the browser
    arcaeon open --no-browser    # print the sign-in link instead

1. A running server. `arcaeon serve` writes <ARCAEON_HOME or ~/.arcaeon>/
   serve.json (pid, port, url) while it runs. If that file names a loopback
   url that answers GET /health, this asks it for a one-time sign-in code
   (POST /session/code with the token from serve.token) and opens
   `<url>/?t=<code>`, then exits 0. The code works once, for a short while.
2. No running server. It starts one in this process, on 127.0.0.1 only
   (`--port`, default 8787; `--root`, default the current directory), with
   the dashboard mounted, opens the link and serves until Ctrl+C, like
   `arcaeon serve`.

`--no-browser` prints the link with its one-time code and opens nothing. If
a browser cannot be opened, the link is printed instead. Only 127.0.0.1 is
ever contacted; a serve.json naming anything else is not used. The token is
read, sent to that server in a header and never printed.

Exit codes: 0 the link was opened or printed (and, when this process started
the server, a clean stop), 2 bad usage, 3 COULD NOT LOOK: a running server
that would not give a code (an older serve without the dashboard, a token
that does not match), or a port that cannot be bound.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

from arcaeon import verdict as V
from arcaeon.serve import DEFAULT_PORT

LOOPBACK_PREFIX = "http://127.0.0.1:"
#: Seconds to wait for a running server's answer.
TIMEOUT = 5

#: The server this process started, while it serves (tests stop it).
current = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="arcaeon open",
        description="Open the local dashboard in a browser: a running `arcaeon serve` if "
                    "there is one, else one started here on 127.0.0.1.")
    ap.add_argument("--no-browser", action="store_true",
                    help="print the sign-in link (with its one-time code) instead of "
                         "opening a browser")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help=f"port for a server this starts (default {DEFAULT_PORT}; 0 picks one)")
    ap.add_argument("--root", default=None, metavar="DIR",
                    help="served root for a server this starts (default: the current "
                         "directory)")
    return ap


def running_url() -> str | None:
    """The url of a running serve named by serve.json, if it answers /health."""
    from arcaeon.serve import server as S
    try:
        doc = json.loads(S.serve_json_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    url = doc.get("url") if isinstance(doc, dict) else None
    if not isinstance(url, str) or not url.startswith(LOOPBACK_PREFIX):
        return None
    port = url[len(LOOPBACK_PREFIX):]
    if not port.isdigit() or not 0 < int(port) <= 65535:
        return None
    try:
        with _opener().open(url + "/health", timeout=TIMEOUT) as r:
            ok = r.status == 200 and json.loads(r.read().decode("utf-8")).get("ok") is True
    except (OSError, ValueError, AttributeError):
        return None
    return url if ok else None


def ask_code(url: str) -> tuple[str | None, str | None]:
    """(sign-in link, None) from a running server, or (None, the plain reason)."""
    from arcaeon.serve import auth
    from arcaeon.serve import dashboard as D
    try:
        token = auth.load_or_create()
    except OSError as e:
        return None, (f"cannot read the token in {auth.token_path()} "
                      f"({e.strerror or type(e).__name__})")
    req = urllib.request.Request(url + D.CODE_PATH, data=b"", method="POST",
                                 headers={"Authorization": f"Bearer {token}"})
    try:
        with _opener().open(req, timeout=TIMEOUT) as r:
            doc = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        e.close()
        if e.code == 404:
            return None, ("the running server does not answer the dashboard; stop it and "
                          "run `arcaeon open` again to start one that does")
        if e.code == 401:
            return None, ("the running server did not accept this machine's token "
                          "(serve.token changed since it started)")
        return None, f"the running server answered {e.code} when asked for a sign-in code"
    except (OSError, ValueError) as e:
        return None, f"the running server did not answer ({type(e).__name__})"
    code = doc.get("code") if isinstance(doc, dict) else None
    if not isinstance(code, str) or not code:
        return None, "the running server gave no sign-in code"
    from urllib.parse import quote
    return f"{url}/?t={quote(code)}", None


def _show(link: str, no_browser: bool) -> None:
    if no_browser:
        print(link, flush=True)
        return
    import webbrowser
    try:
        opened = webbrowser.open(link)
    except Exception:  # noqa: BLE001  no browser is not a failure: print the link
        opened = False
    if opened:
        print("arcaeon open: opened the dashboard in your browser (the link works once).",
              flush=True)
    else:
        print("arcaeon open: could not open a browser; open this link (it works once):",
              flush=True)
        print(link, flush=True)


def main(argv: list[str] | None = None) -> int:
    global current
    a = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    if not 0 <= a.port <= 65535:
        print(f"arcaeon open: --port {a.port} is not a port (0 to 65535)", file=sys.stderr)
        return V.EXIT_USAGE
    url = running_url()
    if url is not None:
        link, problem = ask_code(url)
        if link is None:
            print(f"arcaeon open: COULD NOT LOOK: {problem}", file=sys.stderr)
            return V.EXIT_COULD_NOT_LOOK
        _show(link, a.no_browser)
        return V.EXIT_GOOD
    import os
    root = os.path.abspath(a.root) if a.root is not None else os.getcwd()
    if not os.path.isdir(root):
        print(f"arcaeon open: --root {a.root} is not a directory", file=sys.stderr)
        return V.EXIT_USAGE
    from arcaeon.serve import dashboard as D
    from arcaeon.serve import server as S
    try:
        srv = D.make_dashboard_server(port=a.port, root=root)
    except OSError as e:
        print(f"arcaeon open: COULD NOT LOOK: cannot start a server on 127.0.0.1:{a.port} "
              f"({e.strerror or type(e).__name__})", file=sys.stderr)
        return V.EXIT_COULD_NOT_LOOK
    current = srv
    try:
        link = f"{srv.url}/?t={D.issue_code(srv)}"
        print(f"arcaeon open: no server was running; started one for {srv.fence.root}",
              file=sys.stderr, flush=True)
        _show(link, a.no_browser)
        S.run(srv, out=sys.stderr)
    finally:
        current = None
    return V.EXIT_GOOD


__all__ = ["LOOPBACK_PREFIX", "ask_code", "main", "running_url"]
