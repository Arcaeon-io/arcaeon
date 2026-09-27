# SPDX-License-Identifier: MIT
"""`arcaeon doctor`: check this install and say what it found (K115).

    arcaeon doctor [--json]

One line per thing it looked at: the Python version, which extras are
installed, whether ARCAEON_KEY is set (never its value), whether a local
`arcaeon serve` answers, whether each AI client's config file carries an
`arcaeon` entry, and whether the activity journal can be written.

It changes nothing. It reads files, asks `GET /health` of a server that
serve.json says is on this machine (loopback only; it never reaches off the
machine), and opens and removes one temp file in an existing journal
directory to prove it is writable. It creates no directory.

Exit 0 when every check could be read, whatever it found (a server that is
not running or a client with no entry is a reading, not a fault). Exit 3,
COULD NOT LOOK, when any check could not be looked at: a config file that
does not parse, a serve.json naming a host off this machine, a server that
neither answers nor refuses. Never a green on 3.

The client check reads each file itself. When `arcaeon connect --check`
(K021) lands, that is the one definition of present, absent and stale, and
this reader should call it instead.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from arcaeon import verdict as V

USAGE = ("usage: arcaeon doctor [--json]\n"
         "check this install: Python, extras, key set or not, server, clients, journal.\n"
         "exit 0 every check was read, 3 COULD NOT LOOK (a check could not be looked at)")

PY_FLOOR = (3, 10)
OK, NO, CNL = "ok", "no", V.COULD_NOT_LOOK
LOOPBACK = ("127.0.0.1", "localhost", "::1", "[::1]")
HEALTH_TIMEOUT = 2.0


def _check(name: str, status: str, detail: str, **extra) -> dict:
    return {"check": name, "status": status, "detail": detail, **extra}


def check_python() -> dict:
    v = sys.version_info
    ver = f"{v[0]}.{v[1]}.{v[2]}"
    if tuple(v[:2]) >= PY_FLOOR:
        return _check("python", OK, f"{ver} (needs {PY_FLOOR[0]}.{PY_FLOOR[1]} or newer)")
    return _check("python", NO, f"{ver} is older than {PY_FLOOR[0]}.{PY_FLOOR[1]}")


def check_extras() -> list[dict]:
    from arcaeon import cli
    out = []
    for name, mods in cli._EXTRAS.items():
        have = all(cli._importable(m) for m in mods)
        out.append(_check(f"extra {name}", OK if have else NO,
                          "installed" if have else f'not installed (pip install "arcaeon[{name}]")'))
    return out


def check_key() -> dict:
    from arcaeon import remote
    # Whether it is set, never the value: a doctor report gets pasted into bug reports.
    if remote.key():
        return _check("key", OK, "ARCAEON_KEY is set")
    return _check("key", NO, "ARCAEON_KEY is not set (the free verbs do not need it)")


def _health(url: str) -> tuple[str, str]:
    import urllib.error
    import urllib.parse
    import urllib.request
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    if host not in LOOPBACK and f"[{host}]" not in LOOPBACK:
        return CNL, f"serve.json names {host or url!r}, off this machine; doctor only asks loopback"
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/health", timeout=HEALTH_TIMEOUT) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        return NO, f"{url} answered /health with HTTP {e.code}"
    except urllib.error.URLError as e:
        if isinstance(e.reason, ConnectionRefusedError):
            return NO, f"nothing answers at {url} (serve.json is left over; run arcaeon serve)"
        return CNL, f"{url} neither answered nor refused ({e.reason})"
    except (OSError, ValueError) as e:
        return CNL, f"{url} neither answered nor refused ({type(e).__name__})"
    if code == 200:
        return OK, f"arcaeon serve answers at {url}"
    return NO, f"{url} answered /health with HTTP {code}"


def check_serve() -> dict:
    from arcaeon import journal
    p = journal.home() / "serve.json"
    if not p.exists():
        return _check("serve", NO, "not running (no serve.json; start it with arcaeon serve)")
    try:
        url = json.loads(p.read_text(encoding="utf-8")).get("url")
    except (OSError, ValueError, AttributeError) as e:
        return _check("serve", CNL, f"serve.json could not be read ({type(e).__name__})",
                      **V.could_not_look("a server url", str(p), "unreadable",
                                         "serve.json did not parse"))
    if not isinstance(url, str) or not url:
        return _check("serve", CNL, "serve.json has no url",
                      **V.could_not_look("a server url", str(p), "missing",
                                         "serve.json has no url"))
    status, detail = _health(url)
    extra = {} if status != CNL else V.could_not_look("GET /health", url, "network", detail)
    return _check("serve", status, detail, **extra)


def _command_resolves(cmd) -> bool:
    if not isinstance(cmd, str) or not cmd:
        return False
    return Path(cmd).is_file() or shutil.which(cmd) is not None


def check_client(entry) -> dict:
    """present, absent or stale for one client, read only. `stale`: the entry
    is there but its command no longer resolves on this machine."""
    from arcaeon.connect import catalog as C
    name = f"client {entry.name}"
    if not entry.writes_file:
        return _check(name, OK, f"no config file to check (arcaeon connect {entry.name} "
                      "prints what it needs)", state="n/a")
    path = C.config_path(entry)
    if not path:
        return _check(name, OK, "keeps no config file on this OS", state="n/a")
    p = Path(path)
    if not p.exists():
        return _check(name, OK, f"absent: {path} is not there", state="absent")
    try:
        text = p.read_text(encoding="utf-8-sig")
        data = json.loads(text) if text.strip() else {}
    except (OSError, ValueError) as e:
        why = "does not parse as JSON" if isinstance(e, ValueError) else "could not be read"
        return _check(name, CNL, f"{path} {why}",
                      **V.could_not_look("an arcaeon entry", path, "unreadable", f"the file {why}"))
    block = data.get(entry.key) if isinstance(data, dict) else None
    got = block.get("arcaeon") if isinstance(block, dict) else None
    if not isinstance(got, dict):
        return _check(name, OK, f"absent: {path} has no arcaeon entry", state="absent")
    if _command_resolves(got.get("command")):
        return _check(name, OK, f"present in {path}", state="present")
    return _check(name, OK, f"stale: {path} names {got.get('command')!r}, "
                  "which does not resolve here", state="stale")


def check_clients() -> list[dict]:
    from arcaeon.connect import catalog as C
    return [check_client(e) for e in C.CATALOG]


def check_journal() -> dict:
    from arcaeon import journal
    if not journal.enabled():
        return _check("journal", OK, "off (ARCAEON_JOURNAL=0), nothing is written")
    home = journal.home()
    if not home.exists():
        parent = home.parent
        while not parent.exists() and parent != parent.parent:
            parent = parent.parent
        if parent.exists() and os.access(parent, os.W_OK):
            return _check("journal", OK, f"{home} is not there yet; its parent is writable")
        return _check("journal", NO, f"{home} is not there and {parent} is not writable")
    if not home.is_dir():
        return _check("journal", NO, f"{home} is a file, not a directory")
    try:
        fd, tmp = tempfile.mkstemp(prefix=".doctor-", dir=str(home))
        os.close(fd)
        os.unlink(tmp)
    except OSError as e:
        return _check("journal", NO, f"{home} is not writable ({e.strerror or type(e).__name__})")
    return _check("journal", OK, f"{home} is writable")


def run() -> list[dict]:
    return [check_python(), *check_extras(), check_key(), check_serve(),
            *check_clients(), check_journal()]


def report(checks: list[dict]) -> dict:
    blind = [c for c in checks if c["status"] == CNL]
    out = {"checks": checks, "could_not_look": len(blind)}
    if blind:
        out = {"verdict": V.COULD_NOT_LOOK, "ok": None, **out}
    else:
        out = {"ok": True, **out}
    out["exit"] = V.EXIT_COULD_NOT_LOOK if blind else V.EXIT_GOOD
    return out


def render(rep: dict) -> str:
    width = max(len(c["check"]) for c in rep["checks"])
    lines = [f"{c['check']:<{width}}  {c['status']:<14}  {c['detail']}" for c in rep["checks"]]
    if rep["could_not_look"]:
        lines.append(f"{V.COULD_NOT_LOOK}: {rep['could_not_look']} check(s) could not be "
                     "looked at (exit 3)")
    else:
        lines.append("every check was read (exit 0)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(a in ("-h", "--help") for a in argv):
        print(USAGE)
        return V.EXIT_GOOD
    bad = [a for a in argv if a != "--json"]
    if bad:
        print(f"arcaeon doctor: unknown argument {bad[0]!r}\n{USAGE}", file=sys.stderr)
        return V.EXIT_USAGE
    rep = report(run())
    print(json.dumps(rep, indent=1) if "--json" in argv else render(rep))
    return rep["exit"]


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
