# SPDX-License-Identifier: MIT
"""`arcaeon connect`: print the config an AI client needs (K018, K019).

    arcaeon connect --list [--json]
    arcaeon connect <client> [--os windows|macos|linux] [--json]
    arcaeon connect <client> --write|--undo|--check [--path FILE] [--json]

`connect <client>` prints the file it would change, the exact JSON it would
merge into it, and `nothing written (add --write to apply)`. It writes
nothing, creates nothing and only looks at whether the file is there.
`--os` previews another machine's path (`~` or `%APPDATA%` stand in for
its home unless ARCAEON_CONNECT_HOME names one).

`--write` (K020, connect/write.py) backs the file up byte for byte to
`<file>.arcaeon-bak-<UTC stamp>`, merges only the `arcaeon` entry, and
prints the keys it changed and the backup path. A file that does not parse
is COULD NOT LOOK, exit 3, `reason_word: "unreadable"`, never overwritten.
`--path FILE` writes that file instead of the catalog's.

`--undo` (K021) moves the newest backup back over the file, consuming it
(for a file `--write` created, it removes the file and any directory the
write made), so write then undo leaves the home byte-identical. `--check`
reads only and says `present` (exit 0), `absent` or `stale` (exit 1; stale:
the configured command no longer resolves), or COULD NOT LOOK (exit 3).

A client whose docs did not state the path is printed with `confirmed: NO`,
and `--write` refuses it (COULD NOT LOOK, exit 3, `reason_word:
"path_unconfirmed"`, nothing written) unless `--path` names the file.
"""
from __future__ import annotations

import json
import os
import sys

from arcaeon import verdict as V
from arcaeon.connect import catalog as C
from arcaeon.connect import write as W

USAGE = ("usage: arcaeon connect --list [--json]\n"
         "       arcaeon connect <client> [--os windows|macos|linux] [--json]\n"
         "       arcaeon connect <client> --write|--undo|--check [--path FILE] [--json]\n"
         "clients: " + ", ".join(C.names()))
NOTHING_WRITTEN = "nothing written (add --write to apply)"
ENTRY_NAME = "arcaeon"
DEFAULT_URL = "http://127.0.0.1:8787"
DEPLOY_LINE = "needs a public URL, which is a deploy decision"
ACTIONS = ("--write", "--undo", "--check")


def launch_form() -> dict:
    """How a client starts the arcaeon MCP server (K025 refines this)."""
    return {"command": "arcaeon", "args": ["mcp"]}


def server_entry(entry: C.Entry) -> dict:
    """The one `arcaeon` entry that goes under the client's key."""
    form = launch_form()
    if entry.key == "servers":                   # VS Code names the transport
        return {"type": "stdio", **form}
    return dict(form)


def merge_json(entry: C.Entry) -> dict:
    return {entry.key: {ENTRY_NAME: server_entry(entry)}}


def _serve_url() -> tuple[str, str]:
    from arcaeon import journal
    try:
        url = json.loads((journal.home() / "serve.json").read_text(encoding="utf-8")).get("url")
    except (OSError, ValueError, AttributeError):
        url = None
    if isinstance(url, str) and url:
        return url, "from serve.json, written by a running arcaeon serve"
    return DEFAULT_URL, "the default port; start it with `arcaeon serve`"


def plan(entry: C.Entry, os_name: str) -> dict:
    """Everything `connect <client>` prints, as data. Reads, never writes."""
    out = {"client": entry.name, "title": entry.title, "transport": entry.transport,
           "os": os_name, "confirmed": C.confirmed_for(entry, os_name),
           "doc_url": entry.doc_url, "read_date": entry.read_date, "note": entry.note,
           "written": False}
    if entry.writes_file:
        path = C.config_path(entry, os_name)
        out["file"] = path
        out["exists"] = (os.path.isfile(path) if os_name == C.current_os() else None)
        out["merge"] = merge_json(entry)
    elif entry.transport == "http-openapi":
        from arcaeon import journal
        url, source = _serve_url()
        out.update({"url": url, "url_source": source, "openapi_url": url + "/openapi.json",
                    "token_file": str(journal.home() / "serve.token")})
    else:
        out["reason"] = (f"{entry.title} reaches outside tools only at a public HTTPS "
                         "address (a connector or a GPT Action); arcaeon serve binds "
                         f"127.0.0.1 only, so it {DEPLOY_LINE}")
    return out


def render(p: dict) -> str:
    lines = [f"arcaeon connect {p['client']}  ({p['title']}, {p['transport']}, {p['os']})"]
    if "file" in p:
        state = {True: "exists", False: "not there yet", None: "on another machine"}[p["exists"]]
        lines.append(f"file: {p['file']}  ({state})")
    conf = ("yes" if p["confirmed"] else
            "NO, the client's docs did not state this path; check it before --write")
    lines.append(f"confirmed: {conf}")
    lines.append(f"source: {p['doc_url']} (read {p['read_date']})")
    if p.get("note"):
        lines.append(f"note: {p['note']}")
    if "merge" in p:
        lines.append(f"would merge (only the {ENTRY_NAME!r} entry; every other key stays):")
        lines.append(json.dumps(p["merge"], indent=2))
    elif "url" in p:
        lines.append(f"url: {p['url']}  ({p['url_source']})")
        lines.append(f"openapi: {p['openapi_url']}")
        lines.append(f"token: {p['token_file']}  (`arcaeon serve --print-token` prints it; "
                     "send it as `Authorization: Bearer <token>`)")
    else:
        lines.append(p["reason"])
    lines.append(NOTHING_WRITTEN)
    return "\n".join(lines)


def _cnl(entry: C.Entry, file, reason_word: str, reason: str) -> dict:
    return {"client": entry.name, "action": "write", "verdict": V.COULD_NOT_LOOK,
            "reason_word": reason_word, "reason": reason, "file": file,
            "written": False, "exit": V.EXIT_COULD_NOT_LOOK}


def do_write(entry: C.Entry, os_name: str, path: str | None) -> dict:
    """--write, as data. A path the client's docs did not state is refused
    unless `path` names the file."""
    file = path or C.config_path(entry, os_name)
    if path is None and not C.confirmed_for(entry, os_name):
        return _cnl(entry, file, "path_unconfirmed",
                    f"{entry.title}'s docs did not state {file}; check where it keeps "
                    "its config and pass --path FILE")
    res = W.write(file, entry.key, ENTRY_NAME, server_entry(entry))
    return {"client": entry.name, "title": entry.title, "transport": entry.transport,
            "os": os_name, "action": "write", **res}


def render_write(r: dict) -> str:
    lines = [f"arcaeon connect {r['client']} --write"]
    if r.get("file"):
        lines.append(f"file: {r['file']}")
    if r.get("verdict") == V.COULD_NOT_LOOK:
        lines.append(f"{V.COULD_NOT_LOOK} ({r['reason_word']}): {r['reason']}")
        lines.append("nothing written")
        return "\n".join(lines)
    if r.get("already"):
        lines.append(f"the {ENTRY_NAME!r} entry is already there, the same; nothing written")
        return "\n".join(lines)
    if r.get("backup_kind") == "absent":
        lines.append(f"backup: {r['backup']}  (the file was not there; "
                     f"`arcaeon connect {r['client']} --undo` removes it again)")
    else:
        lines.append(f"backup: {r['backup']}  (a byte-for-byte copy; "
                     f"`arcaeon connect {r['client']} --undo` puts it back)")
    for c in r["changed"]:
        lines.append(f"changed: {c['key']} ({c['change']})")
    lines.append("written")
    return "\n".join(lines)


def do_undo(entry: C.Entry, os_name: str, path: str | None) -> dict:
    file = path or C.config_path(entry, os_name)
    return {"client": entry.name, "os": os_name, "action": "undo", **W.undo(file)}


def do_check(entry: C.Entry, os_name: str, path: str | None) -> dict:
    file = path or C.config_path(entry, os_name)
    return {"client": entry.name, "os": os_name, "action": "check",
            "confirmed": path is not None or C.confirmed_for(entry, os_name),
            **W.check(file, entry.key, ENTRY_NAME, server_entry(entry))}


def render_other(r: dict) -> str:
    lines = [f"arcaeon connect {r['client']} --{r['action']}", f"file: {r['file']}"]
    if r.get("verdict") == V.COULD_NOT_LOOK:
        lines.append(f"{V.COULD_NOT_LOOK} ({r['reason_word']}): {r['reason']}")
        lines.append("nothing changed" if r["action"] == "undo" else "nothing checked")
    elif r["action"] == "undo":
        if r["backup_kind"] == "absent":
            lines.append(f"removed the file: it was not there before --write "
                         f"({r['restored']} consumed)")
        else:
            lines.append(f"restored: {r['restored']}  (the backup is consumed)")
        lines.append(f"backups left: {r['backups_left']}")
    else:
        why = {"present": f"command {r.get('command')!r} resolves",
               "absent": ("no arcaeon entry" if r["exists"] else "the file is not there"),
               "stale": f"command {r.get('command')!r} does not resolve here"}[r["state"]]
        if r["state"] == "present" and not r.get("matches", True):
            why += "; differs from what --write would put there now"
        lines.append(f"state: {r['state']}  ({why})")
        if not r["confirmed"]:
            lines.append("confirmed: NO, the client's docs did not state this path")
    return "\n".join(lines)


def _usage(msg: str) -> int:
    print(f"arcaeon connect: {msg}\n{USAGE}", file=sys.stderr)
    return V.EXIT_USAGE


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(a in ("-h", "--help") for a in argv):
        print(USAGE)
        return V.EXIT_GOOD
    as_json = "--json" in argv
    if "--list" in argv:
        extra = [a for a in argv if a not in ("--list", "--json")]
        if extra:
            return _usage(f"--list takes no {extra[0]!r}")
        if as_json:
            print(json.dumps({"os": C.current_os(), "clients": C.list_rows()}, indent=1))
        else:
            print(C.render_list())
        return V.EXIT_GOOD
    os_name, pos, i = C.current_os(), [], 0
    actions, path = [], None
    while i < len(argv):
        a = argv[i]
        if a in ("--os", "--path") or a.startswith(("--os=", "--path=")):
            flag = a.split("=", 1)[0]
            val = a.split("=", 1)[1] if "=" in a else (argv[i + 1] if i + 1 < len(argv) else "")
            i += 1 if "=" in a else 2
            if flag == "--path":
                if not val:
                    return _usage("--path takes a file")
                path = val
                continue
            if val not in C.OSES:
                return _usage(f"--os takes one of {', '.join(C.OSES)}")
            os_name = val
            continue
        if a == "--json":
            i += 1
            continue
        if a in ACTIONS:
            actions.append(a)
            i += 1
            continue
        if a.startswith("-"):
            return _usage(f"unknown option {a!r}")
        pos.append(a)
        i += 1
    if len(pos) != 1:
        return _usage("name one client" if not pos else "name one client, not several")
    entry = C.get(pos[0])
    if entry is None:
        return _usage(f"no client {pos[0]!r}")
    if len(actions) > 1:
        return _usage(f"{actions[0]} and {actions[1]} do not go together")
    if not actions:
        if path is not None:
            return _usage("--path goes with --write, --undo or --check")
        p = plan(entry, os_name)
        print(json.dumps(p, indent=1) if as_json else render(p))
        return V.EXIT_GOOD
    if not entry.writes_file:
        return _usage(f"{entry.name} has no config file to write")
    if os_name != C.current_os():
        return _usage(f"{actions[0]} acts on this machine ({C.current_os()}) only; "
                      "--os is for previews")
    if actions[0] == "--write":
        r = do_write(entry, os_name, path)
        print(json.dumps(r, indent=1) if as_json else render_write(r))
        return r["exit"]
    r = (do_undo if actions[0] == "--undo" else do_check)(entry, os_name, path)
    print(json.dumps(r, indent=1) if as_json else render_other(r))
    return r["exit"]
