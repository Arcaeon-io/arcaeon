# SPDX-License-Identifier: MIT
"""The client catalog for `arcaeon connect` (K018).

One Entry per AI client. For each: the config file per OS (a template over
{home}, {appdata} and {xdg_config}), the top-level key the arcaeon entry
goes under, the transport, and the public doc page the path was read from
with the date it was read. `confirmed` is per OS: True only where that page
states the path in words; a path taken from anywhere else is False, and
`connect` prints that it is unconfirmed.

Transports:
    stdio-mcp          the client starts `arcaeon mcp` itself and speaks MCP
                       over stdin/stdout
    http-openapi       the caller reads GET /openapi.json from a running
                       `arcaeon serve` and calls its routes
    remote-connector   the client only reaches tools at a public HTTPS
                       address; the loopback server is not one, so connect
                       writes nothing for it

ARCAEON_CONNECT_HOME replaces the home directory (tests, and trying the
command on a copy): with it set, {appdata} is <home>/AppData/Roaming and
{xdg_config} is <home>/.config, whatever APPDATA and XDG_CONFIG_HOME say, so
nothing outside that directory is ever named.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath

__all__ = ["Entry", "CATALOG", "OSES", "HOME_ENV", "TRANSPORTS", "DEPLOY_LINE",
           "GPT_ACTION_MANIFEST", "GPT_ACTION_COMMAND", "REMOTE_LINES", "names", "get",
           "current_os", "home", "config_path", "confirmed_for", "list_rows",
           "render_list"]

HOME_ENV = "ARCAEON_CONNECT_HOME"
OSES = ("windows", "macos", "linux")
TRANSPORTS = ("stdio-mcp", "http-openapi", "remote-connector")
READ_DATE = "2026-09-27"

#: K024. ChatGPT reaches outside tools only through a remote connector or a
#: GPT Action, both at a public HTTPS address. The GPT Action manifest is
#: generated from the route table (K084) and committed at this path.
DEPLOY_LINE = "needs a public URL, which is a deploy decision"
GPT_ACTION_MANIFEST = "docs/schemas/gpt_action_openapi.json"
GPT_ACTION_COMMAND = "arcaeon schema --format gpt-action --out gpt_action.json"
REMOTE_LINES = (
    "ChatGPT reaches outside tools through remote connectors or GPT Actions, and both "
    "need a public HTTPS address.",
    "arcaeon serve binds 127.0.0.1 only (loopback), so it is not one.",
    f"GPT Action manifest: {GPT_ACTION_MANIFEST} in the source tree, or "
    f"`{GPT_ACTION_COMMAND}`; its server url is a placeholder to replace.",
    DEPLOY_LINE,
)


@dataclass(frozen=True)
class Entry:
    name: str
    title: str
    transport: str
    #: The top-level key the arcaeon entry goes under; None: no config file.
    key: str | None
    #: OS -> path template, or None where the client keeps no file.
    paths: dict = field(default_factory=dict)
    #: OS -> True if the doc page states that path in words.
    confirmed: dict = field(default_factory=dict)
    doc_url: str = ""
    read_date: str = READ_DATE
    note: str = ""

    @property
    def writes_file(self) -> bool:
        return self.key is not None and any(self.paths.values())


def _all(template: str) -> dict:
    return {o: template for o in OSES}


def _yes(*oses) -> dict:
    return {o: o in oses for o in OSES}


CATALOG: tuple[Entry, ...] = (
    Entry("claude-desktop", "Claude Desktop", "stdio-mcp", "mcpServers",
          {"windows": "{appdata}/Claude/claude_desktop_config.json",
           "macos": "{home}/Library/Application Support/Claude/claude_desktop_config.json",
           "linux": "{xdg_config}/Claude/claude_desktop_config.json"},
          _yes("windows", "macos"),
          "https://modelcontextprotocol.io/quickstart/user",
          note="the page names the macOS and Windows files only; there is no "
               "Linux build it documents"),
    Entry("claude-code", "Claude Code", "stdio-mcp", "mcpServers",
          _all("{home}/.claude.json"), _yes(*OSES),
          "https://code.claude.com/docs/en/mcp",
          note="user scope; a project's own .mcp.json takes the same mcpServers key"),
    Entry("cursor", "Cursor", "stdio-mcp", "mcpServers",
          _all("{home}/.cursor/mcp.json"), _yes(*OSES),
          "https://cursor.com/docs/context/mcp",
          note="global file; a project's .cursor/mcp.json takes the same key"),
    Entry("windsurf", "Windsurf (Cascade)", "stdio-mcp", "mcpServers",
          {"windows": "{appdata}/devin/mcp_config.json",
           "macos": "{xdg_config}/devin/mcp_config.json",
           "linux": "{xdg_config}/devin/mcp_config.json"},
          _yes(*OSES),
          "https://docs.windsurf.com/windsurf/cascade/mcp",
          note="the Windsurf page now redirects to docs.devin.ai/desktop/cascade/mcp, "
               "which gives these paths; builds from before the move read "
               "~/.codeium/windsurf/mcp_config.json"),
    Entry("vscode", "VS Code (Copilot agent mode)", "stdio-mcp", "servers",
          {"windows": "{appdata}/Code/User/mcp.json",
           "macos": "{home}/Library/Application Support/Code/User/mcp.json",
           "linux": "{xdg_config}/Code/User/mcp.json"},
          _yes(),
          "https://code.visualstudio.com/docs/copilot/customization/mcp-servers",
          note="the page confirms the `servers` key and a user-profile mcp.json, but "
               "reaches it through `MCP: Open User Configuration`, not by path; a "
               "workspace's .vscode/mcp.json takes the same key"),
    Entry("gemini-cli", "Gemini CLI", "stdio-mcp", "mcpServers",
          _all("{home}/.gemini/settings.json"), _yes(*OSES),
          "https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md",
          note="user settings; a project's .gemini/settings.json takes the same key"),
    Entry("chatgpt", "ChatGPT", "remote-connector", None, {}, _yes(*OSES),
          "https://developers.openai.com/plugins/deploy/connect-chatgpt",
          note="the page also names a Secure MCP Tunnel, which arcaeon does not "
               "set up"),
    Entry("generic-http", "Any HTTP / OpenAPI framework", "http-openapi", None, {},
          _yes(*OSES),
          "https://spec.openapis.org/oas/v3.1.0",
          note="no file to change: point the framework at GET /openapi.json on a "
               "running `arcaeon serve`"),
)

_BY_NAME = {e.name: e for e in CATALOG}
assert len(_BY_NAME) == len(CATALOG), "one entry per client name"
assert all(e.transport in TRANSPORTS for e in CATALOG)


def names() -> list[str]:
    return [e.name for e in CATALOG]


def get(name: str) -> Entry | None:
    return _BY_NAME.get(name)


def current_os() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def home() -> Path:
    """$ARCAEON_CONNECT_HOME, else the user's home directory."""
    override = os.environ.get(HOME_ENV, "").strip()
    return Path(override) if override else Path.home()


def _bases(os_name: str, home_dir: str | None) -> dict:
    """{home}, {appdata}, {xdg_config} for `os_name`, as strings in its form.

    A given home (the argument, else ARCAEON_CONNECT_HOME) is taken as written
    and fixes all three. Without one: this OS reads the real home, APPDATA and
    XDG_CONFIG_HOME; another OS (a preview for a different machine) gets the
    placeholders a user would type there, `~` or `%USERPROFILE%`/`%APPDATA%`."""
    pure = PureWindowsPath if os_name == "windows" else PurePosixPath
    h = home_dir if home_dir is not None else (os.environ.get(HOME_ENV, "").strip() or None)
    if h is not None:
        return {"home": str(pure(h)), "appdata": str(pure(h, "AppData", "Roaming")),
                "xdg_config": str(pure(h, ".config"))}
    if os_name != current_os():
        if os_name == "windows":
            return {"home": "%USERPROFILE%", "appdata": "%APPDATA%",
                    "xdg_config": str(pure("%USERPROFILE%", ".config"))}
        return {"home": "~", "appdata": "~/AppData/Roaming", "xdg_config": "~/.config"}
    h = str(Path.home())
    return {"home": str(pure(h)),
            "appdata": os.environ.get("APPDATA", "").strip() or str(pure(h, "AppData", "Roaming")),
            "xdg_config": (os.environ.get("XDG_CONFIG_HOME", "").strip()
                           or str(pure(h, ".config")))}


def config_path(entry: Entry, os_name: str | None = None,
                home_dir: str | None = None) -> str | None:
    """The config file `entry` keeps on `os_name` (default: this OS), or None.
    `home_dir` stands in for the home directory; the result is a path string
    in that OS's own form, and nothing is read or created."""
    os_name = os_name or current_os()
    tmpl = entry.paths.get(os_name)
    if not tmpl:
        return None
    b = _bases(os_name, home_dir)
    head, _, rest = tmpl.partition("/")
    root = b[head.strip("{}")] if head.startswith("{") else head
    pure = PureWindowsPath if os_name == "windows" else PurePosixPath
    return str(pure(root, *rest.split("/"))) if rest else str(pure(root))


def confirmed_for(entry: Entry, os_name: str | None = None) -> bool:
    return bool(entry.confirmed.get(os_name or current_os(), False))


def list_rows(os_name: str | None = None, home_dir: str | None = None) -> list[dict]:
    os_name = os_name or current_os()
    return [{"client": e.name, "title": e.title, "transport": e.transport, "key": e.key,
             "config": config_path(e, os_name, home_dir),
             "confirmed": confirmed_for(e, os_name), "doc_url": e.doc_url,
             "read_date": e.read_date, "note": e.note} for e in CATALOG]


def render_list(os_name: str | None = None, home_dir: str | None = None) -> str:
    rows = list_rows(os_name, home_dir)
    head = ("client", "transport", "confirmed", "config file")
    body = [(r["client"], r["transport"], "yes" if r["confirmed"] else "NO",
             r["config"] or "(none: nothing to write)") for r in rows]
    w = [max(len(x[i]) for x in [head, *body]) for i in range(3)]
    fmt = lambda x: f"{x[0]:<{w[0]}}  {x[1]:<{w[1]}}  {x[2]:<{w[2]}}  {x[3]}"  # noqa: E731
    lines = [fmt(head), *(fmt(x) for x in body)]
    if any(not r["confirmed"] for r in rows):
        lines.append("confirmed NO: the client's docs did not state that path; check it "
                     "before --write")
    return "\n".join(lines)
