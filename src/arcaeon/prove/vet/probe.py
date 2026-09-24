"""Live probe harness: connect to an MCP server over stdio, list its tools, and
run every registered dynamic check against each one. Added 2026-09-05.

This is the first code in mcp_vet that CALLS a server. Everything else here
reads bytes; the guarantees that rest on that (re-runnable grade keyed to
`source_sha256`, "no network call, no LLM" on the free badge) do not hold for
a probe, which is why it is its own verb with its own artifact shape and is
never folded into scan / grade / badge. The artifact says "as observed at T",
the way `audit-verify` says "bounded" instead of pretending certainty.

Guardrails, all of them enforced HERE rather than trusted to the check:
  - a tool is called only if it says `readOnlyHint: true` (the check skips the
    rest, and the harness refuses the call as a second fence);
  - a global cap on total calls (default 40), stated in the artifact when hit;
  - a per-call timeout;
  - bounded backoff on results whose error text mentions 429 / rate;
  - a connection or auth failure is a BLIND SPOT and a non-zero exit, never a
    finding and never a pass.

The SDK is imported lazily inside `run_probe`, so this module imports fine in
an install without the [mcp] extra and the CLI can print a plain message.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import __version__
from .badge_cli import NOT_A_CERTIFICATION
from .dynamic_checks import DYNAMIC_CHECKS, dynamic_check_names

DEFAULT_MAX_CALLS = 40
DEFAULT_TIMEOUT = 20.0
# Retries on a rate-limit reply. Three sleeps, doubling from `backoff_base`,
# then the call is reported as the error it was. Every attempt counts against
# the cap: a server that rate-limits us is still being called.
RATE_RETRIES = 3

SCOPE_NOTE = (
    "One observation at observed_at against a live server, which may answer "
    "differently later. Only tools annotated readOnlyHint=true whose control "
    "call returned more than one item were probed; everything else is listed "
    "in blind_spots, not counted as passing. A clean result means only that "
    "what we were allowed to test binds. Cardinality is compared, not values: "
    "a filter that shrinks to the right count and the wrong rows still passes."
)
SITE_CONVENTION = (
    "findings[].file is the TOOL NAME and findings[].line is 0: a live probe "
    "has no source line to point at."
)


class CapReached(Exception):
    """Raised by `ProbeSession.call` when the global call cap is exhausted."""


@dataclass
class CallOutcome:
    """What one tool call came back as. `error` is None on a success result;
    otherwise the error text (an `isError` result's content, a timeout, a
    transport failure). `cardinality` is filled only on success."""
    error: str | None
    cardinality: int | None = None


@dataclass
class ProbeSession:
    """The duck-typed `session` a dynamic check receives. Wraps the SDK client
    with the cap, the timeout, the backoff, the read-only fence, and the
    blind-spot list. Checks call `call()` and `blind_spot()`; nothing else."""
    client: object
    loop: object
    max_calls: int = DEFAULT_MAX_CALLS
    timeout: float = DEFAULT_TIMEOUT
    backoff_base: float = 1.0
    calls_made: int = 0
    cap_hit: bool = False
    blind_spots: list = field(default_factory=list)
    read_only_tools: set = field(default_factory=set)
    # Every call the probe made, in order: (tool, args, error). The artifact
    # does not carry it; tests and a curious operator read it.
    call_log: list = field(default_factory=list)

    def blind_spot(self, tool: str | None, reason: str) -> None:
        self.blind_spots.append({"tool": tool, "reason": reason})

    def call(self, name: str, arguments: dict) -> CallOutcome:
        # Second fence, independent of the check's own readOnlyHint test: the
        # harness will not place a call to a tool it has not seen annotated
        # read-only, whatever a check asks for.
        if name not in self.read_only_tools:
            raise RuntimeError("probe refused to call %r: not annotated "
                               "readOnlyHint=true" % name)
        attempt = 0
        while True:
            if self.calls_made >= self.max_calls:
                self.cap_hit = True
                raise CapReached()
            self.calls_made += 1
            outcome = self.loop.run_until_complete(
                _call_once(self.client, name, arguments, self.timeout))
            self.call_log.append((name, dict(arguments), outcome.error))
            if outcome.error is None or not _looks_rate_limited(outcome.error):
                return outcome
            attempt += 1
            if attempt > RATE_RETRIES:
                return outcome
            time.sleep(self.backoff_base * (2 ** (attempt - 1)))


def _looks_rate_limited(text: str) -> bool:
    t = text.lower()
    return "429" in t or "rate" in t


def _leaf_error(exc: BaseException) -> str:
    """`Type: text` for the innermost cause. anyio wraps a dead server
    process in an ExceptionGroup whose own message ("unhandled errors in a
    TaskGroup") says nothing; the leaf is the line an operator can act on."""
    seen = 0
    while getattr(exc, "exceptions", None) and seen < 10:
        exc = exc.exceptions[0]
        seen += 1
    return "%s: %s" % (type(exc).__name__, str(exc)[:300])


def _error_text(result) -> str:
    parts = []
    for block in getattr(result, "content", None) or []:
        t = getattr(block, "text", None)
        if isinstance(t, str):
            parts.append(t)
    return " ".join(parts)[:500] or "tool returned isError with no text"


async def _call_once(client, name: str, arguments: dict, timeout: float) -> CallOutcome:
    from .dynamic_checks import cardinality
    try:
        result = await client.call_tool(name, arguments, read_timeout_seconds=timeout)
    except Exception as exc:                    # timeout, transport, protocol error
        return CallOutcome(error=_leaf_error(exc))
    if getattr(result, "is_error", False):
        return CallOutcome(error=_error_text(result))
    return CallOutcome(error=None,
                       cardinality=cardinality(getattr(result, "structured_content", None),
                                               getattr(result, "content", None) or []))


def _artifact(server_command: list, *, connected: bool, tools_listed: int,
              tools_probed: int, session: ProbeSession | None, findings: list,
              blind_spots: list, max_calls: int) -> dict:
    return {
        "kind": "mcp_vet_probe",
        "tool": "mcp_vet",
        "tool_version": __version__,
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "server_command": list(server_command),
        "connected": connected,
        "tools_listed": tools_listed,
        "tools_probed": tools_probed,
        "calls_made": session.calls_made if session else 0,
        "call_cap": max_calls,
        "cap_hit": bool(session.cap_hit) if session else False,
        "findings": [f.as_dict() for f in findings],
        "blind_spots": blind_spots,
        "dynamic_checks_run": dynamic_check_names(),
        "site_convention": SITE_CONVENTION,
        "scope_note": SCOPE_NOTE,
        "not_a_certification": NOT_A_CERTIFICATION,
    }


def run_probe(server_command: list, *, cwd=None, max_calls: int = DEFAULT_MAX_CALLS,
              timeout: float = DEFAULT_TIMEOUT, backoff_base: float = 1.0,
              env: dict | None = None, call_log: list | None = None) -> dict:
    """Probe one server and return the artifact dict. Never raises on the
    server's account: a connection failure comes back as `connected: false`
    plus a blind spot. Raises ImportError (uncaught, on purpose) when the SDK
    is not installed so the CLI can say so plainly.

    `call_log`, if a list is passed, receives every call the probe made as
    (tool, args, error) in order. It is for tests and a curious operator; the
    artifact never carries it."""
    from mcp import Client, StdioServerParameters, stdio_client

    if not server_command:
        raise ValueError("probe needs a server command")
    params = StdioServerParameters(command=server_command[0],
                                   args=list(server_command[1:]),
                                   cwd=cwd, env=env)
    loop = asyncio.new_event_loop()
    try:
        return _run_on_loop(loop, Client, stdio_client, params, server_command,
                            max_calls, timeout, backoff_base, call_log)
    finally:
        loop.close()


def _run_on_loop(loop, Client, stdio_client, params, server_command,
                 max_calls, timeout, backoff_base, call_log=None) -> dict:
    client = Client(stdio_client(params), read_timeout_seconds=timeout)
    try:
        loop.run_until_complete(client.__aenter__())
    except Exception as exc:
        # Auth and connection failures land here (dead process, missing
        # command, handshake timeout). Blind spot, not a finding, not a pass.
        return _artifact(server_command, connected=False, tools_listed=0,
                         tools_probed=0, session=None, findings=[],
                         blind_spots=[{"tool": None,
                                       "reason": "connection failed: " + _leaf_error(exc)}],
                         max_calls=max_calls)
    session = ProbeSession(client=client, loop=loop, max_calls=max_calls,
                           timeout=timeout, backoff_base=backoff_base)
    if call_log is not None:
        session.call_log = call_log
    findings: list = []
    tools: list = []
    tools_probed = 0
    try:
        try:
            tools = list(loop.run_until_complete(client.list_tools()).tools)
        except Exception as exc:
            session.blind_spot(None, "tools/list failed: " + _leaf_error(exc))
            tools = []
        for t in tools:
            ann = getattr(t, "annotations", None)
            if ann is not None and getattr(ann, "read_only_hint", None) is True:
                session.read_only_tools.add(t.name)

        for i, t in enumerate(tools):
            before = session.calls_made
            try:
                for _name, fn in DYNAMIC_CHECKS:
                    findings.extend(fn(session, t))
            except CapReached:
                session.blind_spot(t.name, "call cap (%d) reached before this "
                                           "tool was fully probed" % max_calls)
                for rest in tools[i + 1:]:
                    session.blind_spot(rest.name, "not probed: call cap (%d) "
                                                  "reached" % max_calls)
                break
            finally:
                if session.calls_made > before:
                    tools_probed += 1
    finally:
        try:
            loop.run_until_complete(client.__aexit__(None, None, None))
        except Exception:
            pass
    return _artifact(server_command, connected=True, tools_listed=len(tools),
                     tools_probed=tools_probed, session=session,
                     findings=findings, blind_spots=session.blind_spots,
                     max_calls=max_calls)


def render_probe_text(art: dict) -> str:
    """The short human summary the CLI prints without --json."""
    lines = ["mcp-vet probe: %s" % " ".join(art["server_command"])]
    if not art["connected"]:
        lines.append("NOT CONNECTED: %s" % art["blind_spots"][0]["reason"])
    lines.append("tools listed %d, probed %d, calls %d/%d%s"
                 % (art["tools_listed"], art["tools_probed"], art["calls_made"],
                    art["call_cap"], " (CAP HIT, probe stopped early)" if art["cap_hit"] else ""))
    for f in art["findings"]:
        lines.append("[%s] %s @ tool %s: %s" % (f["severity"], f["check"], f["file"], f["detail"]))
    lines.append("%d finding(s), %d blind spot(s)" % (len(art["findings"]), len(art["blind_spots"])))
    for b in art["blind_spots"]:
        lines.append("  blind spot: %s: %s" % (b["tool"] or "(server)", b["reason"]))
    lines.append("dynamic checks run: %s" % ", ".join(art["dynamic_checks_run"]))
    lines.append("observed at %s. %s" % (art["observed_at"], art["scope_note"]))
    lines.append(art["not_a_certification"])
    return "\n".join(lines)
