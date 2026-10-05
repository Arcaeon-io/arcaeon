# SPDX-License-Identifier: MIT
"""arcaeon.connect.docker_after: the Docker MCP Gateway after-interceptor (L4-03).

    docker mcp gateway run \\
        --interceptor 'after:exec:arcaeon gate mcp-after --config /cfg/arcaeon-gateway.json'

    arcaeon gate mcp-after [--config FILE] [--tool NAME]
                           [--action {read,act,pay,irreversible}] [--enforce {warn,block}]
    python -m arcaeon.connect.docker_after ...          (the same)

Docker MCP Gateway hands an `after:` interceptor the tool-call response JSON
on stdin and takes what it prints on stdout as the response. This reads it,
runs arcaeon.connect.mcp_result.verify_tool_result on the tool result and
prints the result back: unchanged but for _meta["dev.arcaeon/verdict"] when
allowed, replaced by an isError REFUSED result when refused (block mode).
One line naming the verdict goes to stderr for the gateway's log.

WHAT IT READS on stdin, one JSON object:

    a CallToolResult                       checked and rewritten
    a JSON-RPC response {"result": ...}    its result checked and rewritten in place
    a JSON-RPC error    {"error": ...}     passed through unchanged (no tool result)
    {"request": ..., "response": ...}      the response checked; the tool name read
                                           from request.params.name

ALWAYS JSON BACK. Exit 0 for any stdin: empty, not JSON, not UTF-8, a
duplicate key, not an object, over MAX_STDIN_BYTES: each is a COULD NOT LOOK
refusal result, never a traceback. Bad arguments or a config that cannot be
read print a refusal result too, and exit 2, with the reason on stderr.

THE TOOL NAME picks the action from the config's `tools`. It is --tool, else
request.params.name / params.name in the input. When the gateway hands
neither, every result is held to default_action (default act).
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

from arcaeon import verdict as V
from arcaeon.connect.mcp_result import GatewayConfig, refusal_result, verify_tool_result
from arcaeon.record.row import loads_strict

__all__ = ["main", "MAX_STDIN_BYTES", "CONFIG_ENV", "USAGE", "rewrite"]

CONFIG_ENV = "ARCAEON_GATEWAY_CONFIG"
MAX_STDIN_BYTES = 32 << 20
USAGE = """usage: arcaeon gate mcp-after [--config FILE] [--tool NAME]
                              [--action {read,act,pay,irreversible}]
                              [--enforce {warn,block}]"""
_SPEC = {"--config": "config", "--tool": "tool", "--action": "action", "--enforce": "enforce"}


class _Usage(Exception):
    pass


def _parse(argv: list[str]) -> dict:
    out: dict[str, Any] = {}
    i = 0
    while i < len(argv):
        a = argv[i]
        key, sep, val = a.partition("=")
        if key not in _SPEC:
            raise _Usage(f"unknown argument {a!r}")
        if not sep:
            i += 1
            if i >= len(argv):
                raise _Usage(f"{key} needs a value")
            val = argv[i]
        out[_SPEC[key]] = val
        i += 1
    return out


def _cnl_summary(reason: str, looked_for: str, word: str) -> dict:
    return {"verdict": V.COULD_NOT_LOOK, "decision": "refuse", "action": None, "tool": None,
            "reason": f"refuse: COULD NOT LOOK: {reason}", "reasons": [reason],
            "could_not_check": {"looked_for": looked_for, "where": "stdin",
                                "reason_word": word},
            "would_refuse": True, "warning": None, "enforce_mode": "block",
            "enforce_source": "default", "enforce_detail": "nothing to check: block"}


def _tool_name(obj: dict) -> str | None:
    for holder in (obj.get("request"), obj):
        params = holder.get("params") if isinstance(holder, dict) else None
        name = params.get("name") if isinstance(params, dict) else None
        if isinstance(name, str):
            return name
    return None


def rewrite(obj: Any, *, config: GatewayConfig, tool: str | None = None,
            action: str | None = None, enforce: str | None = None,
            _depth: int = 0) -> tuple[Any, dict | None]:
    """(the object to print, the decision or None when passed through untouched)."""
    if not isinstance(obj, dict):
        return verify_tool_result(obj, config=config, tool=tool, action=action,
                                  enforce=enforce)
    tool = tool or _tool_name(obj)
    for slot in ("result", "response"):
        if _depth < 2 and isinstance(obj.get(slot), dict):
            new, d = rewrite(obj[slot], config=config, tool=tool, action=action,
                             enforce=enforce, _depth=_depth + 1)
            return {**obj, slot: new}, d
    if "error" in obj and "jsonrpc" in obj:
        return obj, None                         # a JSON-RPC error: no tool result to check
    return verify_tool_result(obj, config=config, tool=tool, action=action, enforce=enforce)


def _emit(stdout, obj) -> None:
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    if hasattr(stdout, "buffer"):
        stdout = stdout.buffer
    stdout.write(data)
    stdout.flush()


def main(argv: list[str] | None = None, *, stdin=None, stdout=None, stderr=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    stdin = stdin if stdin is not None else sys.stdin.buffer
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr
    if any(a in ("-h", "--help") for a in argv):
        print(USAGE + "\n" + (__doc__ or ""), file=stderr)
        return V.EXIT_GOOD
    try:
        opts = _parse(argv)
        path = opts.get("config") or os.environ.get(CONFIG_ENV)
        cfg = GatewayConfig.from_file(path) if path else GatewayConfig()
        if opts.get("enforce") is not None:
            from arcaeon.prove import gate_mode
            gate_mode.resolve(opts["enforce"])           # ValueError on an unknown word
        if opts.get("action") is not None:
            GatewayConfig.from_dict({"default_action": opts["action"]})
    except (_Usage, ValueError, OSError) as e:
        print(f"arcaeon gate mcp-after: {e}\n{USAGE}", file=stderr)
        _emit(stdout, refusal_result(_cnl_summary(
            f"the interceptor could not start ({str(e)[:200]})",
            "a readable interceptor config", "unreadable")))
        return V.EXIT_USAGE
    obj, why = None, None
    try:
        raw = stdin.read(MAX_STDIN_BYTES + 1)
    except Exception as e:  # noqa: BLE001
        raw, why = None, f"stdin could not be read ({type(e).__name__})"
    if raw is None:
        why = why or "stdin could not be read"
    elif len(raw) > MAX_STDIN_BYTES:
        why = f"the response is over {MAX_STDIN_BYTES} bytes; not read"
    elif not raw.strip():
        why = "stdin was empty: no response to check"
    else:
        try:
            obj = loads_strict(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as e:
            why = (f"the response is not one JSON object ({str(e)[:120]}); a duplicate key "
                   f"counts, since two readers would see two responses")
        if why is None and not isinstance(obj, dict):
            why = "the response is not a JSON object"
    if why is not None:
        summary = _cnl_summary(why, "the tool-call response JSON on stdin", "unreadable")
        _emit(stdout, refusal_result(summary))
        print(f"arcaeon mcp-after: {V.COULD_NOT_LOOK} refuse: {why}", file=stderr)
        return V.EXIT_GOOD
    try:
        out, d = rewrite(obj, config=cfg, tool=opts.get("tool"), action=opts.get("action"),
                         enforce=opts.get("enforce"))
    except Exception as e:  # noqa: BLE001  never a traceback, never a green
        why = f"the check could not finish ({type(e).__name__})"
        _emit(stdout, refusal_result(_cnl_summary(why, "a finished check", "unreadable")))
        print(f"arcaeon mcp-after: {V.COULD_NOT_LOOK} refuse: {why}", file=stderr)
        return V.EXIT_GOOD
    _emit(stdout, out)
    if d is None:
        print("arcaeon mcp-after: a JSON-RPC error, passed through", file=stderr)
    else:
        print(f"arcaeon mcp-after: {d['verdict']} {d['decision']} {d['action']}"
              + (f" (tool {d['tool']})" if d.get("tool") else "")
              + (f" [{d['enforce_mode']} from {d['enforce_source']}]")
              + (" WARNING: would refuse in block mode" if d.get("warning") else ""),
              file=stderr)
    return V.EXIT_GOOD


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
