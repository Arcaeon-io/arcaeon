# SPDX-License-Identifier: MIT
"""arcaeon.connect.docker_after: the Docker MCP Gateway after-interceptor (L4-03).

    docker mcp gateway run \\
        --interceptor 'after:exec:arcaeon gate mcp-after --config /cfg/arcaeon-gateway.json'

    arcaeon gate mcp-after [--config FILE] [--tool NAME]
                           [--action {read,act,pay,irreversible}] [--enforce {warn,block}]
    python -m arcaeon.connect.docker_after ...          (the same)

THE REAL CONTRACT (L4-05), read from github.com/docker/mcp-gateway at
a34df45d4ec0e941a9853ad768c4f6cd818966b3, pkg/interceptors/interceptors.go:

  * Only tools/call is intercepted (l.94).
  * stdin is json.Marshal of the *mcp.CallToolResult (l.119-122): a bare
    CallToolResult {"_meta"?, "content", "structuredContent"?, "isError"?}
    (go-sdk v1.4.1 protocol.go l.76-120). There is no JSON-RPC envelope, no
    request and no tool name. When the call itself failed, the response is
    nil and stdin is `null`.
  * The command runs as `/bin/sh -c <everything after "after:exec:">`
    (l.61-65, l.160-165).
  * Non-empty stdout is unmarshalled into mcp.CallToolResult and replaces the
    response (l.133-139). EMPTY stdout keeps the original response (l.142),
    so a refusal must never be empty.
  * A non-zero exit fails the call with "executing interceptor" (l.127-130),
    and stdout is dropped. That is fail closed, but the client sees a gateway
    error, not our REFUSED text.

WHAT THIS DOES: it runs arcaeon.connect.mcp_result.verify_tool_result on the
CallToolResult and prints a CallToolResult back. The result is unchanged
except for _meta["dev.arcaeon/verdict"] when allowed. It is replaced by an
isError REFUSED result when refused (block mode). One line naming the verdict
goes to stderr for the gateway's log.

    a CallToolResult (has "content")     checked and rewritten
    null                                 the gateway's own error: prints nothing,
                                         so the gateway returns that error unchanged
    anything else (a JSON-RPC envelope,  COULD NOT LOOK refusal: Docker never
    {"request","response"}, no content)  sends it (the old guessed shapes are gone)

ALWAYS JSON BACK for a result. Exit 0 for any stdin: empty, not JSON, not
UTF-8, a duplicate key, not an object, over MAX_STDIN_BYTES. Each one is a
COULD NOT LOOK refusal result, never a traceback. Bad arguments or a config
that cannot be read print a refusal result too, and exit 2 (the gateway
then fails the call), with the reason on stderr.

THE TOOL NAME picks the action from the config's `tools`. Only --tool sets
it. Docker does not send the name, and a name inside the result is the
server's word, so it is never read. One interceptor runs for every tool, so
without --tool every result is held to default_action (default act).
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

from arcaeon import verdict as V
from arcaeon.connect.mcp_result import (
    GatewayConfig,
    could_not_look_summary,
    refusal_result,
    verify_tool_result,
)
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


_cnl_summary = could_not_look_summary


def rewrite(obj: Any, *, config: GatewayConfig, tool: str | None = None,
            action: str | None = None, enforce: str | None = None) -> tuple[dict, dict]:
    """(the CallToolResult to print, the decision). `obj` must be the bare
    CallToolResult Docker writes. Go marshals `content` with no omitempty, so
    the key is always there. Anything without it is not that shape and is a
    COULD NOT LOOK refusal, whatever the action."""
    if not isinstance(obj, dict) or "content" not in obj:
        why = ("the input is not a CallToolResult (no `content`); Docker MCP Gateway writes "
               "a bare CallToolResult, never a JSON-RPC envelope or a request/response pair")
        summary = _cnl_summary(why, "a CallToolResult on stdin", "unreadable")
        return refusal_result(summary), summary
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
        if why is None and obj is None:
            # interceptors.go l.119-122/l.142: the call failed, json.Marshal(nil) is
            # `null`, and empty stdout hands the gateway's own error back unchanged.
            print("arcaeon mcp-after: stdin null: the tool call returned an error; "
                  "printed nothing, so the gateway's error passes through", file=stderr)
            return V.EXIT_GOOD
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
    print(f"arcaeon mcp-after: {d['verdict']} {d['decision']} {d['action']}"
          + (f" (tool {d['tool']})" if d.get("tool") else "")
          + (f" [{d['enforce_mode']} from {d['enforce_source']}]")
          + (" WARNING: would refuse in block mode" if d.get("warning") else ""),
          file=stderr)
    return V.EXIT_GOOD


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
