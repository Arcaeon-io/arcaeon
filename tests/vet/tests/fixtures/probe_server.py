"""Fixture MCP server for the live probe (test_probe.py). 2026-09-05.

Run with `python tests/fixtures/probe_server.py`; speaks MCP over stdio via
the SDK's MCPServer. Five tools, each one a case the probe must land in a
specific bucket:

  list_posts        readOnlyHint=true; `author_id` REALLY filters; unknown
                    keys are REJECTED (error result). Must draw no finding.
  list_comments     readOnlyHint=true; `user_id` is declared and IGNORED;
                    unknown keys are accepted silently. Must draw BOTH
                    sub-verdicts.
  get_post          readOnlyHint=true; returns exactly one item. Must be a
                    "naturally singular" blind spot, never a finding.
  create_post       NO annotation. Must be a blind spot and must NEVER be
                    called: every call appends a line to the file named by
                    $MCP_VET_PROBE_COUNTER, which the test asserts stays
                    absent.
  list_ratelimited  readOnlyHint=true; the FIRST call answers with a 429-style
                    error, every later call returns five rows; `status`
                    really filters and unknown keys are rejected. Exercises
                    the backoff path; must draw neither finding nor blind
                    spot, and its control call must show up TWICE in the
                    call log.

The SDK's MCPServer ignores unknown argument keys by default (observed on
mcp 2.0.0), which is exactly the behaviour list_comments needs and exactly
what list_posts must not have. So the strict tool is enforced one layer up:
`call_tool` is overridden to reject keys outside the declared schema before
the SDK sees them, and `list_tools` stamps `additionalProperties: false` on
that tool's schema so the contract is visible to a client too.
"""
from __future__ import annotations

import os

from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, TextContent, ToolAnnotations

STRICT_TOOLS = {"list_posts", "list_ratelimited"}
POSTS = [{"id": i, "author_id": "author-%d" % (i % 3), "title": "post %d" % i}
         for i in range(12)]
COMMENTS = [{"id": i, "user_id": "user-%d" % (i % 4), "body": "comment %d" % i}
            for i in range(9)]
_state = {"ratelimit_calls": 0}


class StrictOnSome(MCPServer):
    async def list_tools(self):
        tools = await super().list_tools()
        for t in tools:
            if t.name in STRICT_TOOLS:
                t.input_schema["additionalProperties"] = False
        return tools

    async def call_tool(self, name, arguments, context=None):
        if name in STRICT_TOOLS:
            declared = {t.name: t for t in await self.list_tools()}[name]
            extra = sorted(set(arguments or {}) - set(declared.input_schema.get("properties", {})))
            if extra:
                return CallToolResult(
                    content=[TextContent(type="text", text="unknown argument(s): %s" % extra)],
                    is_error=True)
        return await super().call_tool(name, arguments, context)


mcp = StrictOnSome("mcp_vet_probe_fixture")
RO = ToolAnnotations(read_only_hint=True)


@mcp.tool(annotations=RO)
def list_posts(author_id: str | None = None) -> list[dict]:
    """List posts, optionally filtered by author_id."""
    if author_id is None:
        return POSTS
    return [p for p in POSTS if p["author_id"] == author_id]


@mcp.tool(annotations=RO)
def list_comments(user_id: str | None = None) -> list[dict]:
    """List comments, optionally filtered by user_id."""
    return COMMENTS                      # user_id deliberately ignored


@mcp.tool(annotations=RO)
def get_post(post_id: int) -> dict:
    """Fetch one post by id."""
    return {"id": post_id, "title": "post %d" % post_id}


@mcp.tool()
def create_post(title: str) -> dict:
    """Create a post. WRITES: the probe must never reach this."""
    counter = os.environ.get("MCP_VET_PROBE_COUNTER")
    if counter:
        with open(counter, "a", encoding="utf-8") as fh:
            fh.write("create_post called\n")
    return {"id": 999, "title": title}


def _tool_error_cls():
    for path, name in (("mcp.server.mcpserver.exceptions", "ToolError"),
                       ("mcp.server.fastmcp.exceptions", "ToolError")):
        try:
            return getattr(__import__(path, fromlist=[name]), name)
        except Exception:  # noqa: BLE001
            continue
    return RuntimeError


_ToolError = _tool_error_cls()


@mcp.tool(annotations=RO)
def list_ratelimited(status: str | None = None) -> list[dict]:
    """List rows; the first call is rate-limited."""
    _state["ratelimit_calls"] += 1
    if _state["ratelimit_calls"] == 1:
        # ToolError, not RuntimeError: from mcp 2.1 a server that raises a bare
        # exception has its message withheld, and the client sees only "Error
        # executing tool <name>". This fixture stands in for a WELL-BEHAVED
        # third-party server -- one that tells the caller why -- because the
        # test downstream is about backoff recovery, and it asserts the prober
        # relays the reason it was given. (The other case is real and worth a
        # check of its own someday: a probed server whose errors are opaque
        # gives a client nothing to act on. Noted, not built.)
        raise _ToolError("429 Too Many Requests: rate limit exceeded")
    rows = [{"id": i, "status": "open" if i % 2 else "closed"} for i in range(5)]
    if status is not None:
        rows = [r for r in rows if r["status"] == status]
    return rows


if __name__ == "__main__":
    mcp.run(transport="stdio")
