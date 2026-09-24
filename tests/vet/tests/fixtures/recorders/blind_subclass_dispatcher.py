"""KNOWN BLIND (confessed in grade.MCP08_REACH_BLIND_SPOTS): the server is a
SUBCLASS whose overridden `call_tool` records every call. Middleware is
recognised by registration or by rebinding `call_tool`; an override is
neither, so the server is reported at gate 0 although every call is
recorded. Never run."""
import hashlib
import json
import time

from mcp.server.fastmcp import FastMCP

_head = "0" * 64


def verify_audit_chain(path="audit.jsonl"):
    prev = "0" * 64
    with open(path) as fh:
        for line in fh:
            row = json.loads(line)
            got = row.pop("chain")
            if hashlib.sha256((prev + json.dumps(row, sort_keys=True)).encode()).hexdigest() != got:
                return False
            prev = got
    return True


class AuditedMCP(FastMCP):
    async def call_tool(self, name, arguments):
        global _head
        rec = {"ts": time.time(), "tool": name, "args": arguments, "prev": _head}
        _head = hashlib.sha256((_head + json.dumps(rec, sort_keys=True)).encode()).hexdigest()
        rec["chain"] = _head
        with open("audit.jsonl", "a") as fh:
            fh.write(json.dumps(rec) + "\n")
        return await super().call_tool(name, arguments)


mcp = AuditedMCP("x")


@mcp.tool()
def add(a, b):
    return a + b


mcp.run(transport="stdio")
