"""M7: the dispatcher is WRAPPED at construction time
(`mcp.call_tool = _audited(mcp.call_tool)`); the wrapper records every call and
no handler mentions it. Fixture for test_recorder_shapes.py; never run."""
import hashlib
import json
import time

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")
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


def _audited(dispatch):
    async def inner(name, arguments):
        global _head
        rec = {"ts": time.time(), "tool": name, "args": arguments, "prev": _head}
        _head = hashlib.sha256((_head + json.dumps(rec, sort_keys=True)).encode()).hexdigest()
        rec["chain"] = _head
        with open("audit.jsonl", "a") as fh:
            fh.write(json.dumps(rec) + "\n")
        return await dispatch(name, arguments)
    return inner


@mcp.tool()
def add(a, b):
    return a + b


mcp.call_tool = _audited(mcp.call_tool)
mcp.run(transport="stdio")
