"""M7: construction-time middleware. No handler names the recorder; it is
registered once with `mcp.add_middleware(AuditMiddleware())` and runs on every
call. Fixture for test_recorder_shapes.py; never run."""
import hashlib
import json
import time

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")


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


class AuditMiddleware:
    head = "0" * 64

    async def on_call_tool(self, context, call_next):
        rec = {"ts": time.time(), "tool": context.message.name,
               "args": context.message.arguments, "prev": self.head}
        self.head = hashlib.sha256((self.head + json.dumps(rec, sort_keys=True)).encode()).hexdigest()
        rec["chain"] = self.head
        with open("audit.jsonl", "a") as fh:
            fh.write(json.dumps(rec) + "\n")
        return await call_next(context)


@mcp.tool()
def add(a, b):
    return a + b


mcp.add_middleware(AuditMiddleware())
mcp.run(transport="stdio")
