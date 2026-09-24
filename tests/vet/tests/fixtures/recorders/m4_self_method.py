"""M4: a class-method handler records through `self._log(...)`, a method of
the SAME class. Fixture for test_recorder_shapes.py; never run."""
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


class Svc:
    def __init__(self):
        self.head = "0" * 64

    def _log(self, tool, args):
        rec = {"ts": time.time(), "tool": tool, "args": args, "prev": self.head}
        self.head = hashlib.sha256((self.head + json.dumps(rec, sort_keys=True)).encode()).hexdigest()
        rec["chain"] = self.head
        with open("audit.jsonl", "a") as fh:
            fh.write(json.dumps(rec) + "\n")

    @mcp.tool()
    def add(self, a, b):
        self._log("add", {"a": a, "b": b})
        return a + b


svc = Svc()
mcp.run(transport="stdio")
