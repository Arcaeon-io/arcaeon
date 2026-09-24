"""M5: the record is written by a context manager the handler enters
(`with audit_span(tool, args):`). Fixture for test_recorder_shapes.py; never run."""
import contextlib
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


@contextlib.contextmanager
def audit_span(tool, args):
    global _head
    rec = {"ts": time.time(), "tool": tool, "args": args, "prev": _head}
    _head = hashlib.sha256((_head + json.dumps(rec, sort_keys=True)).encode()).hexdigest()
    rec["chain"] = _head
    with open("audit.jsonl", "a") as fh:
        fh.write(json.dumps(rec) + "\n")
    yield


@mcp.tool()
def add(a, b):
    with audit_span("add", {"a": a, "b": b}):
        return a + b


mcp.run(transport="stdio")
