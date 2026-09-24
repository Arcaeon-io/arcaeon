"""M2: the record is written by a decorator FACTORY called in the decorator
list (`@with_ledger("add")`). Fixture for test_recorder_shapes.py; never run."""
import functools
import hashlib
import json
import time

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")
_head = "0" * 64


def _record(tool, args):
    global _head
    rec = {"ts": time.time(), "tool": tool, "args": args, "prev": _head}
    _head = hashlib.sha256((_head + json.dumps(rec, sort_keys=True)).encode()).hexdigest()
    rec["chain"] = _head
    with open("audit.jsonl", "a") as fh:
        fh.write(json.dumps(rec) + "\n")


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


def with_ledger(tool):
    def deco(fn):
        @functools.wraps(fn)
        def inner(*a, **k):
            _record(tool, k)
            return fn(*a, **k)
        return inner
    return deco


@mcp.tool()
@with_ledger("add")
def add(a, b):
    return a + b


mcp.run(transport="stdio")
