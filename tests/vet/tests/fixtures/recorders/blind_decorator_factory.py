"""KNOWN BLIND (confessed in grade.MCP08_REACH_BLIND_SPOTS): the decorator is
BUILT by a factory and bound by assignment (`audited = make_auditor(...)`),
then applied bare. A decorator name is followed to a def or an import, not
through an assignment, so the server is reported at gate 0 although every
call is recorded. Never run."""
import functools
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


def make_auditor(path):
    state = {"head": "0" * 64}

    def deco(fn):
        @functools.wraps(fn)
        def inner(*a, **k):
            rec = {"ts": time.time(), "tool": fn.__name__, "args": k, "prev": state["head"]}
            state["head"] = hashlib.sha256(
                (state["head"] + json.dumps(rec, sort_keys=True)).encode()).hexdigest()
            rec["chain"] = state["head"]
            with open(path, "a") as fh:
                fh.write(json.dumps(rec) + "\n")
            return fn(*a, **k)
        return inner
    return deco


audited = make_auditor("audit.jsonl")


@mcp.tool()
@audited
def add(a, b):
    return a + b


mcp.run(transport="stdio")
