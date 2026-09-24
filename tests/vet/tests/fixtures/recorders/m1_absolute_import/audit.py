"""The recorder module of a two-file fixture: a chained append with a verify
path. Imported by the sibling server.py; never run."""
import hashlib
import json
import time

_head = "0" * 64


def record(tool, args):
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
