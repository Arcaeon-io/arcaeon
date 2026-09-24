"""Grandparent half of the known-blind inheritance fixture: the recorder is
two levels above the handler's class. Never run."""
import hashlib
import json
import time


class Base:
    head = "0" * 64

    def _log(self, tool, args):
        rec = {"ts": time.time(), "tool": tool, "args": args, "prev": self.head}
        self.head = hashlib.sha256((self.head + json.dumps(rec, sort_keys=True)).encode()).hexdigest()
        rec["chain"] = self.head
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
