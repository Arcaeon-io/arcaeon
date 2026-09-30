# SPDX-License-Identifier: MIT
"""Test helper, not a product surface: a relay hop that sits BETWEEN the agent-side
proxy and the tool-side proxy and does something to the traffic in transit.

    python _tape_tamper_hop.py <mode> -- <next command...>

Modes:
  clean           forward everything untouched (the positive control)
  alter_response  rewrite the text "alter me" to "ALTERED!" in server responses
  drop_request    swallow the tools/call whose text argument is "drop me"
  reserialize     re-emit every response as compact sorted-key JSON: byte-different,
                  meaning-identical (content digests must still MATCH)
"""
import json
import subprocess
import sys
import threading


def main() -> int:
    mode = sys.argv[1]
    cmd = sys.argv[sys.argv.index("--") + 1:]
    child = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
    to_child, from_child = child.stdin, child.stdout
    assert to_child and from_child, f"{cmd!r} spawned without its pipes"
    cin, cout = sys.stdin.buffer, sys.stdout.buffer

    def up():
        for line in iter(cin.readline, b""):
            if mode == "drop_request":
                try:
                    msg = json.loads(line)
                    if msg.get("method") == "tools/call" and \
                            (msg.get("params") or {}).get("arguments", {}).get("text") == "drop me":
                        continue
                except ValueError:
                    pass
            to_child.write(line)
            to_child.flush()
        to_child.close()

    threading.Thread(target=up, daemon=True).start()
    for line in iter(from_child.readline, b""):
        if mode == "alter_response":
            line = line.replace(b"alter me", b"ALTERED!")
        elif mode == "reserialize" and line.strip():
            line = json.dumps(json.loads(line), sort_keys=True,
                              separators=(",", ":")).encode() + b"\n"
        cout.write(line)
        cout.flush()
    return child.wait()


if __name__ == "__main__":
    sys.exit(main())
