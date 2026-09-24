"""Planted-failure test for pass_receipt_gaps (the quesen bug class / scar #132:
a verifier that greens an empty log reports PASS having checked nothing).

sram's redundancy rule: a checker counts only once observed FAILING on the exact
bug. So each RED case is a hollow pass that MUST fire; each GREEN case is a
backed pass (or a findings verdict) that must stay quiet.
"""
from dataclasses import asdict

from arcaeon.prove.vet.grade import pass_receipt_gaps, grade_source, verify, _EMPTY_SHA


# A benign MCP server: no file read, no secret, no exec — a real clean pass.
_BENIGN = (
    "from mcp.server.fastmcp import FastMCP\n"
    "mcp = FastMCP('x')\n"
    "@mcp.tool()\n"
    "def ping():\n"
    "    return 'pong'\n"
)

# ---- RED: hollow passes. MUST fire. ----
RED = [
    # greened with zero checks run
    {"verdict": "no findings in checked classes", "checks_run": [],
     "source_sha256": "a" * 64, "findings": []},
    # pass over the sha256 of empty bytes — graded nothing
    {"verdict": "no findings in checked classes", "checks_run": ["secret_in_code"],
     "source_sha256": _EMPTY_SHA, "findings": []},
    # no bytes pinned at all
    {"verdict": "informational findings only", "checks_run": ["secret_in_code"],
     "source_sha256": "", "findings": []},
    # incoherent: says 'no findings' but carries findings
    {"verdict": "no findings in checked classes", "checks_run": ["secret_in_code"],
     "source_sha256": "b" * 64, "findings": [{"severity": "high", "check": "x"}]},
]

# ---- GREEN: backed passes / findings verdicts. MUST stay quiet. ----
def _green_cases():
    real = asdict(grade_source(_BENIGN, "benign"))
    assert real["verdict"] == "no findings in checked classes", real["verdict"]
    return [
        real,  # a real clean grade over real bytes — backed pass
        # a findings verdict is not a hollow-pass risk even with thin evidence
        {"verdict": "high-severity findings", "checks_run": [],
         "source_sha256": _EMPTY_SHA, "findings": [{"severity": "high"}]},
    ]


def main():
    fails = []
    for i, g in enumerate(RED):
        if not pass_receipt_gaps(g):
            fails.append(f"RED[{i}] did NOT fire (hollow pass passed): {g.get('verdict')}")
    for i, g in enumerate(_green_cases()):
        gaps = pass_receipt_gaps(g)
        if gaps:
            fails.append(f"GREEN[{i}] false-fired: {gaps}")

    # verify() must refuse to bless a hollow pass even when it reproduces
    v = verify(RED[1], "")  # empty source reproduces the empty-source hash
    if v["reproduced"]:
        fails.append("verify() blessed a hollow pass that reproduced")

    if fails:
        print("FAIL:")
        for f in fails:
            print("  " + f)
        raise SystemExit(1)
    print(f"OK — {len(RED)} hollow passes fire, {len(_green_cases())} backed quiet, "
          "verify() rejects reproduced-but-hollow")


if __name__ == "__main__":
    main()


def test_pass_receipt_gaps_hollow_fires_backed_quiet():
    """pytest entry — planted-red assertions live in main()."""
    main()
