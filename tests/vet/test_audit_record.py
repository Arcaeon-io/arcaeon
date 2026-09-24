"""MCP08 `audit-record` tests (board B2, 2026-08-30). Written BEFORE the check
existed; the first run fails on an unregistered check name, which is the point.

Design: `design/MCP08_audit_record.md`. Four gates, one finding per server,
severity = the first gate not met. The precision cases matter more than the
detection cases here, because the failure this class invites is crying "no audit
trail" at a server whose trail is one import away.
"""
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from arcaeon.prove.vet.checks import scan_source  # noqa: E402

HDR = 'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n'
RUN = '\nmcp.run(transport="stdio")\n'

# --- fixtures, one per rung of the ladder -----------------------------------

NO_RECORD = HDR + '''
@mcp.tool()
def add(a, b):
    return a + b
''' + RUN

PRINT_ONLY = HDR + '''
@mcp.tool()
def add(a, b):
    print("add", a, b)
    return a + b
''' + RUN

BARE_LOG = HDR + '''import logging

@mcp.tool()
def add(a, b):
    logging.info("done")
    return a + b
''' + RUN

PLAIN_LOG = HDR + '''import logging, time

@mcp.tool()
def add(a, b):
    logging.info("tool=%s args=%s ts=%s", "add", {"a": a, "b": b}, time.time())
    return a + b
''' + RUN

_CHAIN_BODY = '''import hashlib, json, time

_head = "0" * 64


def _audit(tool, args):
    global _head
    rec = {"ts": time.time(), "tool": tool, "args": args, "prev": _head}
    _head = hashlib.sha256((_head + json.dumps(rec, sort_keys=True)).encode()).hexdigest()
    rec["chain"] = _head
    with open("audit.jsonl", "a") as fh:
        fh.write(json.dumps(rec) + "\\n")
'''

_VERIFIER = '''

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
'''

_HANDLER = '''

@mcp.tool()
def add(a, b):
    _audit("add", {"a": a, "b": b})
    return a + b
'''

CHAINED_NO_VERIFY = HDR + _CHAIN_BODY + _HANDLER + RUN
AUDITED = HDR + _CHAIN_BODY + _VERIFIER + _HANDLER + RUN


def _audit_findings(src):
    return [f for f in scan_source(src, "t.py") if f.check == "audit-record"]


def _one(src):
    fs = _audit_findings(src)
    assert len(fs) == 1, "expected exactly ONE finding per server, got %r" % (fs,)
    return fs[0]


# --- the ladder -------------------------------------------------------------

def test_no_record_at_all_is_high():
    f = _one(NO_RECORD)
    assert f.severity == "high", f
    assert f.gates == {"presence": False, "completeness": False,
                       "tamper_evidence": False, "reconstructability": False}, f.gates
    assert f.line == 5, f  # points at the handler that records nothing


def test_print_is_not_a_record():
    """A print() is stdout, not an audit trail. Precision case #1."""
    f = _one(PRINT_ONLY)
    assert f.severity == "high", f
    assert f.gates["presence"] is False, f.gates


def test_logging_without_the_tool_name_is_not_a_record():
    """A log line that cannot say WHICH tool ran cannot answer MCP08."""
    f = _one(BARE_LOG)
    assert f.severity == "high", f
    assert f.gates["presence"] is False, f.gates


def test_plain_unchained_log_is_medium():
    f = _one(PLAIN_LOG)
    assert f.severity == "medium", f
    assert f.gates["presence"] is True and f.gates["completeness"] is True, f.gates
    assert f.gates["tamper_evidence"] is False, f.gates


def test_chained_but_unverifiable_is_low():
    f = _one(CHAINED_NO_VERIFY)
    assert f.severity == "low", f
    assert f.gates["tamper_evidence"] is True, f.gates
    assert f.gates["reconstructability"] is False, f.gates


def test_all_four_gates_met_is_no_finding():
    assert _audit_findings(AUDITED) == [], _audit_findings(AUDITED)


def test_the_audited_fixture_is_clean_across_every_class():
    """The positive fixture has to be clean overall, or 'no finding' above is
    proving something other than what it says."""
    assert scan_source(AUDITED, "t.py") == [], scan_source(AUDITED, "t.py")


# --- scope: this must not shout at things that are not servers --------------

def test_silent_without_an_entrypoint():
    """A module that defines a handler but never serves is not a deployed
    server. Asking a fragment where its audit trail is, is noise."""
    assert _audit_findings(HDR + "\n@mcp.tool()\ndef add(a, b):\n    return a + b\n") == []


def test_silent_without_a_handler():
    assert _audit_findings(HDR + RUN) == []


def test_silent_on_a_plain_module():
    assert _audit_findings("import json\n\ndef f(x):\n    return json.dumps(x)\n") == []


# --- the honest self-finding ------------------------------------------------

def test_our_own_mcp_server_no_longer_fires_on_itself():
    """HISTORY, kept because the inversion is the point. In v0.0.6 this test
    read `_one(src); assert f.severity == "high"` — mcp_vet/server.py kept NO
    record of the scans it was asked to run, the check fired on the file that
    ships it, and that went in the README rather than being filtered.

    v0.0.7 wired a real `arcaeon_ledger` row per tool call, so the assertion
    flips. It is allowed to flip ONLY because test_audit_ledger.py proves the
    record exists at runtime: one row per call through the MCP client, carrying
    the tool name, timestamp, path and source digest, with a tampered row named
    by line number. Passing this check by rearranging source text to please the
    heuristic would be the exact dishonesty the project exists to catch."""
    src = (Path(__file__).resolve().parents[2] / "src" / "arcaeon" / "prove" / "vet" / "server.py").read_text(encoding="utf-8")
    assert _audit_findings(src) == [], _audit_findings(src)


def test_our_own_public_safety_server_is_now_clean():
    """Inverted 2026-08-30 (B2c): until that morning this asserted severity ==
    'high' because mcp_public_safety kept no record at all. It now appends a
    chained arcaeon_ledger row per call and ships audit_verify, so the honest
    expectation is NO audit-record finding. If this goes red again, the record
    was removed or the heuristic regressed; either is loud on purpose."""
    root = Path(__file__).resolve().parent.parent
    p = root / "mcp_public_safety" / "server.py"
    if not p.exists():
        return  # located elsewhere; grade_own.py is the loud path for that
    fs = _audit_findings(p.read_text(encoding="utf-8"))
    assert fs == [], fs


def test_arcaeon_ledger_mcp_server_is_the_reference_record():
    """arcaeon-ledger's MCP server IS the pattern: a hash-chained append-only
    record with a verifier. Gates 1, 3 and 4 must all read True. Gate 2 is the
    one a static pass cannot see, and the finding must say so rather than
    quietly pass it."""
    # arcaeon merge: the ledger is in this repo; read the moved server, not a sibling checkout.
    for base in (Path(__file__).resolve().parents[2] / "src" / "arcaeon" / "record",):
        p = base / "ledger" / "mcp_server.py"
        if p.exists():
            break
    else:
        # Absence must stay LOUD on a machine where the sibling checkout is
        # supposed to exist -- that is the point of this fixture. On CI it is a
        # single-repo checkout with no siblings, so its absence there is the
        # expected state, not a missing fixture, and failing on it reports an
        # environment gap as a code defect (mirror CI, 2026-09-06).
        if os.environ.get("CI"):
            import pytest
            pytest.skip("arcaeon-ledger is a sibling checkout, absent by design on CI")
        raise AssertionError("arcaeon-ledger mcp_server.py not located — the "
                             "reference fixture for this check cannot go missing silently")
    fs = _audit_findings(p.read_text(encoding="utf-8"))
    if not fs:
        return  # passed all four; nothing to explain
    f = fs[0]
    assert f.gates["presence"] is True, f.gates
    assert f.gates["tamper_evidence"] is True, f.gates
    assert f.gates["reconstructability"] is True, f.gates
    assert f.gates["completeness"] is False, f.gates
    assert f.severity == "medium", f
    assert "completeness" in f.detail, f.detail


# --- artifact shape ---------------------------------------------------------

def test_gates_survive_the_finding_dict_and_other_checks_do_not_carry_them():
    d = _one(NO_RECORD).as_dict()
    assert set(d["gates"]) == {"presence", "completeness", "tamper_evidence",
                               "reconstructability"}, d
    other = list(scan_source('API_KEY = "sk_live_FAKEFAKEFAKEFAKEFAKEFAKEFAKE"\n', "t.py"))
    assert other and "gates" not in other[0].as_dict(), (
        "a `gates` key on every finding would change the bytes of every prior "
        "grade artifact; it must appear only where it means something")


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    p = 0
    for fn in fns:
        try:
            fn(); print("PASS", fn.__name__); p += 1
        except Exception:
            print("FAIL", fn.__name__); traceback.print_exc()
    print("\n%d/%d passed" % (p, len(fns)))
    sys.exit(0 if p == len(fns) else 1)
