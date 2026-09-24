"""Grade-METADATA tests (board F20, 2026-08-30).

The grade artifact drifted from the code: `checks_run` listed three classes
while four were running, and `blind_spots` still confessed three gaps that
v0.0.4 had closed. Both errors point the same way — the artifact understated
the tool — which is the wrong direction of error for something whose only
product is an honest self-report.

So the metadata gets tested like a finding does:
  - every check that actually fires must be named in `checks_run`
  - nothing named as a blind spot may be a check that actually fires
  - every remaining blind spot must be EVIDENCED: a fixture that slips past it
    for 0 findings, plus a control that fires, so the 0 is caused by the named
    gap and not by an inert fixture.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from arcaeon.prove.vet.checks import scan_source
from arcaeon.prove.vet.grade import grade_source, BLIND_SPOTS

HDR = "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"

# Ground truth: one planted red per check class. What fires here is what the
# tool ACTUALLY does, independent of anything the artifact claims about itself.
PLANTED = {
    "unsafe-exec": HDR + "@mcp.tool()\ndef f(cmd):\n    import os\n    return os.system(cmd)\n",
    "ssrf": HDR + "@mcp.tool()\ndef f(url):\n    import urllib.request\n    return urllib.request.urlopen(url).read()\n",
    "path-traversal": HDR + "@mcp.tool()\ndef f(path):\n    return open(path).read()\n",
    "zero-auth": HDR + "mcp.run(transport='sse')\n",
    "secret-in-code": HDR + 'GITHUB_TOKEN = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"\n',
    # MCP08: a served server whose tool calls leave nothing behind. The
    # `mcp.run(...)` line is load-bearing — this check deliberately only asks
    # the question of a file that actually serves (see design/MCP08_audit_record.md).
    "audit-record": HDR + '@mcp.tool()\ndef f(x):\n    return x\n\nmcp.run(transport="stdio")\n',
    "unreceipted-allow": (
        'def _gate(user, resource):\n'
        '    if not user.member_of(resource):\n'
        '        return {"allowed": False, "receipt": _hash(user, resource)}\n'
        '    return {"allowed": True}\n'
    ),
    # unsafe-deser (0.0.11): pickle.loads of tool input — RCE, a class that had
    # no check until the 2026-09-01 audit.
    "unsafe-deser": HDR + "@mcp.tool()\ndef f(b):\n    import pickle\n    return pickle.loads(b)\n",
    # except-returns-success (0.0.17): the mcp-atlassian shape from gate 2,
    # the fetcher a tool calls turns a caught exception into an empty list, so
    # the handler's own careful error path never fires and the agent is told
    # there are no projects.
    "except-returns-success": HDR + (
        "def _all():\n"
        "    try:\n"
        "        return _client.get('/rest/api/3/project')\n"
        "    except Exception:\n"
        "        logger.error('fetch failed')\n"
        "        return []\n\n"
        "@mcp.tool()\ndef projects():\n    return _all()\n"
    ),
}


def _kinds(src):
    return {f.check for f in scan_source(src, "t.py")}


def test_checks_run_names_every_check_that_actually_fires():
    """The drift itself: path-traversal ran from 0.0.4 on and the artifact
    never said so."""
    claimed = grade_source(HDR, "hdr.py").checks_run
    for name, src in PLANTED.items():
        assert name in _kinds(src), f"fixture for {name} does not actually fire — bad fixture"
        assert name in claimed, f"{name} runs but checks_run does not name it: {claimed}"


def test_checks_run_is_derived_from_the_registry_not_a_literal():
    from arcaeon.prove.vet.checks import check_names
    # On a file that PARSES, every registered check runs. On one that does
    # not, checks_run is [] — see test_unparseable_file_claims_zero_checks.
    assert grade_source(HDR, "hdr.py").checks_run == check_names()
    assert sorted(check_names()) == sorted(PLANTED), (
        "the registry and the planted-red set disagree — a check is registered "
        "with no red, or fires with no registration")


def test_no_blind_spot_names_a_check_that_runs():
    """A confession that names a closed class understates the tool."""
    for name in grade_source(HDR, "hdr.py").checks_run:
        for bs in BLIND_SPOTS:
            assert name.lower() not in bs.lower(), f"blind spot claims {name} is open: {bs!r}"


def test_gaps_closed_in_0_0_4_are_not_still_confessed():
    blob = " ".join(BLIND_SPOTS).lower()
    for closed, proof in (
        ("__import__", HDR + "@mcp.tool()\ndef f(e):\n    return __import__('os').system(e)\n"),
        ("aliased taint", HDR + "@mcp.tool()\ndef f(url):\n    import urllib.request\n    p = url\n    return urllib.request.urlopen(p).read()\n"),
        ("arbitrary file read", HDR + "@mcp.tool()\ndef f(path):\n    return open(path).read()\n"),
    ):
        assert _kinds(proof), f"{closed}: proof fixture no longer fires"
        assert closed not in blob, f"{closed} was closed in 0.0.4 but is still confessed as open"


def test_every_blind_spot_carries_evidence():
    """Two evidence tables now, because a gap can point two ways: a MISS (a
    fixture that scores 0) or a FALSE RED (a fixture that fires when it should
    not). Every confessed gap sits in exactly one of them."""
    from arcaeon.prove.vet.grade import BLIND_SPOT_EVIDENCE, FALSE_RED_EVIDENCE
    assert not (set(BLIND_SPOT_EVIDENCE) & set(FALSE_RED_EVIDENCE)), (
        "a gap cannot be both a miss and a false red — pick the direction it "
        "actually fails in")
    assert set(BLIND_SPOT_EVIDENCE) | set(FALSE_RED_EVIDENCE) == set(BLIND_SPOTS), (
        "every confessed gap needs evidence and every piece of evidence needs a gap")


def test_every_false_red_fixture_actually_fires():
    """An over-report confessed without a fixture that over-reports is a hedge.
    Each false-red entry ships the source that really does draw the wrong red,
    plus the reason in plain language."""
    from arcaeon.prove.vet.grade import FALSE_RED_EVIDENCE
    for bs, (fires, why) in FALSE_RED_EVIDENCE.items():
        fs = scan_source(fires, "fr.py")
        assert fs, f"false red is stale — the tool no longer fires here: {bs!r}"
        assert why.strip(), f"a false red needs a stated reason: {bs!r}"


def test_each_blind_spot_fixture_really_slips_past():
    """The confession is evidenced, not asserted: the fixture scores 0."""
    from arcaeon.prove.vet.grade import BLIND_SPOT_EVIDENCE
    for bs, (slips, _control) in BLIND_SPOT_EVIDENCE.items():
        fs = scan_source(slips, "slip.py")
        assert fs == [], f"blind spot is stale — the tool now catches it: {bs!r} -> {fs}"


def test_blind_spot_fixtures_are_not_vacuously_clean():
    """Each 0 is caused by the named gap, not by a fixture with nothing in it:
    the paired control differs minimally and DOES fire."""
    from arcaeon.prove.vet.grade import BLIND_SPOT_EVIDENCE
    for bs, (_slips, control) in BLIND_SPOT_EVIDENCE.items():
        fs = scan_source(control, "control.py")
        assert fs, f"control for {bs!r} fires nothing — the 0 above proves nothing"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    p = 0
    for fn in fns:
        try:
            fn(); print("PASS", fn.__name__); p += 1
        except Exception:
            print("FAIL", fn.__name__); traceback.print_exc()
    print(f"\n{p}/{len(fns)} passed")
    sys.exit(0 if p == len(fns) else 1)


def test_unparseable_file_claims_zero_checks_and_never_passes():
    """0.0.14 (2026-09-01 audit, critical #1): a SyntaxError used to produce
    one 'parse' info finding under a checks_run that named all 8 checks, and
    the verdict 'informational findings only' — a pass-class verdict on a
    file no check ever read. Now: checks_run is empty, the verdict is its
    own non-pass string, and the hollow-pass detector flags it."""
    from arcaeon.prove.vet.grade import _PASS_VERDICTS, pass_receipt_gaps
    g = grade_source("def broken(:\n    pass\n", "broken.py")
    assert g.checks_run == []
    assert [f["check"] for f in g.findings] == ["parse"]
    assert g.verdict not in _PASS_VERDICTS
    assert "0 checks" in g.verdict
    from dataclasses import asdict
    forged = asdict(g); forged["verdict"] = "informational findings only"
    assert any("failed to parse" in gap for gap in pass_receipt_gaps(forged))


def test_dispatch_blind_spot_has_a_slip_and_a_control():
    from arcaeon.prove.vet.grade import _BS_DISPATCH, BLIND_SPOT_EVIDENCE, BLIND_SPOTS
    assert _BS_DISPATCH in BLIND_SPOTS
    slip, control = BLIND_SPOT_EVIDENCE[_BS_DISPATCH]
    assert "unsafe-exec" not in _kinds(slip), "the table-dispatch slip is now caught — retire the blind spot"
    assert "unsafe-exec" in _kinds(control), "constant-string getattr must resolve"


def _except_sites(src):
    return [f for f in scan_source(src, "t.py") if f.check == "except-returns-success"]


def test_shadowed_and_dead_except_blind_spots_have_slip_and_control():
    """Board 118, from the 2026-09-04 runtime run: three of 27 shipped findings
    could not be made to execute at all, in two shapes, and both are OVER-reports
    rather than misses. So both arms of each pair FIRE. That is what makes them
    different from every entry in BLIND_SPOT_EVIDENCE, where the slip scores 0
    and the control proves the 0 was not vacuous: here the tool produces a
    finding either way, and only runtime separates the wrong one from the right
    one. The test exercises both arms so a future fix that closes either gap
    breaks this test and forces the confession to be retired rather than left
    standing as a stale apology."""
    from arcaeon.prove.vet.checks import except_success_coverage
    from arcaeon.prove.vet.grade import (BLIND_SPOTS, FALSE_RED_EVIDENCE,
                               _FR_EXCEPT_SHADOWED, _FR_EXCEPT_DEAD,
                               _EXCEPT_SHADOWED_SLIP, _EXCEPT_SHADOWED_CONTROL,
                               _EXCEPT_DEAD_SLIP, _EXCEPT_DEAD_CONTROL)
    assert _FR_EXCEPT_SHADOWED in BLIND_SPOTS
    assert _FR_EXCEPT_DEAD in BLIND_SPOTS
    # The table ships the fixture that is WRONG, which is the direction a false
    # red fails in. The control lives beside it and is exercised here.
    assert FALSE_RED_EVIDENCE[_FR_EXCEPT_SHADOWED][0] == _EXCEPT_SHADOWED_SLIP
    assert FALSE_RED_EVIDENCE[_FR_EXCEPT_DEAD][0] == _EXCEPT_DEAD_SLIP

    # --- shadowed site -------------------------------------------------------
    # Slip: two findings, one failure path. The inner body converts first, so
    # the outer except is never entered at runtime and one of these two is a
    # phantom. The rule counts both.
    slip = _except_sites(_EXCEPT_SHADOWED_SLIP)
    assert len(slip) == 2, f"the shadowed slip must still double-count: {slip}"
    assert len({(f.file, f.line) for f in slip}) == 2, slip
    # Control: the same file with the inner swallow removed, which is exactly
    # the monkeypatch that lit jira/fields.py:879 on the real repo. Now the
    # outer handler is the only one and it really does run: one finding, right.
    control = _except_sites(_EXCEPT_SHADOWED_CONTROL)
    assert len(control) == 1, f"the control must fire once and be right: {control}"
    # The pair is one edit apart: the control is the slip minus the inner try.
    assert "get_fields" in _EXCEPT_SHADOWED_SLIP and "get_fields" in _EXCEPT_SHADOWED_CONTROL
    assert _EXCEPT_SHADOWED_CONTROL.count("except Exception") == 1
    assert _EXCEPT_SHADOWED_SLIP.count("except Exception") == 2

    # --- dead except ---------------------------------------------------------
    # The sharpest form of "cannot tell a reachable except from a dead one":
    # the dead clause and the live one produce the SAME finding, byte for byte,
    # at the same line. `.get()` versus `[...]` is the entire difference and the
    # rule never looks at it.
    dead = _except_sites(_EXCEPT_DEAD_SLIP)
    live = _except_sites(_EXCEPT_DEAD_CONTROL)
    assert len(dead) == 1 and len(live) == 1, (dead, live)
    assert (dead[0].file, dead[0].line, dead[0].detail) == \
           (live[0].file, live[0].line, live[0].detail), \
        "if these ever differ, the rule can now tell them apart, so retire the gap"

    # The coverage line counts the shape and REPORTS it. The finding count is
    # identical either way, which is the "reported, not subtracted" rule.
    assert except_success_coverage(_EXCEPT_DEAD_SLIP, "t.py")["dead_keyerror_candidates"] == 1
    assert except_success_coverage(_EXCEPT_DEAD_CONTROL, "t.py")["dead_keyerror_candidates"] == 0
    assert len(dead) == len(live)
    # A bare `except:` over the same block is not counted: it catches
    # everything, so nothing about the try block can make it dead.
    assert except_success_coverage(
        _EXCEPT_DEAD_SLIP.replace("except KeyError:", "except Exception:"),
        "t.py")["dead_keyerror_candidates"] == 0
