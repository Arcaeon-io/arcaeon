"""MCP08 reachability over the honest recording shapes (0.0.17).

Before 0.0.17 the audit-record walk followed same-file calls only, so a server
whose record was one import, one decorator, one `self.` or one middleware
registration away scored gate 0: a FALSE RED, the expensive error for this
project. This file is the table of shapes it now follows and, for each, the
MUTATION that should send it back to gate 0 (delete the recorder call, the
decorator, the import, the base class). A shape is only "fixed" if both halves
hold: clean scores 4 AND the mutation scores 0. The shapes it still cannot
follow live under `blind_*` and are counted against grade.MCP08_REACH_BLIND_SPOTS
so a confession cannot outlive its fixture, or the other way round.

Fixtures: tests/fixtures/recorders/. Never executed, only parsed.
"""
from pathlib import Path

import pytest

from arcaeon.prove.vet import checks
from arcaeon.prove.vet.grade import grade_source, MCP08_REACH_BLIND_SPOTS
from arcaeon.prove.vet.service import scan_target

REC = Path(__file__).parent / "tests" / "fixtures" / "recorders"
ORDER = ["presence", "completeness", "tamper_evidence", "reconstructability"]


def _gate(findings) -> int:
    """Consecutive gates met, 0..4, same rule as bench/grade_sample.gate_reached."""
    ar = [f for f in findings if f["check"] == "audit-record"]
    if not ar:
        return 4
    g = ar[0].get("gates") or {}
    n = 0
    for k in ORDER:
        if not g.get(k):
            break
        n += 1
    return n


def _server(name: str):
    """(source, rel, package_dir) for a fixture: a file is graded alone, a
    package directory is graded through its server.py with the dir in hand."""
    p = REC / name
    if p.is_dir():
        return (p / "server.py").read_text(encoding="utf-8"), "server.py", p
    return p.read_text(encoding="utf-8"), name, None


def _grade(src, rel, pkg) -> int:
    assert checks.audit_record_applies(src), f"{rel}: fixture is not asked MCP08 at all"
    return _gate(grade_source(src, rel, package_dir=pkg).findings)


# (fixture, expected gate, mutation (old, new) that must send it to gate 0)
CASES = [
    # M1: recorder in a sibling module, relative and absolute import forms
    ("m1_relative_import", 4, ("from .audit import record\n", "")),
    ("m1_absolute_import", 4, ('    record("add", {"a": a, "b": b})\n', "")),
    # M2: decorator on the handler whose body records, bare and factory-call
    ("m2_bare_decorator.py", 4, ("@audited\n", "")),
    ("m2_decorator_factory_call.py", 4, ('@with_ledger("add")\n', "")),
    # M4: class-method handler recording through self.<method>
    ("m4_self_method.py", 4, ('        self._log("add", {"a": a, "b": b})\n', "")),
    # M5: context-manager recorder around the handler body
    ("m5_context_manager.py", 4, ('with audit_span("add", {"a": a, "b": b}):', "if True:")),
    # M6: recorder inherited one level, same file and sibling-module mixin
    ("m6_base_class_same_file.py", 4, ("class Svc(Audited):", "class Svc:")),
    ("m6_package_mixin", 4, ("class Svc(AuditedMixin):", "class Svc:")),
    # M7: construction-time middleware, registered and wrap-the-dispatcher
    ("m7_middleware_class.py", 4, ("mcp.add_middleware(AuditMiddleware())\n", "")),
    ("m7_wrapped_call_tool.py", 4, ("mcp.call_tool = _audited(mcp.call_tool)\n", "")),
    # genuine gate 0: nothing recorded, print only, and non-recording lookalikes
    # of every shape above (a @timed decorator, a quiet() context, a
    # self._validate call, a Cors middleware, a retrying call_tool wrapper)
    ("gate0_no_record.py", 0, None),
    ("gate0_print_only.py", 0, None),
    ("gate0_lookalikes.py", 0, None),
]


@pytest.mark.parametrize("name,expected,mutation", CASES, ids=[c[0] for c in CASES])
def test_shape_grades_as_expected(name, expected, mutation):
    src, rel, pkg = _server(name)
    assert _grade(src, rel, pkg) == expected


@pytest.mark.parametrize("name,expected,mutation",
                         [c for c in CASES if c[2]], ids=[c[0] for c in CASES if c[2]])
def test_mutation_sends_shape_back_to_gate_0(name, expected, mutation):
    """Delete the one thing that makes the record reachable; the walk must
    notice. A shape that scores 4 either way is a fixture that never needed
    the walk, not a shape the walk follows."""
    src, rel, pkg = _server(name)
    old, new = mutation
    assert src.count(old) == 1, f"{name}: mutation target must occur exactly once"
    mutated = src.replace(old, new)
    assert _grade(mutated, rel, pkg) == 0


# --- M8: every remaining blindness has a sentence AND a fixture ------------

def _blind_fixtures():
    return sorted(p.name for p in REC.iterdir() if p.name.startswith("blind_"))


def test_blind_spot_count_matches_known_blind_fixtures():
    """One sentence per shape the walk cannot follow, one fixture per sentence.
    Closing a blind spot means deleting BOTH, so the confession never outlives
    the gap and the gap is never quietly unconfessed."""
    assert len(MCP08_REACH_BLIND_SPOTS) == len(_blind_fixtures()), (
        f"{len(MCP08_REACH_BLIND_SPOTS)} confessed vs fixtures {_blind_fixtures()}")


@pytest.mark.parametrize("name", _blind_fixtures())
def test_each_known_blind_fixture_really_scores_gate_0(name):
    """The confession is evidenced: the honest server is still reported at
    gate 0. When one of these starts scoring 4 the walk learned the shape,
    and the sentence in grade.MCP08_REACH_BLIND_SPOTS comes out."""
    src, rel, pkg = _server(name)
    assert _grade(src, rel, pkg) == 0, f"{name} is no longer blind: retire its confession"


def test_single_file_grade_names_its_own_blindness():
    """The same M1 server that reaches gate 4 with its package reaches gate 0
    alone, and the grade it returns says so in blind_spots (no package
    directory, sibling records invisible). That sentence is the whole point of
    the single-file mode being a confessed limit rather than a silent one."""
    src, rel, pkg = _server("m1_relative_import")
    assert _grade(src, rel, pkg) == 4
    alone = grade_source(src, rel)
    assert _gate(alone.findings) == 0
    assert any("single file" in bs and "package directory" in bs for bs in alone.blind_spots)


# --- the directory scan is where the package directory actually arrives ----

def test_scan_target_directory_reaches_gate_4_but_file_target_does_not():
    """`scan_target` on the package passes each file its directory, so the
    relative-import recorder is followed and no audit-record finding is
    raised for server.py. The same server.py as a FILE target gets no
    directory (its receipt pins one file, and a grade may not depend on
    files the receipt does not pin), so it is reported high."""
    pkg = REC / "m1_relative_import"
    tree = scan_target(pkg)
    ar = [f for f in tree.findings
          if f["check"] == "audit-record" and f["file"] == "server.py"]
    assert ar == [], ar
    alone = scan_target(pkg / "server.py")
    ar = [f for f in alone.findings if f["check"] == "audit-record"]
    assert ar and ar[0]["severity"] == "high", ar
