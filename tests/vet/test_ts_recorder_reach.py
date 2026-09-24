"""Where the TS record may live (0.0.17): M13 routing, M15 relative imports,
M16 wrappers and decorators, M17 the honest no-front-end grade.

Every "clean" case here has a paired mutation that must go red. A walk that
returns clean for both the fixture and its mutation is not reaching the
record; it is guessing.
"""
from __future__ import annotations

import importlib
import shutil
import sys
import tomllib
from pathlib import Path

import pytest

import arcaeon.prove.vet.ts_checks as tc
from arcaeon.prove.vet import grade as grade_mod
from arcaeon.prove.vet.grade import grade_source
from arcaeon.prove.vet.service import scan_target

HERE = Path(__file__).parent
FIXTURES = HERE / "tests" / "fixtures" / "ts"
needs_ts = pytest.mark.skipif(not tc.available(), reason="tree-sitter [ts] extra not installed")

# The TS front end ran TWO checks from 0.0.17 (2026-09-04, `except-returns-
# success` joined `audit-record`), so these assertions read the registry
# instead of a literal: a hand-kept copy of the check list is exactly the
# drift `checks.CHECKS` exists to prevent.
TS_CHECK_NAMES = [name for name, _ in tc.TS_CHECKS]

# A minimal one-file TS MCP server with a handler that records nothing.
_TS_NO_RECORD = '''\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "adder", version: "1.0.0" });
server.tool("add", { a: z.number(), b: z.number() }, async (args) => {
  return { content: [{ type: "text", text: String(args.a + args.b) }] };
});
const transport = new StdioServerTransport();
await server.connect(transport);
'''

_PY_CLEAN = '''\
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("demo")

@mcp.tool()
def add(a: int, b: int) -> int:
    return a + b

if __name__ == "__main__":
    mcp.run()
'''


def _audit_findings(g):
    return [f for f in g.findings if f["check"] == "audit-record"]


def _copy_fixture(name: str, tmp_path: Path) -> Path:
    dst = tmp_path / name
    shutil.copytree(FIXTURES / name, dst)
    return dst


def _mutate(path: Path, old: str, new: str = "") -> None:
    s = path.read_text(encoding="utf-8")
    assert old in s, "mutation target not in fixture: %r" % old[:40]
    path.write_text(s.replace(old, new), encoding="utf-8")


# ---------------------------------------------------------------- M13 routing

@needs_ts
def test_m13_ts_tree_reports_only_audit_record(tmp_path):
    (tmp_path / "server.ts").write_text(_TS_NO_RECORD, encoding="utf-8")
    g = scan_target(tmp_path)
    assert g.files_scanned == ["server.ts"]
    assert g.checks_run == TS_CHECK_NAMES
    assert g.verdict == "high-severity findings"
    # Never imply the Python battery ran on a TS file.
    assert not any(c in g.checks_run for c in ("secret-in-code", "exec-sink", "net-egress"))
    assert g.per_file == {"server.ts": "high-severity findings"}


@needs_ts
def test_m13_mixed_tree_checks_run_is_the_intersection(tmp_path):
    (tmp_path / "server.ts").write_text(_TS_NO_RECORD, encoding="utf-8")
    (tmp_path / "server.py").write_text(_PY_CLEAN, encoding="utf-8")
    g = scan_target(tmp_path)
    assert g.files_scanned == ["server.py", "server.ts"]
    assert g.checks_run == TS_CHECK_NAMES
    assert set(g.per_file) == {"server.py", "server.ts"}
    # The Python file, graded on its own through the same entry, ran more.
    py_alone = grade_source(_PY_CLEAN, "server.py")
    assert len(py_alone.checks_run) > 1 and "audit-record" in py_alone.checks_run


@needs_ts
def test_m13_single_string_routes_by_extension():
    ts = grade_source(_TS_NO_RECORD, "server.ts")
    assert ts.checks_run == TS_CHECK_NAMES
    js = grade_source(_TS_NO_RECORD, "server.mjs")
    assert js.checks_run == TS_CHECK_NAMES


# ------------------------------------------------------- M15 relative imports

@needs_ts
def test_m15_import_recorder_fixture_is_clean_as_a_tree():
    g = scan_target(FIXTURES / "import_recorder")
    assert g.files_scanned == ["audit.ts", "server.ts"]
    assert g.checks_run == TS_CHECK_NAMES
    assert _audit_findings(g) == [], g.findings
    assert g.verdict == "no findings in checked classes"


@needs_ts
def test_m15_import_recorder_server_alone_is_a_finding():
    # No resolver: the file has no write in it, and the grade must say so.
    src = (FIXTURES / "import_recorder" / "server.ts").read_text(encoding="utf-8")
    g = grade_source(src, "server.ts")
    hits = _audit_findings(g)
    assert hits and hits[0]["severity"] == "high"


@needs_ts
def test_m15_resolver_finds_the_sibling_through_js_suffix():
    src = (FIXTURES / "import_recorder" / "server.ts").read_text(encoding="utf-8")
    resolve = tc.file_resolver(FIXTURES / "import_recorder", FIXTURES)
    findings, ran = tc.scan_source_ts_ex(src, "server.ts", resolve=resolve)
    assert ran == TS_CHECK_NAMES
    assert [f for f in findings if f.check == "audit-record"] == []


@needs_ts
@pytest.mark.parametrize("old", [
    'import { record } from "./audit.js";\n',   # delete the import
    '  record("add", args);\n',                 # delete the call
])
def test_m15_import_recorder_mutation_goes_red(tmp_path, old):
    d = _copy_fixture("import_recorder", tmp_path)
    _mutate(d / "server.ts", old)
    g = scan_target(d)
    hits = _audit_findings(g)
    assert hits and hits[0]["severity"] == "high"
    assert hits[0]["file"] == "server.ts"
    assert g.verdict == "high-severity findings"


@needs_ts
def test_m15_resolver_refuses_paths_outside_the_tree(tmp_path):
    (tmp_path / "inner").mkdir()
    (tmp_path / "outside.ts").write_text("export function record() {}\n", encoding="utf-8")
    resolve = tc.file_resolver(tmp_path / "inner", tmp_path / "inner")
    assert resolve("../outside") is None
    assert resolve("../outside.js") is None


# ------------------------------------------------- M16 wrappers + decorators

@needs_ts
def test_m16_wrapper_recorder_fixture_is_clean():
    g = scan_target(FIXTURES / "wrapper_recorder")
    assert g.checks_run == TS_CHECK_NAMES
    assert _audit_findings(g) == [], g.findings


@needs_ts
def test_m16_wrapper_removed_goes_red(tmp_path):
    d = _copy_fixture("wrapper_recorder", tmp_path)
    body = 'async (args) => {\n  return { content: [{ type: "text", text: String(args.a + args.b) }] };\n}'
    _mutate(d / "server.ts", 'withAudit("add", %s)' % body, body)
    g = scan_target(d)
    hits = _audit_findings(g)
    assert hits and hits[0]["severity"] == "high"


@needs_ts
def test_m16_wrapper_bound_to_a_const_is_followed():
    src = (FIXTURES / "wrapper_recorder" / "server.ts").read_text(encoding="utf-8")
    body = 'async (args) => {\n  return { content: [{ type: "text", text: String(args.a + args.b) }] };\n}'
    src = src.replace(
        'withAudit("add", %s));' % body,
        'handler);\nconst handler = withAudit("add", %s);' % body,
    )
    findings, ran = tc.scan_source_ts_ex(src, "server.ts")
    assert ran == TS_CHECK_NAMES
    assert [f for f in findings if f.check == "audit-record"] == []


@needs_ts
def test_m16_decorator_recorder_fixture_is_clean():
    g = scan_target(FIXTURES / "decorator_recorder")
    assert g.files_scanned == ["tools.ts"]
    assert g.checks_run == TS_CHECK_NAMES
    assert _audit_findings(g) == [], g.findings


@needs_ts
def test_m16_decorator_removed_goes_red(tmp_path):
    d = _copy_fixture("decorator_recorder", tmp_path)
    _mutate(d / "tools.ts", "  @Audited()\n")
    g = scan_target(d)
    hits = _audit_findings(g)
    assert hits and hits[0]["severity"] == "high"
    assert hits[0]["file"] == "tools.ts"


# ------------------------------------------------ M17 honest without the extra

def test_m17_without_the_ts_extra_a_ts_file_is_unparseable_never_clean(monkeypatch, tmp_path):
    # Make the optional imports fail INSIDE this test (nothing is uninstalled):
    # None in sys.modules makes `import tree_sitter` raise ImportError.
    monkeypatch.setitem(sys.modules, "tree_sitter", None)
    monkeypatch.setitem(sys.modules, "tree_sitter_typescript", None)
    try:
        importlib.reload(tc)
        assert tc.available() is False

        g = grade_source(_TS_NO_RECORD, "server.ts")
        assert g.checks_run == []
        assert g.verdict == grade_mod._UNPARSEABLE
        assert g.verdict not in grade_mod._PASS_VERDICTS
        reasons = [f["detail"] for f in g.findings if f["check"] == "parse"]
        assert reasons and "pip install 'arcaeon[ts]'" in reasons[0]

        # Same honesty at the tree level.
        (tmp_path / "server.ts").write_text(_TS_NO_RECORD, encoding="utf-8")
        t = scan_target(tmp_path)
        assert t.checks_run == []
        # qa-fixes 2026-09-24: a tree where every file ran zero checks is the
        # one word NO GRADEABLE FILES (exit 3), never clean and never a pass.
        from arcaeon.verdict import NO_GRADEABLE_FILES
        assert t.verdict == NO_GRADEABLE_FILES
        assert t.verdict not in grade_mod._PASS_VERDICTS
        assert t.per_file == {"server.ts": grade_mod._UNPARSEABLE}
    finally:
        monkeypatch.undo()
        importlib.reload(tc)


def test_m17_pyproject_ts_extra_lists_both_packages():
    # Checks the two package NAMES are present with a floor, not an exact
    # version string -- PIN_POLICY_2026-09-05.md moves the floor/ceiling as
    # the tested version changes (2026-09-05: >=0.25/>=0.23 -> >=0.26.0,<0.27
    # / >=0.23.2,<0.24), and this test's own name says what it is actually
    # guarding: both packages are declared, each with a real floor.
    data = tomllib.loads((HERE / "pyproject.toml").read_text(encoding="utf-8"))
    extra = data["project"]["optional-dependencies"]["ts"]
    assert len(extra) == 2
    assert any(d.startswith("tree-sitter>=") and not d.startswith("tree-sitter-typescript")
              for d in extra), extra
    assert any(d.startswith("tree-sitter-typescript>=") for d in extra), extra
