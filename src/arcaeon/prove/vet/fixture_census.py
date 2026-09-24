"""mcp_vet.fixture_census -- how many must-hit/must-miss fixtures back each
check, read from the package's OWN test files (batch-100 item 85, 2026-09-05).

A badge that names WHICH checks ran says nothing about how well-proven any one
of them is. This module answers a narrower, honest question: for each check
name in the live registry (`checks.check_names()`), how many places in
mcp_vet's own test suite plant a sample that check MUST FIRE on (a must-hit,
the planted-red / positive control) and how many plant a sample it MUST STAY
SILENT on (a must-miss, the clean negative)? Both shapes are already the house
style -- test_checks.py's own docstring says it outright: "each failure class
gets a planted red AND a clean negative."

THE RULE, stated precisely (read this before trusting a number below it):
walk every `Compare` node in the package's own `test_*.py` files (source
checkout only -- see `available` below) and match a check name against either
side of the comparison, resolving simple module-level string aliases first
(`CHECK = "except-returns-success"` then used bare as `CHECK`, the idiom
`test_except_returns_success.py` uses throughout). `in` / `==` against a
matched name is a must-hit; `not in` / `!=` is a must-miss. When that Compare
sits directly inside a `for x in (<literal tuple/list>): ...` loop -- inline,
or via a same-function local variable that was just assigned that literal --
the count is the literal's length (several tests here plant four sources under
one assert), not 1.

WHAT THIS UNDERCOUNTS, ON PURPOSE CONFESSED RATHER THAN HIDDEN: a test file
that routes the comparison through a shared helper function
(`test_secret_in_code.py`'s `_secret_findings(src)`, called once per test with
a different planted `src`) puts the Compare inside the HELPER, which this
walk visits once per file, not once per call site. Those checks' true fixture
count is undercounted here. This is a coverage COUNT, not a fixture-quality
audit -- the same honest-but-narrow promise `except_success_coverage`'s own
"a proxy, not a verdict" line makes elsewhere in this project.
"""
from __future__ import annotations

import ast
from pathlib import Path


def _project_root() -> Path:
    """The source-checkout root that holds this package's own test_*.py files
    (sibling to the `mcp_vet/` package directory). Absent in a bare wheel
    install -- `fixture_coverage()` reports that honestly (`available: False`)
    rather than guessing a zero that reads like "proven against nothing."""
    # arcaeon merge: vet's own tests live at <repo>/tests/vet, four levels above
    # src/arcaeon/prove/vet/. Absent in a wheel install, reported as such.
    return Path(__file__).resolve().parents[4] / "tests" / "vet"


def _own_test_files(root: Path) -> list:
    if not root.is_dir():
        return []
    # This module's own file has nothing to find in it and is not a test file;
    # excluded implicitly since it does not match test_*.py. conftest.py is
    # fixtures/plumbing, not assertions, and also does not match the glob.
    return sorted(root.glob("test_*.py"))


def _literal_len(node) -> int | None:
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return len(node.elts)
    return None


def _module_string_aliases(tree: ast.Module) -> dict:
    """`NAME = "literal"` at module scope -> {"NAME": "literal"}. Covers the
    `CHECK = "except-returns-success"` idiom so a bare `CHECK` in a Compare
    resolves to the check name it stands for."""
    out: dict = {}
    for stmt in tree.body:
        if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
                and isinstance(stmt.value, ast.Constant)
                and isinstance(stmt.value.value, str)):
            out[stmt.targets[0].id] = stmt.value.value
    return out


class _FileCounter:
    """One file's worth of hit/miss counts, walked once."""

    def __init__(self, check_names, aliases: dict):
        self.check_names = set(check_names)
        self.aliases = aliases
        self.hits = {c: 0 for c in check_names}
        self.misses = {c: 0 for c in check_names}

    def _resolve(self, node) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name) and node.id in self.aliases:
            return self.aliases[node.id]
        return None

    def _local_list_lens(self, func_node) -> dict:
        """Same-function `NAME = [literal, ...]` assignments, so a `for x in
        NAME:` a few lines below an inline list still gets its real length."""
        out: dict = {}
        for stmt in ast.walk(func_node):
            if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
                    and isinstance(stmt.targets[0], ast.Name)):
                ln = _literal_len(stmt.value)
                if ln is not None:
                    out[stmt.targets[0].id] = ln
        return out

    def _score(self, node: ast.Compare, mult: int) -> None:
        operands = [node.left] + list(node.comparators)
        matched = sorted({r for o in operands if (r := self._resolve(o)) in self.check_names})
        if not matched:
            return
        for op in node.ops:
            if isinstance(op, (ast.In, ast.Eq)):
                for c in matched:
                    self.hits[c] += mult
            elif isinstance(op, (ast.NotIn, ast.NotEq)):
                for c in matched:
                    self.misses[c] += mult

    def _walk(self, node, for_stack, local_lens) -> None:
        if isinstance(node, ast.FunctionDef):
            local_lens = self._local_list_lens(node)
        if isinstance(node, ast.For):
            mult = _literal_len(node.iter)
            if mult is None and isinstance(node.iter, ast.Name):
                mult = local_lens.get(node.iter.id)
            for_stack = for_stack + [mult]
        if isinstance(node, ast.Compare):
            mult = 1
            for m in reversed(for_stack):
                if m:
                    mult = m
                    break
            self._score(node, mult)
        for child in ast.iter_child_nodes(node):
            self._walk(child, for_stack, local_lens)

    def run(self, tree: ast.Module) -> None:
        self._walk(tree, [], {})


def fixture_coverage(check_names, root: Path | None = None) -> dict:
    """`{"available": bool, "root": str, "files": [name, ...], "per_check":
    {check: {"must_hit": n, "must_miss": n}}}`.

    `available` is False (and every count 0) only when no `test_*.py` files
    were found at all -- a bare wheel install, not a genuine zero -- so a
    reader does not mistake "this install ships no tests" for "this check has
    never been proven.\""""
    default = root is None
    root = root or _project_root()
    files = _own_test_files(root)
    per_check = {c: {"must_hit": 0, "must_miss": 0} for c in check_names}
    if not files:
        # No path at all (qa-fixes 2026-09-24): in a wheel install the default
        # root is a directory that does not exist, and printing it read as a
        # real location. Say what is true instead.
        return {"available": False,
                "root": None if default else str(root),
                "note": "this install ships no vet test files (a wheel install), "
                        "so no fixture census; see the source checkout's tests/vet",
                "files": [], "per_check": per_check}
    for fp in files:
        try:
            tree = ast.parse(fp.read_text(encoding="utf-8", errors="replace"),
                             filename=str(fp))
        except SyntaxError:
            continue
        aliases = _module_string_aliases(tree)
        counter = _FileCounter(check_names, aliases)
        counter.run(tree)
        for c in check_names:
            per_check[c]["must_hit"] += counter.hits[c]
            per_check[c]["must_miss"] += counter.misses[c]
    # The default root is named relative to the checkout: an absolute path
    # would publish this machine's layout inside every badge JSON.
    return {"available": True, "root": "tests/vet" if default else str(root),
            "files": [f.name for f in files], "per_check": per_check}
