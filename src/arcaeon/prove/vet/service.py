"""mcp_vet.service — the target-level scan entry (R11, 2026-09-01).

`grade_source` grades ONE source string. A real MCP server is a path — one file
or a directory of them — and a service (or the badge lane) needs to point at
that path and get back ONE deterministic, receipt-ready result for the whole
server, not to read files and stitch grades itself. That is this module.

Determinism is the load-bearing property (a badge is only worth anything if a
skeptic re-running it gets the same bytes): files are walked in sorted order,
each graded through the existing `grade_source` (no second scanner to drift),
and the server-level `source_sha256` is a hash OVER the sorted list of
(relpath, per-file-sha256) pairs — so the same tree always produces the same
digest, and moving/editing/adding any file moves it visibly.

No code execution, no network — same stance as the rest of the package.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path

from .grade import grade_source, _verdict
from .checks import check_names, Finding
from . import ts_checks
from . import __version__


# Files we grade: Python (the full battery) and TypeScript/JavaScript (the
# tree-sitter front end, one check, 0.0.17). The walk does NOT route: every
# gradeable file goes through `grade_source`, which is the one place that
# decides by extension, and the receipt's checks_run reads off what ran.
# Anything else is listed as skipped (honestly, not silently) so the caller
# knows the scan's real scope. Common non-source dirs are pruned so a vendored
# tree does not make the grade about someone else's code.
_PY_SUFFIX = ".py"
PRUNE_DIRS = frozenset({
    "__pycache__", ".git", ".venv", "venv", "node_modules", ".mypy_cache",
    ".pytest_cache", "build", "dist", ".tox", ".eggs", "site-packages",
    # Test/fixture directories (item 146, 2026-09-05 parity fix). Before this,
    # `grade-target`'s walk pruned only build/cache/vendor dirs while
    # bench/grade_sample.py's harness ALSO pruned test/example dirs — the two
    # selection paths disagreed, and the CLI's self-scan of `projects/mcp_vet`
    # graded its own 33 test/fixture findings as "high-severity", the same
    # inflation any stranger's repo with a test suite would get
    # (FAILURE_DISTRIBUTION_2026-09-02_sample200.md section 1). `fixtures` and
    # `__snapshots__` are two the harness itself did not have.
    "test", "tests", "__tests__", "example", "examples", "fixtures",
    "__snapshots__",
})

# Filenames that are tests/fixtures no matter which directory holds them.
# Needed because mcp_vet's OWN test_*.py files live at the package root, not
# under a `tests/` directory — directory-name pruning alone misses them.
_TEST_FILENAME_RE = re.compile(
    r"^(?:test_.*|.*_test|conftest)\.py$"
    r"|^.*\.(?:test|spec)\.(?:jsx?|tsx?|mjs|cjs)$",
    re.IGNORECASE,
)


def _gradeable(p: Path) -> bool:
    return p.suffix == _PY_SUFFIX or ts_checks.is_ts_path(p.name)


def _is_test_or_fixture(rel_parts, name: str) -> bool:
    """True if a directory on the path is a known test/fixture dir, or the
    filename itself is a test/fixture name (test_*.py, *_test.py, conftest.py,
    *.test.js/ts, *.spec.js/ts, ...)."""
    if any(part in PRUNE_DIRS for part in rel_parts):
        return True
    return bool(_TEST_FILENAME_RE.match(name))


def select_files(root: Path):
    """THE one file-selection walk. Both `scan_target` (below, `grade-target`'s
    engine) and the bench sampling harness (bench/grade_sample.py's
    candidate_files) call this so a stranger's own test suite is pruned
    identically everywhere mcp_vet grades a tree (item 146, 2026-09-05) —
    before this fix the two walks disagreed and grade-target counted a
    project's tests as its shipped server.

    Yields gradeable (.py / ts_checks.is_ts_path) files under `root`, sorted,
    with build/cache/vendor dirs AND test/fixture dirs+filenames pruned. A
    single FILE target is always yielded as-is: pointing `grade-target`
    straight at one file is an explicit ask that pruning must not override.
    """
    root = Path(root)
    if root.is_file():
        yield root
        return
    hits = []
    for p in root.rglob("*"):
        if not p.is_file() or not _gradeable(p):
            continue
        rel = p.relative_to(root)
        if _is_test_or_fixture(rel.parts, p.name):
            continue
        hits.append(p)
    for p in sorted(hits, key=lambda x: str(x.relative_to(root)).replace("\\", "/")):
        yield p


@dataclass
class TargetGrade:
    """One graded MCP server (a path). Superset of a single-file Grade: it adds
    the per-file breakdown and the file list, and its `source_sha256` is the
    tree digest (see module docstring), NOT any one file's hash."""
    tool: str
    tool_version: str
    target: str
    source_sha256: str          # digest over the sorted (relpath, sha256) set
    files_scanned: list         # [relpath, ...] sorted; the exact scope
    files_skipped: list         # [relpath, ...] not .py / .ts / .js, listed for honesty
    checks_run: list
    findings: list              # every file's findings, each carrying its file+line
    blind_spots: list
    verdict: str                # server-level = worst across files
    per_file: dict              # {relpath: verdict} — where the worst came from
    schema: int = 1

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(asdict(self), indent=indent, ensure_ascii=False)


def _iter_source_files(root: Path):
    """Yield (path, relpath_str) for every file `select_files` picks, sorted,
    pruned. A single file yields just itself."""
    root = Path(root)
    for p in select_files(root):
        rel = p.name if root.is_file() else str(p.relative_to(root)).replace("\\", "/")
        yield p, rel


def _skipped_files(root: Path) -> list:
    """Everything under root that was NOT graded: non-.py files outside pruned
    dirs, AND every .py file inside a pruned dir (test/fixture dirs included,
    item 146). The second half is the 2026-09-01 audit's finding #4 — pruning
    is by directory/filename pattern only (a dir called `build/`, `venv/`, or
    `tests/` is skipped whether or not it holds real production code), so a
    first-party module hidden there was neither scanned nor listed. It is
    still not scanned; it is now listed, so the receipt's scope is honest."""
    if root.is_file():
        return [] if _gradeable(root) else [root.name]
    out = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(root)
        pruned = _is_test_or_fixture(rel.parts, p.name)
        if _gradeable(p) and not pruned:
            continue                       # graded, not skipped
        if pruned and not _gradeable(p):
            continue                       # vendored/non-source noise: not scope
        out.append(str(rel).replace("\\", "/"))
    return out


# Third verdict state (item 146, 2026-09-05): a tree with ZERO gradeable files
# after pruning (a repo that is only tests, or only docs, or a wrong-language
# tree) is NOT a clean pass — `_verdict([])` would say "no findings in checked
# classes", which reads exactly like a server that was actually looked at and
# came back clean. That conflation is the same "hollow pass" shape
# `pass_receipt_gaps` polices for a single file; here it is caught before the
# verdict is even written, by never handing this case to `_verdict` at all.
# Deliberately NOT in `_PASS_VERDICTS` (grade.py) — a caller must not be able
# to read this as "checked, clean".
#: The one spelling (arcaeon.verdict.NO_GRADEABLE_FILES, exit 3). Since 0.9.0
#: (qa-fixes 2026-09-24) it also covers a target whose every file ran ZERO
#: checks: an unparseable file, or a .ts file without the [ts] extra.
from arcaeon.verdict import NO_GRADEABLE_FILES  # noqa: E402  "NO GRADEABLE FILES"


def scan_target(path: str | Path) -> TargetGrade:
    """Scan one MCP server (a file or a directory) and return one deterministic
    TargetGrade. Reuses grade_source per file; the server verdict is the worst
    file verdict, UNLESS zero files survived selection, in which case the
    verdict is `NO_GRADEABLE_FILES` — a third state, not a clean pass (item
    146). Raises FileNotFoundError if the path does not exist — a scan that
    cannot see its target must not quietly return a clean grade."""
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"scan target does not exist: {root}")

    files_scanned: list[str] = []
    all_findings: list[dict] = []
    per_file: dict[str, str] = {}
    tree_parts: list[str] = []

    ran_everywhere: list | None = None
    any_checked = False
    for fpath, rel in _iter_source_files(root):
        # Bytes, not read_text: universal-newline decoding rewrote CRLF and
        # made the hash disagree with the file on disk (qa-fixes item 8).
        raw = fpath.read_bytes()
        src = raw.decode("utf-8", errors="replace")
        # A TS file may keep its recorder one relative import away; the tree
        # scan can see the sibling (it is inside the same digest), so it hands
        # grade_source a resolver scoped to this tree. A Python file gets its
        # directory (`package_dir`) for the same reason, and only when the
        # target is a DIRECTORY: a single-file target's digest covers one file,
        # so its grade may not depend on siblings the receipt does not pin.
        resolve = (ts_checks.file_resolver(fpath.parent, root if root.is_dir() else fpath.parent)
                   if ts_checks.is_ts_path(rel) else None)
        package_dir = fpath.parent if (root.is_dir() and not ts_checks.is_ts_path(rel)) else None
        g = grade_source(src, rel, resolve=resolve, package_dir=package_dir)
        # checks_run for the TREE = checks that ran on EVERY file. One file that
        # failed to parse ran zero checks, and the tree's receipt says so rather
        # than claiming the registry (2026-09-01 audit critical #1). A mixed
        # py + ts tree therefore reports ["audit-record"], the one check both
        # front ends ran, and never implies the Python battery ran on the TS.
        ran_everywhere = (g.checks_run if ran_everywhere is None
                          else [c for c in ran_everywhere if c in g.checks_run])
        files_scanned.append(rel)
        per_file[rel] = g.verdict
        all_findings.extend(g.findings)
        if g.checks_run:
            any_checked = True
        tree_parts.append(f"{rel}:{hashlib.sha256(raw).hexdigest()}")

    # Deterministic tree digest: hash the sorted (relpath, per-file-hash) set.
    tree_digest = hashlib.sha256(
        "\n".join(sorted(tree_parts)).encode("utf-8", "surrogatepass")
    ).hexdigest()
    # A single-file target's digest is that file's own raw sha256, the same
    # number `vet grade <file>` and `sha256sum` print (qa-fixes item 8: the
    # tree digest over one file disagreed with both).
    if root.is_file():
        tree_digest = hashlib.sha256(root.read_bytes()).hexdigest()

    # Server verdict = worst file verdict. Reconstruct Finding objects only to
    # reuse the one _verdict ranking (no second severity table to drift).
    findings_objs = [
        Finding(f["check"], f["severity"], f.get("file", ""), f.get("line", 0),
                f.get("detail", ""))
        for f in all_findings
    ]
    # No file survived selection: never a "clean" verdict (see NO_GRADEABLE_FILES).
    # Also never "clean" when every file ran zero checks (unparseable, or TS
    # without the [ts] extra): nothing was graded, so nothing may pass.
    verdict = (NO_GRADEABLE_FILES if not files_scanned or not any_checked
               else _verdict(findings_objs))

    return TargetGrade(
        tool="mcp_vet",
        tool_version=__version__,
        target=str(root).replace("\\", "/"),
        source_sha256=tree_digest,
        files_scanned=files_scanned,
        files_skipped=_skipped_files(root),
        checks_run=list(ran_everywhere or []),
        findings=all_findings,
        blind_spots=grade_source("", "_").blind_spots,
        verdict=verdict,
        per_file=per_file,
    )
