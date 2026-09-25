"""Root conftest: run the suite against src/ without installing anything.

1. src/ goes first on sys.path, so `import arcaeon` is this checkout.
2. PYTHONPATH carries src/ too, so every subprocess a test spawns
   (`python -m arcaeon.record.adapter.proxy`, the MCP servers, crash workers)
   imports the same checkout.
3. The pre-merge package names are BLOCKED in-process. This machine has the old
   packages installed (editable), and a test that still said
   `import arcaeon_ledger` would quietly pass against the OLD code. A blocked
   name fails loud instead. The names live on only in the W2 shims.
"""
import importlib.abc
import os
import sys
from pathlib import Path

SRC = str(Path(__file__).resolve().parent / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
_pp = os.environ.get("PYTHONPATH", "")
if SRC not in _pp.split(os.pathsep):
    os.environ["PYTHONPATH"] = SRC + (os.pathsep + _pp if _pp else "")

OLD_NAMES = frozenset({
    "arcaeon_ledger", "arcaeon_adapter", "arcaeon_receipt", "arcaeon_once", "arcaeon_audit",
    "arcaeon_compact", "arcaeon_continuity", "arcaeon_baseline", "mcp_vet", "arcaeon_dedup",
    "arcaeon_distill", "arcaeon_meter", "arcaeon_connector", "arcaeon_ledger_mcp",
})


class _BlockOldNames(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in OLD_NAMES:
            raise ImportError(f"{name!r} is a pre-merge package name; import it from "
                              f"arcaeon.* (see MIGRATION.md)")
        return None


# 4. The activity journal (arcaeon.journal) is pointed at a throwaway directory
#    for the whole run, subprocesses included, so the suite never writes to the
#    developer's real ~/.arcaeon/activity.jsonl. A test that wants a journal
#    of its own sets ARCAEON_HOME with monkeypatch.
import tempfile  # noqa: E402

os.environ["ARCAEON_HOME"] = tempfile.mkdtemp(prefix="arcaeon-test-home-")
os.environ.pop("ARCAEON_JOURNAL", None)

for _m in [m for m in sys.modules if m.split(".")[0] in OLD_NAMES]:
    del sys.modules[_m]
sys.meta_path.insert(0, _BlockOldNames())


import pytest  # noqa: E402

_TESTS = Path(__file__).resolve().parent / "tests"


@pytest.fixture(autouse=True)
def _run_from_the_old_repo_root(request, monkeypatch):
    """Each source suite ran with its own repo root as the working directory,
    and a few tests lean on that (receipt's archive tests pass
    "examples/ballots/" relative). tests/<key>/ mirrors that root, so a ported
    test runs from there. The merge-level tests in tests/ itself do not move."""
    path = Path(str(request.node.fspath)).resolve()
    try:
        rel = path.relative_to(_TESTS)
    except ValueError:
        return
    if len(rel.parts) >= 2:
        monkeypatch.chdir(_TESTS / rel.parts[0])
