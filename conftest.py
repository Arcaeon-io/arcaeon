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

# 5. The real home is never written (K14xR). mcp_vet's call record defaults to
#    ~/.mcp_vet/audit.jsonl; it is pointed at the session's throwaway home too
#    (tests/vet/conftest.py still gives the vet tree its own). The real
#    ~/.arcaeon and ~/.mcp_vet are measured (file name -> size) now and again
#    when the session ends; any change fails the session by name. Another
#    process writing there during a run (a hand-run `arcaeon demo`) trips it
#    too: ARCAEON_REAL_HOME_GUARD=0 turns the end check off for such a run.
REAL_HOME = Path.home()
REAL_WATCH = (REAL_HOME / ".arcaeon", REAL_HOME / ".mcp_vet")
SESSION_HOME = os.environ["ARCAEON_HOME"]
SESSION_VET_LEDGER = str(Path(SESSION_HOME) / "mcp_vet" / "audit.jsonl")
os.environ["MCP_VET_AUDIT_LEDGER"] = SESSION_VET_LEDGER


def home_snapshot(dirs) -> dict:
    """{file path: size in bytes} for every file under each dir (absent dirs add nothing)."""
    out = {}
    for d in dirs:
        d = Path(d)
        if not d.is_dir():
            continue
        for f in d.rglob("*"):
            try:
                if f.is_file():
                    out[str(f)] = f.stat().st_size
            except OSError:
                continue
    return out


def home_changes(before: dict, after: dict) -> list:
    """Each file added, removed or resized between two snapshots, named."""
    changed = []
    for name in sorted(set(before) | set(after)):
        a, b = before.get(name), after.get(name)
        if a == b:
            continue
        if a is None:
            changed.append(f"{name} (new, {b} bytes)")
        elif b is None:
            changed.append(f"{name} (removed)")
        else:
            changed.append(f"{name} ({a} -> {b} bytes)")
    return changed


def _is_real(value, real: Path) -> bool:
    if not value:
        return True
    try:
        return Path(value).resolve() == real.resolve()
    except OSError:
        return False


REAL_BEFORE = home_snapshot(REAL_WATCH)

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


@pytest.fixture(autouse=True)
def _never_the_real_home(monkeypatch):
    """Every test starts with ARCAEON_HOME and MCP_VET_AUDIT_LEDGER pointing
    away from the real home. A test that sets its own (seven files do, per
    test) still wins: this only steps in when the variable is gone or names
    the real place."""
    if _is_real(os.environ.get("ARCAEON_HOME"), REAL_HOME / ".arcaeon"):
        monkeypatch.setenv("ARCAEON_HOME", SESSION_HOME)
    if _is_real(os.environ.get("MCP_VET_AUDIT_LEDGER"), REAL_HOME / ".mcp_vet" / "audit.jsonl"):
        monkeypatch.setenv("MCP_VET_AUDIT_LEDGER", SESSION_VET_LEDGER)


@pytest.fixture
def real_home_guard():
    """The guard's parts, for tests/test_real_home_guard.py."""
    import types
    return types.SimpleNamespace(real_home=REAL_HOME, watch=REAL_WATCH, before=REAL_BEFORE,
                                 session_home=SESSION_HOME, vet_ledger=SESSION_VET_LEDGER,
                                 snapshot=home_snapshot, changes=home_changes,
                                 is_real=_is_real)


def pytest_sessionfinish(session, exitstatus):
    if os.environ.get("ARCAEON_REAL_HOME_GUARD") == "0":
        return
    changed = home_changes(REAL_BEFORE, home_snapshot(REAL_WATCH))
    if not changed:
        return
    tr = session.config.pluginmanager.get_plugin("terminalreporter")
    msg = ("REAL HOME WRITTEN: the suite changed " + str(len(changed)) + " file(s) under the "
           "real home (ARCAEON_REAL_HOME_GUARD=0 skips this check): " + "; ".join(changed))
    if tr is not None:
        tr.write_line(msg, red=True)
    else:
        print(msg)
    session.exitstatus = 1
