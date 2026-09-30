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


def journal_rows_added(before: dict, after: dict) -> list:
    """For each activity.jsonl that grew, "<t> <verb>" of the rows appended
    since the start snapshot. The verb and time are enough to tell a test's
    run from a hand-run `arcaeon ...` by another process during the session;
    the target (a sha256) is left out. Read-only; never raises."""
    import json as _json
    out = []
    for name in sorted(after):
        if not name.endswith("activity.jsonl"):
            continue
        a, b = before.get(name) or 0, after.get(name)
        if b is None or b <= a:
            continue
        try:
            with open(name, "rb") as f:
                f.seek(a)
                tail = f.read(b - a).decode("utf-8", "replace")
        except OSError:
            continue
        for line in tail.splitlines():
            try:
                row = _json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                out.append(f"{row.get('t')} {row.get('verb')}")
    return out


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
                                 is_real=_is_real, rows_added=journal_rows_added)


def pytest_sessionfinish(session, exitstatus):
    if os.environ.get("ARCAEON_REAL_HOME_GUARD") == "0":
        return
    after = home_snapshot(REAL_WATCH)
    changed = home_changes(REAL_BEFORE, after)
    if not changed:
        return
    tr = session.config.pluginmanager.get_plugin("terminalreporter")
    msg = ("REAL HOME WRITTEN: the suite changed " + str(len(changed)) + " file(s) under the "
           "real home (ARCAEON_REAL_HOME_GUARD=0 skips this check): " + "; ".join(changed))
    rows = journal_rows_added(REAL_BEFORE, after)
    if rows:
        msg += (" | rows appended (a hand-run `arcaeon` elsewhere also lands here): "
                + ", ".join(rows[:20]) + (" ..." if len(rows) > 20 else ""))
    if tr is not None:
        tr.write_line(msg, red=True)
    else:
        print(msg)
    session.exitstatus = 1


# 6. The socket guard (K143). A test may talk to 127.0.0.1 / ::1 / localhost
#    (the stubs a test starts itself) and nothing else, unless it is marked
#    `live`. A non-loopback connect, connect_ex, sendto, bind or name lookup
#    is refused with SocketGuardRefused (an OSError, so the code under test
#    sees a network that is down and nothing leaves the machine) AND the test
#    is failed in its call phase naming the address, even if the code swallowed the
#    error. `live` tests are skipped unless the run selects them (`-m live`).
#    Subprocesses a test spawns are not covered by this in-process guard.
import ipaddress  # noqa: E402
import re  # noqa: E402
import socket as _socket  # noqa: E402

LOOPBACK_NAMES = frozenset({"localhost", "localhost.", "ip6-localhost"})


class SocketGuardRefused(OSError):
    """A test that is not marked `live` tried to reach past loopback."""


def is_loopback_host(host) -> bool:
    if host is None:
        return False
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    host = str(host).strip().strip("[]")
    if host.lower() in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _address_host(address):
    """The host part of a socket address, or None when it has none to judge
    (an AF_UNIX path)."""
    if isinstance(address, (tuple, list)) and address:
        return address[0]
    return None


class _Guard:
    def __init__(self):
        self.active = False
        self.hits = []

    def check(self, what, host, detail=None):
        if not self.active or is_loopback_host(host):
            return
        where = detail if detail is not None else host
        self.hits.append(f"{what} {where!r}")
        raise SocketGuardRefused(f"socket guard: {what} to {where!r} refused; only loopback "
                                 f"is allowed in a test not marked live (K143)")


SOCKET_GUARD = _Guard()
_orig_connect = _socket.socket.connect
_orig_connect_ex = _socket.socket.connect_ex
_orig_sendto = _socket.socket.sendto
_orig_bind = _socket.socket.bind
_orig_getaddrinfo = _socket.getaddrinfo


def _is_inet(sock) -> bool:
    return sock.family in (_socket.AF_INET, _socket.AF_INET6)


def _guarded_connect(self, address):
    if _is_inet(self):
        SOCKET_GUARD.check("connect", _address_host(address), address)
    return _orig_connect(self, address)


def _guarded_connect_ex(self, address):
    if _is_inet(self):
        SOCKET_GUARD.check("connect", _address_host(address), address)
    return _orig_connect_ex(self, address)


def _guarded_sendto(self, data, *args):
    address = args[-1] if args else None
    if _is_inet(self) and address is not None:
        SOCKET_GUARD.check("sendto", _address_host(address), address)
    return _orig_sendto(self, data, *args)


def _guarded_bind(self, address):
    if _is_inet(self):
        host = _address_host(address)
        # "" and 0.0.0.0 / :: are every interface: not loopback
        SOCKET_GUARD.check("bind", host if host else "0.0.0.0", address)
    return _orig_bind(self, address)


def _guarded_getaddrinfo(host, *args, **kwargs):
    if host is not None:
        SOCKET_GUARD.check("lookup", host)
    return _orig_getaddrinfo(host, *args, **kwargs)


_socket.socket.connect = _guarded_connect
_socket.socket.connect_ex = _guarded_connect_ex
_socket.socket.sendto = _guarded_sendto
_socket.socket.bind = _guarded_bind
_socket.getaddrinfo = _guarded_getaddrinfo

_LIVE_SELECTED = re.compile(r"(?<!not )\blive\b")


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "live: talks to a real model or the hosted witness; skipped unless the "
                   "run selects it (`-m live`); the only tests the socket guard lets past "
                   "loopback (K143)")


def pytest_collection_modifyitems(config, items):
    if _LIVE_SELECTED.search(config.getoption("markexpr") or ""):
        return
    skip = pytest.mark.skip(reason="live test: skipped by default; run with -m live (K143)")
    for item in items:
        if item.get_closest_marker("live") is not None:
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def _socket_guard(request):
    """Loopback only, unless the test is marked `live`."""
    if request.node.get_closest_marker("live") is not None:
        yield
        return
    SOCKET_GUARD.hits = []
    SOCKET_GUARD.active = True
    try:
        yield
    finally:
        SOCKET_GUARD.active = False
        SOCKET_GUARD.hits = []


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """A test whose body reached past loopback is FAILED in its call phase,
    naming each address, whatever the body did with the refusal."""
    outcome = yield
    report = outcome.get_result()
    if call.when != "call" or not SOCKET_GUARD.hits:
        return
    if item.get_closest_marker("live") is not None:
        return
    hits, SOCKET_GUARD.hits = SOCKET_GUARD.hits, []
    report.outcome = "failed"
    report.longrepr = ("socket guard (K143): a test not marked live reached past loopback: "
                       + "; ".join(dict.fromkeys(hits)))


@pytest.fixture
def socket_guard():
    """The guard's parts, for tests/test_socket_guard.py."""
    import types
    return types.SimpleNamespace(guard=SOCKET_GUARD, refused=SocketGuardRefused,
                                 is_loopback_host=is_loopback_host)
