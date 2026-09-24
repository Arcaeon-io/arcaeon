"""Suite-wide isolation for the audit ledger (2026-08-30, board B2b).

`mcp_vet_scan` / `mcp_vet_grade` now append a row to a tamper-evident ledger on
every call, and the default path is `~/.mcp_vet/audit.jsonl` — the developer's
REAL one. A test suite that quietly grows the operator's audit log is exactly
the kind of unannounced side effect this project exists to complain about, so
every test in this tree runs against a throwaway ledger under tmp.

The redirect is the same `MCP_VET_AUDIT_LEDGER` env var an operator uses, which
means the isolation is also a standing test that the env var works: if it ever
stopped being read, `test_the_env_var_redirects_and_home_is_never_touched`
fails loudly rather than the suite silently writing to $HOME.
"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))


@pytest.fixture(autouse=True, scope="session")
def _isolate_audit_ledger(tmp_path_factory):
    prior = os.environ.get("MCP_VET_AUDIT_LEDGER")
    os.environ["MCP_VET_AUDIT_LEDGER"] = str(
        tmp_path_factory.mktemp("audit_ledger") / "audit.jsonl")
    yield
    if prior is None:
        os.environ.pop("MCP_VET_AUDIT_LEDGER", None)
    else:
        os.environ["MCP_VET_AUDIT_LEDGER"] = prior


# --- arcaeon merge: the two PRIVATE seal_chain gates ------------------------
# gate_drift's two seal_chain.* gates match against a private checkout's
# bridge/witness/seal_chain.py, which is NOT shipped in arcaeon.
# arcaeon.prove.vet.gate_drift reaches it only through ARCAEON_VET_PRIVATE_ROOT.
# When that variable names a checkout that has the file, the gates run; anywhere
# else the tests that need them skip BY NAME instead of failing or passing silently.
_PRIVATE_ENV = os.environ.get("ARCAEON_VET_PRIVATE_ROOT")
PRIVATE_SEAL_CHAIN = bool(_PRIVATE_ENV) and (
    Path(_PRIVATE_ENV) / "bridge" / "witness" / "seal_chain.py").is_file()

_NEEDS_PRIVATE = ("seal_chain", "test_every_registered_gate_corpus_has_at_least_one_true_and_one_false",
                  "test_cli_check_all_exits_zero_when_clean")


def pytest_collection_modifyitems(config, items):
    if PRIVATE_SEAL_CHAIN:
        return
    skip = pytest.mark.skip(reason="private piece: vet's seal_chain gates need a private "
                                   "checkout (set ARCAEON_VET_PRIVATE_ROOT); not in arcaeon")
    for item in items:
        if "test_gate_drift" in item.nodeid and any(n in item.nodeid for n in _NEEDS_PRIVATE):
            item.add_marker(skip)


# --- qa-fixes 2026-09-24: no default key path ---------------------------------
# receipts.RECEIPT_KEY_FILE no longer defaults to a per-machine secrets folder,
# and `badge --receipt` with no key is UNSIGNED (never an ephemeral stand-in).
# Tests that need a signature ask for one explicitly with this fixture.
@pytest.fixture
def receipt_key(monkeypatch):
    import base64
    from arcaeon.prove.vet import receipts
    seed = bytes(range(32))
    monkeypatch.setenv(receipts.RECEIPT_KEY_ENV, base64.b64encode(seed).decode("ascii"))
    return seed


@pytest.fixture(autouse=True)
def _forget_learned_namespace_prefixes():
    """sealed_scan remembers a key's namespace prefix for the process
    (ns-from-key); no test may inherit one an earlier test taught it."""
    try:
        from arcaeon.remote import sealed_scan
    except ImportError:
        yield
        return
    sealed_scan._reset_prefix_cache()
    yield
    sealed_scan._reset_prefix_cache()
