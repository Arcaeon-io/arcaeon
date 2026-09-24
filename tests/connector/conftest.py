"""Suite-wide isolation for the connector's own call record (2026-09-02, 0.1.4).

Every tool call through the connector now appends a hash-chained row to
`$ARCAEON_CALL_RECORD` (default: `arcaeon.calls.jsonl` beside the ledger log,
which for a bare test run is the repo root). A test suite that quietly grows a
call record in the working tree is the kind of side effect this product exists
to complain about, so every test runs against a throwaway record under tmp.
Same shape as mcp_vet's conftest, for the same reason.

The redirect uses the operator's own env var, so it is also a standing test
that the var is read: if it stopped working, `test_call_record_env_var_is_read`
in test_call_record.py fails rather than the suite silently writing to cwd.
"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))


@pytest.fixture(autouse=True, scope="session")
def _isolate_call_record(tmp_path_factory):
    prior = os.environ.get("ARCAEON_CALL_RECORD")
    os.environ["ARCAEON_CALL_RECORD"] = str(
        tmp_path_factory.mktemp("call_record") / "arcaeon.calls.jsonl")
    yield
    if prior is None:
        os.environ.pop("ARCAEON_CALL_RECORD", None)
    else:
        os.environ["ARCAEON_CALL_RECORD"] = prior


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
