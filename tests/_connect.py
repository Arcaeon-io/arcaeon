"""entry_for: a connect catalog lookup that fails by name instead of handing
back None, for tests that look up a client they know is in the catalog.

The root conftest puts tests/ on sys.path, so `from _connect import entry_for`
works from every test directory.
"""
from __future__ import annotations

from arcaeon.connect import catalog as C


def entry_for(name: str) -> C.Entry:
    """C.get(name), asserted present."""
    entry = C.get(name)
    assert entry is not None, f"{name!r} is not in the connect catalog"
    return entry
