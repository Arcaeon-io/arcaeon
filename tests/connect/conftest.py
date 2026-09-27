"""Every connect test runs with every home variable pointed at a temp folder.

`connect --write` must never touch a real home. ARCAEON_CONNECT_HOME is the
fake home a test writes into; HOME, USERPROFILE, APPDATA, LOCALAPPDATA and
XDG_CONFIG_HOME are pointed at a separate temp folder too, so even a test
that unsets ARCAEON_CONNECT_HOME resolves nothing outside tmp_path.
"""
from __future__ import annotations

import pytest

from arcaeon.connect import catalog as C


@pytest.fixture(autouse=True)
def _no_real_home(tmp_path, monkeypatch):
    guard = tmp_path / "not-a-real-home"
    for var in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(var, str(guard))
    monkeypatch.setenv(C.HOME_ENV, str(tmp_path / "fake-home"))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    return guard
