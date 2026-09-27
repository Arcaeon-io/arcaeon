"""K090R: an adapter called without its framework raises one line naming
the package to install, not a bare ModuleNotFoundError."""
from __future__ import annotations

import importlib
import sys

import pytest

#: adapter module -> (the top-level module it imports, the pip package)
ADAPTERS = {
    "autogen": ("autogen_core", "autogen-core"),
    "crewai": ("crewai", "crewai"),
    "langchain": ("langchain_core", "langchain-core"),
    "llamaindex": ("llama_index", "llama-index-core"),
    "openai_agents": ("agents", "openai-agents"),
}


@pytest.mark.parametrize("adapter", sorted(ADAPTERS))
def test_missing_framework_names_the_package(adapter, monkeypatch):
    top, package = ADAPTERS[adapter]
    for name in [m for m in sys.modules if m == top or m.startswith(top + ".")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, top, None)          # the module is absent
    mod = importlib.import_module(f"arcaeon.adapters.{adapter}")
    with pytest.raises(ModuleNotFoundError) as got:
        mod.arcaeon_tools()
    msg = str(got.value)
    assert f"pip install {package}" in msg and f"arcaeon.adapters.{adapter}" in msg
    assert "\n" not in msg
    assert isinstance(got.value.__cause__, ImportError)
