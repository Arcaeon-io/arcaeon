"""Load a module from a file path, for tests that exercise a script (tools/,
hooks/, the vet action) which is not an importable package.

The root conftest puts tests/ on sys.path, so `from _load import load_module`
works from every test directory. prune tests in MANIFEST.in keeps this file
out of the sdist.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def load_module(name: str, path: str | Path, *, register: bool = False) -> ModuleType:
    """Build a spec for `path`, exec it as module `name`, return the module.

    register=True puts the module in sys.modules[name] before it runs, for
    code that looks its own module up by name (dataclasses, pickling).
    """
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None, f"no module spec for {path}"
    assert spec.loader is not None, f"module spec for {path} has no loader"
    mod = importlib.util.module_from_spec(spec)
    if register:
        sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod
