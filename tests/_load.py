"""Load a module from a file path, for tests that exercise a script (tools/,
hooks/, the vet action) which is not an importable package; and must_match,
a re.search that names what was missing when it finds nothing.

The root conftest puts tests/ on sys.path, so `from _load import load_module`
works from every test directory. prune tests in MANIFEST.in keeps this file
out of the sdist.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, overload


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


@overload
def must_match(pattern: str | re.Pattern[str], text: str, flags: int = 0) -> re.Match[str]: ...
@overload
def must_match(pattern: bytes | re.Pattern[bytes], text: bytes, flags: int = 0) -> re.Match[bytes]: ...
def must_match(pattern: Any, text: Any, flags: int = 0) -> Any:
    """re.search that fails with the pattern and the start of the text, not
    an AttributeError on None. A compiled pattern takes flags=0 only.
    """
    m = re.search(pattern, text, flags)
    shown = pattern.pattern if isinstance(pattern, re.Pattern) else pattern
    assert m is not None, f"no match for {shown!r} in {text[:200]!r}"
    return m
