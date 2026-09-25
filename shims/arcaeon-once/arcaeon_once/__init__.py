# SPDX-License-Identifier: MIT
"""arcaeon_once: compatibility shim. This code now lives in `arcaeon.record.once`.

`pip install arcaeon-once` installs `arcaeon` and this one forwarding module, nothing
else. Every old name (and every old submodule, `arcaeon_once.<name>`) resolves to
the same object in its new home. The shim goes away with arcaeon 1.0.0.
"""
import importlib as _importlib
import importlib.abc as _abc
import importlib.util as _util
import sys as _sys
import warnings as _warnings

_NEW = "arcaeon.record.once"

#: this shim's own release (its pyproject version), not the moved code's
__version__ = "0.2.4"

#: old submodule -> its new home (MIGRATION.md, "Per-module tables")
_SUBMODULES = {
    'arcaeon_once._ledger': 'arcaeon.record.call_record',
    'arcaeon_once.cli': 'arcaeon.record.once.cli',
    'arcaeon_once.mcp_server': 'arcaeon.record.once.mcp_server',
    'arcaeon_once.selftest': 'arcaeon.record.once.selftest',
}

#: the old package's own __all__, unchanged
__all__ = ['guard',
           'receipt',
           'complete',
           'rebuild_index',
           'reclaim',
           'Receipt',
           'GuardContext',
           'AlreadyExecuted',
           'Indeterminate',
           'TamperDetected',
           'IndexUnavailable',
           'HolderAlive',
           'LivenessUnknown']

_warnings.warn("arcaeon_once is deprecated: import arcaeon.record.once instead (removed in arcaeon 1.0.0)",
               DeprecationWarning, stacklevel=2)

_target = _importlib.import_module(_NEW)


def __getattr__(name):
    try:
        return getattr(_target, name)
    except AttributeError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None


def __dir__():
    return sorted(set(globals()) | set(dir(_target)))


class _Alias(_abc.MetaPathFinder, _abc.Loader):
    """`import arcaeon_once.x` returns the new module itself, not a copy."""

    def find_spec(self, name, path=None, target=None):
        if name not in _SUBMODULES:
            return None
        return _util.spec_from_loader(name, self, is_package=self.is_package(name))

    def create_module(self, spec):
        return _importlib.import_module(_SUBMODULES[spec.name])

    def exec_module(self, module):
        pass

    def is_package(self, name):
        spec = _util.find_spec(_SUBMODULES[name])
        return spec is not None and spec.submodule_search_locations is not None

    def get_code(self, name):          # `python -m arcaeon_once.x` (runpy)
        new = _SUBMODULES[name]
        return _util.find_spec(new).loader.get_code(new)


if not any(type(f).__module__ == __name__ for f in _sys.meta_path):
    _sys.meta_path.insert(0, _Alias())


def _script_arcaeon_once(argv=None):
    """The old `arcaeon-once` console script: now `arcaeon once`."""
    argv = list(_sys.argv[1:] if argv is None else argv)
    from arcaeon.cli import main
    return main(["once", *argv])
