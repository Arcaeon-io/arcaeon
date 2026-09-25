# SPDX-License-Identifier: MIT
"""arcaeon_meter: compatibility shim. This code now lives in `arcaeon.save.meter`.

`pip install arcaeon-meter` installs `arcaeon` and this one forwarding module, nothing
else. Every old name (and every old submodule, `arcaeon_meter.<name>`) resolves to
the same object in its new home. The shim goes away with arcaeon 1.0.0.
"""
import importlib as _importlib
import importlib.abc as _abc
import importlib.util as _util
import sys as _sys
import warnings as _warnings

_NEW = "arcaeon.save.meter"

#: this shim's own release (its pyproject version), not the moved code's
__version__ = "0.1.8"

#: old submodule -> its new home (MIGRATION.md, "Per-module tables")
_SUBMODULES = {
    'arcaeon_meter.__main__': 'arcaeon.save.meter.__main__',
    'arcaeon_meter.asgi': 'arcaeon.save.meter.asgi',
    'arcaeon_meter.cli': 'arcaeon.save.meter.cli',
    'arcaeon_meter.keys': 'arcaeon.save.meter.keys',
}

#: the old package's own __all__, unchanged
__all__ = ['Meter',
           'Allowance',
           'Denied',
           'MeterDenied',
           'Usage',
           'key_hash',
           'key_id_of',
           'KEY_PREFIX',
           'LEGACY_KEYSPACE_PREFIX']

_warnings.warn("arcaeon_meter is deprecated: import arcaeon.save.meter instead (removed in arcaeon 1.0.0)",
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
    """`import arcaeon_meter.x` returns the new module itself, not a copy."""

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

    def get_code(self, name):          # `python -m arcaeon_meter.x` (runpy)
        new = _SUBMODULES[name]
        return _util.find_spec(new).loader.get_code(new)


if not any(type(f).__module__ == __name__ for f in _sys.meta_path):
    _sys.meta_path.insert(0, _Alias())


def _script_arcaeon_meter(argv=None):
    """The old `arcaeon-meter` console script: now `arcaeon meter`."""
    argv = list(_sys.argv[1:] if argv is None else argv)
    from arcaeon.cli import main
    return main(["meter", *argv])
