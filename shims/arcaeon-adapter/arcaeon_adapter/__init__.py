# SPDX-License-Identifier: MIT
"""arcaeon_adapter: compatibility shim. This code now lives in `arcaeon.record.adapter`.

`pip install arcaeon-adapter` installs `arcaeon` and this one forwarding module, nothing
else. Every old name (and every old submodule, `arcaeon_adapter.<name>`) resolves to
the same object in its new home. The shim goes away with arcaeon 1.0.0.
"""
import importlib as _importlib
import importlib.abc as _abc
import importlib.util as _util
import sys as _sys
import warnings as _warnings

_NEW = "arcaeon.record.adapter"

#: this shim's own release (its pyproject version), not the moved code's
__version__ = "0.2.1"

#: old submodule -> its new home (MIGRATION.md, "Per-module tables")
_SUBMODULES = {
    'arcaeon_adapter.__main__': 'arcaeon.record.adapter.__main__',
    'arcaeon_adapter._echo_server': 'arcaeon.record.adapter._echo_server',
    'arcaeon_adapter._ledger': 'arcaeon.record.adapter._ledger',
    'arcaeon_adapter._version': 'arcaeon.record.adapter._version',
    'arcaeon_adapter.http_forward': 'arcaeon.record.adapter.http_forward',
    'arcaeon_adapter.observer': 'arcaeon.record.adapter.observer',
    'arcaeon_adapter.proxy': 'arcaeon.record.adapter.proxy',
    'arcaeon_adapter.selftest': 'arcaeon.record.adapter.selftest',
    'arcaeon_adapter.tape': 'arcaeon.record.adapter.tape',
}

#: the old package's own __all__, unchanged
__all__ = ['SEAM',
           'IMPL',
           'VERSION',
           '__version__',
           'FrameSplitter',
           'SeamObserver',
           'main',
           'relay',
           'run']

_warnings.warn("arcaeon_adapter is deprecated: import arcaeon.record.adapter instead (removed in arcaeon 1.0.0)",
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
    """`import arcaeon_adapter.x` returns the new module itself, not a copy."""

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

    def get_code(self, name):          # `python -m arcaeon_adapter.x` (runpy)
        new = _SUBMODULES[name]
        return _util.find_spec(new).loader.get_code(new)


if not any(type(f).__module__ == __name__ for f in _sys.meta_path):
    _sys.meta_path.insert(0, _Alias())


def _script_arcaeon_adapter(argv=None):
    """The old `arcaeon-adapter` console script: now `arcaeon proxy`."""
    argv = list(_sys.argv[1:] if argv is None else argv)
    from arcaeon.cli import main
    return main(["proxy", *argv])


def _script_arcaeon_adapter_selftest(argv=None):
    """The old `arcaeon-adapter-selftest` console script: now `arcaeon selftest adapter`."""
    argv = list(_sys.argv[1:] if argv is None else argv)
    from arcaeon.cli import main
    return main(["selftest", "adapter", *[a for a in argv if a in ("-h", "--help")]])
