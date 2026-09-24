# SPDX-License-Identifier: MIT
"""mcp_vet: compatibility shim. This code now lives in `arcaeon.prove.vet`.

`pip install arcaeon-mcp-vet` installs `arcaeon` and this one forwarding module, nothing
else. Every old name (and every old submodule, `mcp_vet.<name>`) resolves to
the same object in its new home. The shim goes away with arcaeon 1.0.0.
"""
import importlib as _importlib
import importlib.abc as _abc
import importlib.util as _util
import sys as _sys
import warnings as _warnings

_NEW = "arcaeon.prove.vet"

#: old submodule -> its new home (MIGRATION.md, "Per-module tables")
_SUBMODULES = {
    'mcp_vet.__main__': 'arcaeon.prove.vet.__main__',
    'mcp_vet.badge': 'arcaeon.prove.vet.badge',
    'mcp_vet.badge_cli': 'arcaeon.prove.vet.badge_cli',
    'mcp_vet.checks': 'arcaeon.prove.vet.checks',
    'mcp_vet.dynamic_checks': 'arcaeon.prove.vet.dynamic_checks',
    'mcp_vet.fixture_census': 'arcaeon.prove.vet.fixture_census',
    'mcp_vet.gate_drift': 'arcaeon.prove.vet.gate_drift',
    'mcp_vet.grade': 'arcaeon.prove.vet.grade',
    'mcp_vet.instrument': 'arcaeon.prove.vet.instrument',
    'mcp_vet.probe': 'arcaeon.prove.vet.probe',
    'mcp_vet.receipts': 'arcaeon.prove.vet.receipts',
    'mcp_vet.server': 'arcaeon.prove.vet.server',
    'mcp_vet.service': 'arcaeon.prove.vet.service',
    'mcp_vet.ts_checks': 'arcaeon.prove.vet.ts_checks',
    'mcp_vet.verify_page': 'arcaeon.prove.vet.verify_page',
}

_warnings.warn("mcp_vet is deprecated: import arcaeon.prove.vet instead (removed in arcaeon 1.0.0)",
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
    """`import mcp_vet.x` returns the new module itself, not a copy."""

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

    def get_code(self, name):          # `python -m mcp_vet.x` (runpy)
        new = _SUBMODULES[name]
        return _util.find_spec(new).loader.get_code(new)


if not any(type(f).__module__ == __name__ for f in _sys.meta_path):
    _sys.meta_path.insert(0, _Alias())


def _script_mcp_vet(argv=None):
    """The old `mcp-vet` console script: now `arcaeon vet --legacy-exit`."""
    argv = list(_sys.argv[1:] if argv is None else argv)
    from arcaeon.cli import main
    return main(["vet", *argv, "--legacy-exit"])
