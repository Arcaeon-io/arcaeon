# SPDX-License-Identifier: MIT
"""arcaeon_continuity: compatibility shim. This code now lives in `arcaeon.prove.continuity`.

`pip install arcaeon-continuity` installs `arcaeon` and this one forwarding module, nothing
else. Every old name (and every old submodule, `arcaeon_continuity.<name>`) resolves to
the same object in its new home. The shim goes away with arcaeon 1.0.0.
"""
import importlib as _importlib
import importlib.abc as _abc
import importlib.util as _util
import sys as _sys
import warnings as _warnings

_NEW = "arcaeon.prove.continuity"

#: old submodule -> its new home (MIGRATION.md, "Per-module tables")
_SUBMODULES = {
    'arcaeon_continuity.__main__': 'arcaeon.prove.continuity.__main__',
    'arcaeon_continuity._ledger': 'arcaeon.record.call_record',
    'arcaeon_continuity.calibration': 'arcaeon.prove.continuity.calibration',
    'arcaeon_continuity.mcp_server': 'arcaeon.prove.continuity.mcp_server',
    'arcaeon_continuity.selftest': 'arcaeon.prove.continuity.selftest',
}

#: the old package's own __all__, unchanged
__all__ = ['ContinuitySnapshot',
           'CarryResult',
           'ContinuationVerdict',
           'DropReceipt',
           'snapshot',
           'carry_forward',
           'verify_continuation',
           'drop_receipt',
           'restate',
           'added_since_seal',
           'diff_seals',
           'CheckpointReceipt',
           'classify_checkpoint',
           'CHECKPOINT_OUTCOMES',
           'VERDICT_COMPARISONS',
           'verdict_from_dict',
           'UnsupportedVerdictVersion',
           'DeliveryReceipt',
           'DELIVERY_OUTCOMES',
           'ContinuityDependencyError',
           'digest_json']

_warnings.warn("arcaeon_continuity is deprecated: import arcaeon.prove.continuity instead (removed in arcaeon 1.0.0)",
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
    """`import arcaeon_continuity.x` returns the new module itself, not a copy."""

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

    def get_code(self, name):          # `python -m arcaeon_continuity.x` (runpy)
        new = _SUBMODULES[name]
        return _util.find_spec(new).loader.get_code(new)


if not any(type(f).__module__ == __name__ for f in _sys.meta_path):
    _sys.meta_path.insert(0, _Alias())
