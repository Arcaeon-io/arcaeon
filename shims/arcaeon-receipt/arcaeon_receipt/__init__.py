# SPDX-License-Identifier: MIT
"""arcaeon_receipt: compatibility shim. This code now lives in `arcaeon.record.receipt`.

`pip install arcaeon-receipt` installs `arcaeon` and this one forwarding module, nothing
else. Every old name (and every old submodule, `arcaeon_receipt.<name>`) resolves to
the same object in its new home. The shim goes away with arcaeon 1.0.0.
"""
import importlib as _importlib
import importlib.abc as _abc
import importlib.util as _util
import sys as _sys
import warnings as _warnings

_NEW = "arcaeon.record.receipt"

#: old submodule -> its new home (MIGRATION.md, "Per-module tables")
_SUBMODULES = {
    'arcaeon_receipt.approval': 'arcaeon.record.receipt.approval',
    'arcaeon_receipt.approval_mcp': 'arcaeon.record.receipt.approval_mcp',
    'arcaeon_receipt.archive': 'arcaeon.record.receipt.archive',
    'arcaeon_receipt.authorship': 'arcaeon.record.receipt.authorship',
    'arcaeon_receipt.authorship_ingest': 'arcaeon.record.receipt.authorship_ingest',
    'arcaeon_receipt.authorship_mcp': 'arcaeon.record.receipt.authorship_mcp',
    'arcaeon_receipt.ballot': 'arcaeon.record.receipt.ballot',
    'arcaeon_receipt.call': 'arcaeon.record.receipt.call',
    'arcaeon_receipt.call_mcp': 'arcaeon.record.receipt.call_mcp',
    'arcaeon_receipt.call_proxy': 'arcaeon.record.receipt.call_proxy',
    'arcaeon_receipt.cite': 'arcaeon.record.receipt.cite',
    'arcaeon_receipt.cite_batch': 'arcaeon.record.receipt.cite_batch',
    'arcaeon_receipt.cite_extract': 'arcaeon.record.receipt.cite_extract',
    'arcaeon_receipt.cite_mcp': 'arcaeon.record.receipt.cite_mcp',
    'arcaeon_receipt.cli': 'arcaeon.record.receipt.cli',
    'arcaeon_receipt.core': 'arcaeon.record.receipt.core',
    'arcaeon_receipt.roster_report': 'arcaeon.record.receipt.roster_report',
    'arcaeon_receipt.verify_batch': 'arcaeon.record.receipt.verify_batch',
}

#: the old package's own __all__, unchanged
__all__ = ['RECEIPT_VERSION',
           'ADHERENCE_VALUES',
           'build_receipt',
           'verify_receipt',
           'render_exhibit',
           'load_receipt',
           'save_receipt',
           'engagement_scope',
           'attestation',
           'attach_attestation_signature',
           '__version__']

_warnings.warn("arcaeon_receipt is deprecated: import arcaeon.record.receipt instead (removed in arcaeon 1.0.0)",
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
    """`import arcaeon_receipt.x` returns the new module itself, not a copy."""

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

    def get_code(self, name):          # `python -m arcaeon_receipt.x` (runpy)
        new = _SUBMODULES[name]
        return _util.find_spec(new).loader.get_code(new)


if not any(type(f).__module__ == __name__ for f in _sys.meta_path):
    _sys.meta_path.insert(0, _Alias())


def _script_arcaeon_receipt(argv=None):
    """The old `arcaeon-receipt` console script: now `arcaeon receipt --legacy-exit`."""
    argv = list(_sys.argv[1:] if argv is None else argv)
    from arcaeon.cli import main
    return main(["receipt", *argv, "--legacy-exit"])
