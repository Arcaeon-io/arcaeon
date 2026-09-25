# SPDX-License-Identifier: MIT
"""arcaeon_ledger: compatibility shim. This code now lives in `arcaeon.record.ledger`.

`pip install arcaeon-ledger` installs `arcaeon` and this one forwarding module, nothing
else. Every old name (and every old submodule, `arcaeon_ledger.<name>`) resolves to
the same object in its new home. The shim goes away with arcaeon 1.0.0.
"""
import importlib as _importlib
import importlib.abc as _abc
import importlib.util as _util
import sys as _sys
import warnings as _warnings

_NEW = "arcaeon.record.ledger"

#: this shim's own release (its pyproject version), not the moved code's
__version__ = "0.8.1"

#: old submodule -> its new home (MIGRATION.md, "Per-module tables")
_SUBMODULES = {
    'arcaeon_ledger.adversarial': 'arcaeon.record.ledger.adversarial',
    'arcaeon_ledger.artefact': 'arcaeon.record.ledger.artefact',
    'arcaeon_ledger.bundle': 'arcaeon.record.ledger.bundle',
    'arcaeon_ledger.cli': 'arcaeon.record.ledger.cli',
    'arcaeon_ledger.mcp_server': 'arcaeon.record.ledger.mcp_server',
    'arcaeon_ledger.mutation_harness': 'arcaeon.record.ledger.mutation_harness',
    'arcaeon_ledger.reconcile': 'arcaeon.prove.reconcile',
    'arcaeon_ledger.selftest': 'arcaeon.record.ledger.selftest',
    'arcaeon_ledger.tape_pin': 'arcaeon.record.ledger.tape_pin',
    'arcaeon_ledger.witness': 'arcaeon.record.ledger.witness',
}

#: the old package's own __all__, unchanged
__all__ = ['LedgerWriteError',
           'UnverifiedLedgerError',
           'Ledger',
           'VerifyResult',
           'verify_file',
           'chain_at',
           'authority',
           'Head',
           'declare_break',
           'bind_artefact',
           'verify_artefact',
           'digest_bytes',
           'digest_json',
           'WitnessStore',
           'publish_head',
           'verify_against_witness',
           'WitnessVerdict']

_warnings.warn("arcaeon_ledger is deprecated: import arcaeon.record.ledger instead (removed in arcaeon 1.0.0)",
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
    """`import arcaeon_ledger.x` returns the new module itself, not a copy."""

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

    def get_code(self, name):          # `python -m arcaeon_ledger.x` (runpy)
        new = _SUBMODULES[name]
        return _util.find_spec(new).loader.get_code(new)


if not any(type(f).__module__ == __name__ for f in _sys.meta_path):
    _sys.meta_path.insert(0, _Alias())


def _script_arcaeon_ledger(argv=None):
    """The old `arcaeon-ledger` console script. Its subcommands became verbs:
    verify -> `arcaeon verify`, append -> `arcaeon log`, reconcile ->
    `arcaeon reconcile --legacy-exit` (COULD NOT LOOK keeps its old exit 2)."""
    argv = list(_sys.argv[1:] if argv is None else argv)
    from arcaeon.cli import main
    sub, rest = (argv[0], argv[1:]) if argv else (None, [])
    if sub == "verify":
        return main(["verify", *rest])
    if sub == "append":
        return main(["log", *rest])
    if sub == "reconcile":
        return main(["reconcile", *rest, "--legacy-exit"])
    if sub == "--version":
        return main(["version"])
    print("arcaeon-ledger is now `arcaeon verify`, `arcaeon log` and `arcaeon reconcile`.")
    main(["--help"])
    return 0 if sub in ("-h", "--help") else 1   # the old tool: help 0, bad usage 1
