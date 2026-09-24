# SPDX-License-Identifier: MIT
"""arcaeon_all: a marker. `pip install arcaeon-all` now installs `arcaeon[all]`.

The ten components it used to pin are one package now, `arcaeon`, with every
extra. The old names stay importable (`versions()`, `COMPONENTS`). This marker
goes away with arcaeon 1.0.0.
"""
import warnings as _warnings

__version__ = "0.2.3"

#: the one package this marker now stands for
COMPONENTS = ("arcaeon",)

__all__ = ["__version__", "COMPONENTS", "versions"]

_warnings.warn("arcaeon_all is deprecated: import arcaeon instead (removed in arcaeon 1.0.0)",
               DeprecationWarning, stacklevel=2)


def versions():
    """{"arcaeon": its version}. Imports only `arcaeon` itself, which imports nothing."""
    import arcaeon
    return {"arcaeon": arcaeon.__version__}
