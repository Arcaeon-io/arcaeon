# SPDX-License-Identifier: MIT
"""arcaeon_all: a marker. `pip install arcaeon-all` now installs `arcaeon[all]`.

The ten components it used to pin are one package now, `arcaeon`, with every
extra. The old names stay importable (`versions()`, `COMPONENTS`). This marker has
no removal date yet; it will be set from download counts (SUNSET_DATE).
"""
import warnings as _warnings

__version__ = "0.2.4"

#: the one package this marker now stands for
COMPONENTS = ("arcaeon",)

__all__ = ["__version__", "COMPONENTS", "versions"]

#: The removal date. None = not decided: it will be set from download counts,
#: and until then the warning says so instead of naming a release.
SUNSET_DATE = None
_WHEN = (f"removed on {SUNSET_DATE}" if SUNSET_DATE
         else "no removal date yet; it will be set from download counts")

_warnings.warn(f"arcaeon_all is deprecated: import arcaeon instead ({_WHEN})",
               DeprecationWarning, stacklevel=2)


def versions():
    """{"arcaeon": its version}. Imports only `arcaeon` itself, which imports nothing."""
    import arcaeon
    return {"arcaeon": arcaeon.__version__}
