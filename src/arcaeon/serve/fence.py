# SPDX-License-Identifier: MIT
"""Path fence for `arcaeon serve` (K006).

The server answers for one directory, the served root (`--root DIR`, default
the directory serve started in). Every path a request names, inputs and
output directories alike, is resolved against that root, symlinks followed,
and refused with 400 `outside the served root` if it lands anywhere else:
`../x`, an absolute path elsewhere, a drive-relative or UNC path, a symlink
or junction inside the root that points out of it.

A relative path means relative to the root, not to the server's working
directory. A path that passes is handed to the handler as the resolved
absolute path, so the handler reads exactly what the fence checked.

The refusal names the field, never the path it resolved to.
"""
from __future__ import annotations

import os
from pathlib import Path

OUTSIDE = "outside the served root"

#: Request fields that name a file or directory. `ns`, `agent`, `reader_id`
#: and the like are names, not paths, and are not fenced.
PATH_FIELDS = ("ledger", "witness", "tape_a", "tape_b", "pin", "path", "out",
               "receipt", "pack", "mandate", "a", "b")


class OutsideRoot(ValueError):
    """A request path resolved outside the served root."""

    def __init__(self, field: str):
        super().__init__(f"`{field}` is {OUTSIDE}")
        self.field = field


def _key(p: Path) -> str:
    return os.path.normcase(str(p))


class Fence:
    def __init__(self, root: str | os.PathLike):
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise NotADirectoryError(str(root))
        self._root_key = _key(self.root)

    def inside(self, p: Path) -> bool:
        k = _key(p)
        return k == self._root_key or k.startswith(self._root_key.rstrip(os.sep) + os.sep)

    def resolve(self, value: str, field: str = "path") -> str:
        """The resolved absolute path for `value`, or OutsideRoot."""
        if "\0" in value:                  # no OS takes it; some resolve() keep it
            raise OutsideRoot(field)
        try:
            p = Path(value)
            if not p.is_absolute():
                p = self.root / p          # "\\x" and "C:x" pick up the root's drive or not
            real = p.resolve(strict=False)
        except (OSError, ValueError, RuntimeError):   # a NUL byte, a symlink loop
            raise OutsideRoot(field) from None
        if not self.inside(real):
            raise OutsideRoot(field)
        return str(real)

    def apply(self, body):
        """A copy of the request body with every path field fenced and resolved."""
        if not isinstance(body, dict):
            return body
        out = dict(body)
        for f in PATH_FIELDS:
            v = out.get(f)
            if isinstance(v, str) and v:
                out[f] = self.resolve(v, f)
        return out
