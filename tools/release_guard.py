"""The release version guard: refuse to build unless the versions agree.

    py tools/release_guard.py --ref-type tag --ref-name v0.11.0 --target pypi

Checks, all of which must hold:
  1. pyproject.toml [project] version == arcaeon.__version__ (read from src/)
  2. on a tag: the tag is exactly "v" + that version
  3. target "pypi" (the real index) only from a tag; "testpypi" may run from
     a branch (the dry run), where there is no tag to compare
On success prints the version alone on stdout and exits 0; otherwise prints
each refusal on stderr and exits 1. Reads files only; no network.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

TARGETS = ("pypi", "testpypi")


def read_pyproject_version(root: Path) -> str:
    text = (Path(root) / "pyproject.toml").read_text(encoding="utf-8")
    try:
        import tomllib
        return tomllib.loads(text)["project"]["version"]
    except ImportError:  # Python 3.10
        sect = text.split("[project]", 1)[1].split("\n[", 1)[0]
        return re.search(r'^version\s*=\s*"([^"]+)"', sect, re.M).group(1)


def read_package_version(root: Path) -> str:
    """arcaeon.__version__ from this checkout's src/, imported in a fresh
    interpreter so an installed arcaeon cannot answer instead."""
    src = str(Path(root) / "src")
    code = ("import os, sys; sys.path.insert(0, sys.argv[1]); import arcaeon; "
            "n = os.path.normcase; "
            "assert n(arcaeon.__file__).startswith(n(sys.argv[1])), arcaeon.__file__; "
            "print(arcaeon.__version__)")
    r = subprocess.run([sys.executable, "-c", code, src], capture_output=True, text=True,
                       timeout=120, check=True)
    return r.stdout.strip()


def check(pyproject: str, package: str, *, ref_type: str, ref_name: str, target: str) -> list[str]:
    errs = []
    if target not in TARGETS:
        errs.append(f"unknown target {target!r}; expected one of {TARGETS}")
    if pyproject != package:
        errs.append(f"pyproject.toml says {pyproject}, arcaeon.__version__ says {package}")
    if ref_type == "tag":
        if ref_name != f"v{pyproject}":
            errs.append(f"tag {ref_name!r} is not 'v{pyproject}'")
    elif target == "pypi":
        errs.append(f"real PyPI publishes only from a v* tag, this run is on {ref_type} {ref_name!r}")
    return errs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="refuse a release whose versions disagree")
    ap.add_argument("--ref-type", required=True, help="GITHUB_REF_TYPE: tag or branch")
    ap.add_argument("--ref-name", required=True, help="GITHUB_REF_NAME, e.g. v0.11.0")
    ap.add_argument("--target", required=True, help="pypi or testpypi")
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    a = ap.parse_args(argv)
    pyproject = read_pyproject_version(Path(a.root))
    package = read_package_version(Path(a.root))
    errs = check(pyproject, package, ref_type=a.ref_type, ref_name=a.ref_name, target=a.target)
    for e in errs:
        print(f"REFUSED: {e}", file=sys.stderr)
    if errs:
        return 1
    print(pyproject)
    return 0


if __name__ == "__main__":
    sys.exit(main())
