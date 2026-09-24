"""The sdist must not ship test caches, and must ship the package.

RE-TARGETED IN THE ARCAEON MERGE (2026-09-23). This file used to build the
arcaeon-baseline sdist from that repo's root. That distribution is retired
(it becomes a shim that depends on `arcaeon`), so the three checks below now
build the ONE sdist that ships baseline's code, `arcaeon` itself, from this
repo's root. The three checks are unchanged in kind:

colonist-one verified publicly (2026-08-29) that arcaeon-baseline 0.1.4/0.1.6
shipped a 330-file .hypothesis cache - 93% of the download - because the
MANIFEST.in was inert under hatchling and no sdist allowlist existed. This is
the fail-closed gate so it cannot come back silently: build the sdist, assert
no cache dirs and a bounded member count.

2026-08-30 (colonist-one, follow-up): a denylist TEST only catches caches whose
name someone already thought of. `test_top_level_allowlist_is_exhaustive`
asserts every top-level entry in the sdist is on an explicit ALLOWED list, so a
workspace directory nobody has named yet fails the same way .hypothesis did.
And an allowlist that under-includes is the same defect as one that
over-includes, failing quiet: the 0.1.7 build silently dropped probes/, which
`test_ships_documented_probe_sets` pins. In the merged package the two starter
sets ship as package data (arcaeon/prove/baseline/probes/), so a wheel install
gets them too, which the old wheel never did.
"""
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]      # the arcaeon repo root
BANNED = (".hypothesis/", ".pytest_cache/", "__pycache__/", ".git/", "dist/", ".venv/",
          "/tests/")
MAX_MEMBERS = 250  # the whole merged package is ~140 members; a cache blows past this

# Top-level entries one level below the "arcaeon-X.Y.Z/" prefix.
ALLOWED_TOP_LEVEL_DIRS = {"src"}
ALLOWED_TOP_LEVEL_FILES = {
    "README.md", "LICENSE", "pyproject.toml",
    "PKG-INFO",       # generated metadata, always present
    "setup.cfg",      # setuptools writes its egg_info tag block here
    "MANIFEST.in",    # keeps tests/, tools/ and conftest.py out of the sdist
}


def _file_allowed(name: str) -> bool:
    return name in ALLOWED_TOP_LEVEL_FILES


def _build_sdist(dest: Path) -> Path:
    subprocess.run([sys.executable, "-m", "build", "--sdist", "--outdir", str(dest)],
                   cwd=ROOT, check=True, capture_output=True)
    tars = list(dest.glob("*.tar.gz"))
    assert tars, "no sdist produced"
    return max(tars, key=lambda p: p.stat().st_mtime)


def _sdist_names(sdist: Path) -> list[str]:
    with tarfile.open(sdist) as tf:
        return tf.getnames()


def test_sdist_ships_no_caches_and_stays_small():
    """Named-regression check: the caches that actually bit (.hypothesis) stay
    banned by name, and the test tree never rides along."""
    with tempfile.TemporaryDirectory() as td:
        names = _sdist_names(_build_sdist(Path(td)))
        cache_hits = [n for n in names if any(b in n for b in BANNED)]
        assert not cache_hits, f"sdist ships banned cache paths: {cache_hits[:5]}"
        assert len(names) <= MAX_MEMBERS, (
            f"sdist has {len(names)} members (cap {MAX_MEMBERS}) - a cache likely leaked back in")
        assert any(n.endswith("src/arcaeon/prove/baseline/__init__.py") for n in names), \
            "sdist is missing the package itself"


def test_top_level_allowlist_is_exhaustive():
    """Class fix: every top-level path in the sdist must be an allowed dir or
    an allowed file."""
    with tempfile.TemporaryDirectory() as td:
        sdist = _build_sdist(Path(td))
        with tarfile.open(sdist) as tf:
            members = tf.getmembers()
        prefixes = {m.name.split("/", 1)[0] for m in members}
        assert len(prefixes) == 1, f"unexpected multiple top-level prefixes: {prefixes}"
        top_level = set()
        for m in members:
            rest = m.name.split("/", 1)[1] if "/" in m.name else ""
            if not rest:
                continue
            first = rest.split("/", 1)[0]
            top_level.add((first, m.isdir() or "/" in rest))
        unexpected = []
        for name, is_dir_entry in top_level:
            if is_dir_entry:
                if name not in ALLOWED_TOP_LEVEL_DIRS:
                    unexpected.append(name)
            elif not _file_allowed(name):
                unexpected.append(name)
        assert not unexpected, (
            f"sdist top level has entries not on the allowlist: {sorted(set(unexpected))} "
            f"(allowed dirs: {sorted(ALLOWED_TOP_LEVEL_DIRS)}, "
            f"allowed files: {sorted(ALLOWED_TOP_LEVEL_FILES)})")


def test_ships_documented_probe_sets():
    """baseline's README promises two starter sets. Assert both are present."""
    with tempfile.TemporaryDirectory() as td:
        names = _sdist_names(_build_sdist(Path(td)))
        for fname in ("arcaeon/prove/baseline/probes/reasoning.jsonl",
                      "arcaeon/prove/baseline/probes/calibration.jsonl"):
            assert any(n.endswith(fname) for n in names), (
                f"sdist is missing documented content: {fname}")
