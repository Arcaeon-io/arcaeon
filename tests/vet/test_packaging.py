"""Packaging tests (C-agent-23) — the distribution metadata is an artifact like
any other, so it gets asserted, not eyeballed. Written BEFORE pyproject.toml
existed; the first run failed on the missing file, which is the point."""
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

ROOT = Path(__file__).resolve().parent
PYPROJECT = ROOT / "pyproject.toml"
CHANGELOG = ROOT / "CHANGELOG.md"


def _cfg() -> dict:
    assert PYPROJECT.exists(), f"no pyproject.toml at {PYPROJECT}"
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def _changelog_latest(text: str | None = None) -> str:
    """Highest version heading in CHANGELOG.md. The changelog is the source of
    truth for the version number; pyproject and __init__ must agree with it.

    `text` is injectable so a test can plant a malformed changelog without
    touching the real file (default: read CHANGELOG.md)."""
    import re
    if text is None:
        text = CHANGELOG.read_text(encoding="utf-8")
    vers = re.findall(r"^## (\d+\.\d+\.\d+)", text, re.M)
    assert vers, "CHANGELOG has no '## X.Y.Z' headings"
    return max(vers, key=lambda v: tuple(int(p) for p in v.split(".")))


def test_pyproject_identity():
    p = _cfg()["project"]
    assert p["name"] == "arcaeon-mcp-vet", p["name"]
    assert p["requires-python"] == ">=3.10", p["requires-python"]


def test_version_matches_changelog_and_package():
    from arcaeon.prove.vet import __version__
    want = _changelog_latest()
    assert _cfg()["project"]["version"] == want, "pyproject version != CHANGELOG latest"
    assert __version__ == want, f"mcp_vet.__version__ ({__version__}) != CHANGELOG latest ({want})"


def test_license_is_mit():
    p = _cfg()["project"]
    lic = p.get("license")
    text = lic if isinstance(lic, str) else (lic or {}).get("text", "")
    assert "MIT" in text, f"license not MIT: {lic!r}"


def test_console_script_points_at_a_real_callable():
    scripts = _cfg()["project"].get("scripts", {})
    assert "mcp-vet" in scripts, scripts  # the CLI keeps its name; only the DISTRIBUTION was renamed (PyPI collision, 2026-08-30)
    mod, _, attr = scripts["mcp-vet"].partition(":")
    # arcaeon merge: this pyproject is the retired arcaeon-mcp-vet one (a legacy
    # fixture). Its script target now lives at the moved module; the W2 shim
    # keeps the `mcp-vet` script pointing there.
    mod = mod.replace("mcp_vet", "arcaeon.prove.vet", 1)
    import importlib
    fn = getattr(importlib.import_module(mod), attr)
    assert callable(fn), f"{scripts['mcp-vet']} is not callable"


def test_runtime_deps_are_minimal():
    """The scanner core is stdlib-only on purpose: a security checker that drags
    in a dependency tree is a supply-chain surface of its own. The MCP server
    lane lives in an extra."""
    p = _cfg()["project"]
    assert p.get("dependencies", []) == [], p.get("dependencies")
    extras = p.get("optional-dependencies", {})
    assert any("mcp" in d for d in extras.get("mcp", [])), extras


def test_signing_lives_in_an_extra_with_both_backends_declared():
    """Ed25519 is the one capability here the stdlib cannot supply, so it is an
    extra rather than a dependency — and BOTH accepted backends are declared,
    because `mcp_vet.receipts` will happily run on either and an undeclared
    fallback is a dependency nobody can audit."""
    extras = _cfg()["project"].get("optional-dependencies", {})
    assert any("cryptography" in d for d in extras.get("receipts", [])), extras
    assert any("pynacl" in d.lower()
               for d in extras.get("receipts-pynacl", [])), extras


def test_changelog_with_no_version_headings_is_rejected():
    """RED CONTROL (item 33, 2026-09-04): _changelog_latest() asserts `vers`
    is non-empty, but nothing ever fed it a changelog missing '## X.Y.Z'
    headings to prove that assert actually fires -- every other test only
    ever reads the real, well-formed CHANGELOG.md. Plants one and confirms
    the rejection names the reason."""
    import pytest
    bad = "# Changelog\n\nSome prose, no version headings at all.\n"
    with pytest.raises(AssertionError, match="no '## X.Y.Z' headings"):
        _changelog_latest(bad)


def test_package_is_declared_for_the_build_backend():
    """Flat layout + test modules at the repo root: without an explicit package
    list the backend either errors on ambiguity or ships the wrong thing."""
    cfg = _cfg()
    pkgs = cfg.get("tool", {}).get("setuptools", {}).get("packages", [])
    assert "mcp_vet" in pkgs, pkgs
