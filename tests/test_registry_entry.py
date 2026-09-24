"""registry/server.json is a valid MCP Registry record for this package.

- it validates against the registry's published schema (a pinned copy,
  registry/server.schema.2025-12-11.json, so the check runs offline);
- the server starts with the `mcp` verb: packageArguments resolve to ["mcp"];
- its versions equal the package version;
- the README carries the `mcp-name:` marker the registry looks for on PyPI;
- no key or token is in the file.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import arcaeon

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "registry"
SERVER_JSON = REGISTRY / "server.json"
SCHEMA_FILE = REGISTRY / "server.schema.2025-12-11.json"
RAW = SERVER_JSON.read_text(encoding="utf-8")
ENTRY = json.loads(RAW)
SCHEMA = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
PYPROJECT_TEXT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
# the floor is 3.10, which has no tomllib; the three fields read by pattern
PY_NAME = re.search(r'^name = "([^"]+)"', PYPROJECT_TEXT, re.M).group(1)
PY_VERSION = re.search(r'^version = "([^"]+)"', PYPROJECT_TEXT, re.M).group(1)
PY_MCP_EXTRA = re.search(r'^mcp = \["([^"]+)"\]', PYPROJECT_TEXT, re.M).group(1)
PKG = ENTRY["packages"][0]


def _structural_errors(entry: dict) -> list:
    """The schema's hard rules, checked by hand when jsonschema is not installed."""
    errs = []
    for key in SCHEMA["definitions"]["ServerDetail"]["required"]:
        if key not in entry:
            errs.append(f"missing {key}")
    if not re.fullmatch(r"[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+", entry.get("name", "")):
        errs.append("name pattern")
    if not 1 <= len(entry.get("description", "")) <= 100:
        errs.append("description length")
    for pkg in entry.get("packages", []):
        for key in ("registryType", "identifier", "transport"):
            if key not in pkg:
                errs.append(f"package missing {key}")
        for arg in pkg.get("packageArguments", []) + pkg.get("runtimeArguments", []):
            if arg.get("type") == "positional" and not ("value" in arg or "valueHint" in arg):
                errs.append("positional needs value or valueHint")
            if arg.get("type") == "named" and "name" not in arg:
                errs.append("named needs name")
    return errs


def test_validates_against_the_published_schema():
    try:
        import jsonschema
    except ImportError:
        assert _structural_errors(ENTRY) == []
        return
    errors = list(jsonschema.Draft7Validator(SCHEMA).iter_errors(ENTRY))
    assert errors == [], [e.message for e in errors]


def test_the_schema_check_can_fail():
    bad = json.loads(RAW)
    bad["description"] = "x" * 101
    try:
        import jsonschema
    except ImportError:
        assert _structural_errors(bad)
        return
    assert list(jsonschema.Draft7Validator(SCHEMA).iter_errors(bad))


def test_schema_pin_matches_the_file():
    assert ENTRY["$schema"] == SCHEMA["$id"]


def test_package_arguments_are_the_mcp_verb():
    args = PKG["packageArguments"]
    assert [a["value"] for a in args] == ["mcp"]
    assert all(a["type"] == "positional" for a in args)


def test_versions_equal_the_package_version():
    version = PY_VERSION
    assert version == arcaeon.__version__
    assert ENTRY["version"] == version
    assert PKG["version"] == version


def test_points_at_this_pypi_package():
    assert PKG["registryType"] == "pypi"
    assert PKG["registryBaseUrl"] == "https://pypi.org"
    assert PKG["identifier"] == PY_NAME == "arcaeon"
    assert PKG["transport"] == {"type": "stdio"}


def test_runtime_adds_the_mcp_sdk_the_extra_pins():
    # the base install has no dependencies, and `arcaeon mcp` exits 2 without
    # the SDK; the runtime argument must carry the same pin as the [mcp] extra
    extra = PY_MCP_EXTRA
    assert PKG["runtimeHint"] == "uvx"
    (arg,) = PKG["runtimeArguments"]
    assert (arg["type"], arg["name"]) == ("named", "--with")
    assert arg["value"].replace(" ", "") == extra.replace(" ", "")


def test_arcaeon_key_is_declared_optional_and_secret():
    (env,) = PKG["environmentVariables"]
    assert env["name"] == "ARCAEON_KEY"
    assert env["isRequired"] is False and env["isSecret"] is True
    assert "value" not in env and "default" not in env


def test_readme_carries_the_registry_ownership_marker():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert re.search(r"mcp-name: " + re.escape(ENTRY["name"]) + r"(\s|-->)", readme)


def test_repository_is_real_or_plainly_a_placeholder():
    url = ENTRY.get("repository", {}).get("url", "")
    if "github.com/" in url and "PLACEHOLDER" not in url:
        assert re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+", url)
    else:
        assert "PLACEHOLDER" in url


SECRET_SHAPES = [
    r"ghp_[A-Za-z0-9]{20,}", r"github_pat_\w{20,}", r"pypi-[A-Za-z0-9_-]{20,}",
    r"sk-[A-Za-z0-9]{20,}", r"-----BEGIN", r"eyJ[A-Za-z0-9_-]{10,}\.",
    r"\b[0-9a-fA-F]{32,}\b", r"[A-Za-z0-9+/]{40,}={0,2}", r"(?i)bearer\s",
    r"(?i)\"(token|password|secret|private_?key|api_?key)\"\s*:",
]


def test_no_key_or_token_in_the_file():
    for shape in SECRET_SHAPES:
        assert not re.search(shape, RAW), shape


def test_the_secret_check_can_fail():
    planted = RAW.replace('"format": "string"', '"format": "' + "ghp_" + "a" * 36 + '"')
    assert any(re.search(shape, planted) for shape in SECRET_SHAPES)
