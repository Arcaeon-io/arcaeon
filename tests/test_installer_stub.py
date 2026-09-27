"""K118: the Windows installer stubs. Nothing here downloads, installs or builds.

tools/installer/arcaeon.iss is checked as text: marked a stub, not built, not
signed, per-user, no signing line. install.ps1 lives with the website (set
ARCAEON_SITE_ROOT to that checkout); it is parsed by PowerShell and run in its
default dry-run mode, which prints its steps and changes nothing."""
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ISS = (ROOT / "tools" / "installer" / "arcaeon.iss").read_text(encoding="utf-8")
POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")


def test_iss_is_a_stub_that_is_not_built_and_not_signed():
    head = ISS.split("[Setup]", 1)[0]
    for must in ("STUB", "NOT BUILT", "NOT SIGNED", "spend"):
        assert must in head, must
    assert not re.search(r"^\s*SignTool\s*=", ISS, re.M | re.I)
    assert not re.search(r"^\s*SignedUninstaller\s*=\s*yes", ISS, re.M | re.I)


def test_iss_installs_for_the_user_and_runs_doctor():
    assert re.search(r"^PrivilegesRequired=lowest$", ISS, re.M)
    assert '-m pip install --user ""arcaeon[mcp]""' in ISS
    assert '"-m arcaeon doctor"' in ISS


def test_iss_downloads_nothing_itself():
    body = ISS.split("[Setup]", 1)[1]
    assert "http://" not in body and "https://" not in body
    assert "DownloadTemporaryFile" not in body and "idp" not in body.lower()


def test_nothing_in_the_build_compiles_the_iss():
    hits = []
    for p in list((ROOT / "tools").rglob("*.py")) + [ROOT / "pyproject.toml"]:
        if "ISCC" in p.read_text(encoding="utf-8", errors="replace"):
            hits.append(str(p.relative_to(ROOT)))
    assert not hits, hits


@pytest.fixture
def install_ps1():
    root = os.environ.get("ARCAEON_SITE_ROOT")
    if not root:
        pytest.skip("ARCAEON_SITE_ROOT is not set (no site checkout to check install.ps1 in)")
    p = Path(root) / "install.ps1"
    if not p.is_file():
        pytest.skip("ARCAEON_SITE_ROOT has no install.ps1")
    return p


def _code_lines(text):
    return [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def test_install_ps1_is_powershell_51_shaped(install_ps1):
    code = "\n".join(_code_lines(install_ps1.read_text(encoding="utf-8")))
    assert "&&" not in code and "||" not in code
    assert not re.search(r"\?\?|\?\.", code), "null-coalescing is PowerShell 7 only"
    assert not re.search(r"\s\?\s[^:]+\s:\s", code), "ternary is PowerShell 7 only"
    assert "Get-Command py" in code
    assert "'--user'" in code and "'arcaeon[mcp]'" in code
    assert "'doctor'" in code


def test_install_ps1_acts_only_under_apply(install_ps1):
    lines = _code_lines(install_ps1.read_text(encoding="utf-8"))
    for i, ln in enumerate(lines):
        if ln.strip().startswith("& py"):
            assert "if ($Apply)" in "\n".join(lines[max(0, i - 2):i]), ln
    assert "Invoke-WebRequest" not in "\n".join(lines)
    assert "Invoke-Expression" not in "\n".join(lines)


def _ps(*args):
    return subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", *args],
                          capture_output=True, text=True, timeout=120)


@pytest.mark.skipif(POWERSHELL is None, reason="no PowerShell on this machine")
def test_install_ps1_parses(install_ps1):
    p = _ps("-Command",
            f"[void][scriptblock]::Create((Get-Content '{install_ps1}' -Raw)); 'parsed'")
    assert p.returncode == 0, p.stderr
    assert p.stdout.strip() == "parsed"


@pytest.mark.skipif(POWERSHELL is None, reason="no PowerShell on this machine")
def test_install_ps1_dry_run_prints_its_steps_and_changes_nothing(install_ps1):
    p = _ps("-ExecutionPolicy", "Bypass", "-File", str(install_ps1))
    out = p.stdout
    assert "dry run, nothing changes" in out
    if p.returncode == 2:           # no py launcher here: it says so and stops
        assert "py launcher was not found" in out
        return
    assert p.returncode == 0, (out, p.stderr)
    assert 'step 2: py -m pip install --user "arcaeon[mcp]"' in out
    assert "step 3: py -m arcaeon doctor" in out
    assert out.strip().splitlines()[-1] == ("dry run done: nothing was installed, "
                                            "nothing was downloaded.")
