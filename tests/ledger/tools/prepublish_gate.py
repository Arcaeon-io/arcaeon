# SPDX-License-Identifier: MIT
"""prepublish_gate.py: the portable pre-publish dist-integrity gate.

Vendored 2026-09-05 as the subset of the private monorepo's private prepublish_gate.py that
does not depend on anything outside this repo. The private original grew claim
layers, changelog-status greps and a CI-run lookup that need private-monorepo
modules; none of that is portable and none of it is here. What IS here is the
part that caught the 8/15 near-miss: a wheel sitting in dist/ with the right
version string on the tin and the wrong bytes inside.

Six checks, each printing exactly one of three verdicts:

  PASS          the check ran and the repo is right on this point.
  FAIL          the check ran and found something wrong.
  UNVERIFIABLE  the check could not run (no git, no __version__, no dist/).
                This is a third state, never a pass: "cannot tell" and
                "checked and fine" must not print the same word.

  (f) provenance          the package is a git repository with at least one
                          commit. A directory with no history cannot answer
                          "what changed", which is the property this company
                          sells; absent repository is a FAIL, not merely
                          unverifiable (added 2026-09-06 after arcaeon-recall
                          turned out to have been published to PyPI from an
                          untracked folder).

  (a) version-agreement   pyproject [project] version == --version ==
                          <pkg>/__init__.py __version__, and CHANGELOG.md has
                          a heading for that version in its first 200 lines.
  (b) dist-membership     dist/ holds BOTH a wheel and an sdist named for this
                          exact version, and the newest files there are not
                          some other version's (the twine-upload-dist/* trap).
  (c) staleness           the wheel's mtime is not older than the HEAD commit
                          time. A wheel built before the last commit cannot
                          contain that commit, whatever its version says.
  (d) wheel-contents      the wheel zip carries <pkg>/__init__.py and its
                          METADATA Version: line equals --version.
  (e) tag-agreement       in CI (GITHUB_REF_NAME set and starting with "v")
                          the tag must be exactly v<version>.

Exit codes: 0 all PASS; 1 any FAIL; 2 no FAIL but at least one UNVERIFIABLE.
Stdlib only, Python 3.10+, runs on ubuntu-latest and Windows. Nothing here
reads a secret, and nothing here prints one.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

PASS, FAIL, UNVERIFIABLE = "PASS", "FAIL", "UNVERIFIABLE"

# A check returns (verdict, reason). Reasons are one line; the report prints them.
Verdict = tuple[str, str]


def _norm(name: str) -> str:
    """PEP 427 / PEP 503 filename normalization: hyphens, dots and runs of
    either become a single underscore, case folded."""
    return re.sub(r"[-_.]+", "_", name).lower()


def _pyproject(repo: Path) -> tuple[str | None, str | None]:
    """Return ([project].name, [project].version). tomllib is 3.11+; the regex
    fallback keeps 3.10 honest and only looks inside the [project] table."""
    text = (repo / "pyproject.toml").read_text(encoding="utf-8")
    try:
        import tomllib  # noqa: PLC0415  (3.11+)
        proj = tomllib.loads(text).get("project", {})
        return proj.get("name"), proj.get("version")
    except ModuleNotFoundError:
        m = re.search(r"^\[project\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
        block = m.group(1) if m else ""
        name = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
        ver = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
        return (name.group(1) if name else None), (ver.group(1) if ver else None)


def _project_name(repo: Path) -> str | None:
    return _pyproject(repo)[0] if (repo / "pyproject.toml").exists() else None


def _package_dir(repo: Path, project_name: str | None) -> Path | None:
    """The import package is the normalized project name (arcaeon-ledger ->
    arcaeon_ledger). No guessing beyond that: a wrong guess would PASS the
    wrong file."""
    if not project_name:
        return None
    cand = repo / _norm(project_name)
    return cand if (cand / "__init__.py").exists() else None


def _init_version(pkg: Path | None) -> str | None:
    if pkg is None:
        return None
    m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', (pkg / "__init__.py").read_text(encoding="utf-8"), re.M)
    return m.group(1) if m else None


def _changelog_has(repo: Path, version: str) -> bool | None:
    p = repo / "CHANGELOG.md"
    if not p.exists():
        return None
    head = p.read_text(encoding="utf-8", errors="replace").splitlines()[:200]
    v = re.escape(version)
    pat = re.compile(rf"^#{{1,6}}\s*(\[?v?{v}\]?)(\s|$|[:—–-])")
    return any(pat.match(line) for line in head)


def check_version_agreement(repo: Path, version: str) -> Verdict:
    """(a) three sources plus the changelog heading, all naming --version."""
    if not (repo / "pyproject.toml").exists():
        return UNVERIFIABLE, "no pyproject.toml in repo"
    name, pp_v = _pyproject(repo)
    pkg = _package_dir(repo, name)
    init_v = _init_version(pkg)
    cl = _changelog_has(repo, version)
    problems, unverifiable = [], []
    if pp_v != version:
        problems.append(f"pyproject.toml says {pp_v!r}")
    if pkg is None:
        unverifiable.append(f"package dir for {name!r} not found, __version__ unread")
    elif init_v is None:
        unverifiable.append(f"{pkg.name}/__init__.py has no __version__ attribute")
    elif init_v != version:
        problems.append(f"{pkg.name}/__init__.py __version__ is {init_v!r}")
    if cl is None:
        unverifiable.append("no CHANGELOG.md")
    elif cl is False:
        problems.append(f"CHANGELOG.md has no heading for {version} in its first 200 lines")
    if problems:
        return FAIL, "; ".join(problems + unverifiable)
    if unverifiable:
        return UNVERIFIABLE, "; ".join(unverifiable)
    return PASS, f"pyproject, {pkg.name}/__init__.py and CHANGELOG.md all say {version}"


def _artifacts(dist: Path, name: str, version: str) -> tuple[list[Path], list[Path], list[Path]]:
    """(wheels for this version, sdists for this version, every file in dist/)."""
    files = sorted((p for p in dist.iterdir() if p.is_file()), key=lambda p: p.stat().st_mtime)
    stem = f"{_norm(name)}-{version}"
    wheels = [p for p in files if p.suffix == ".whl" and p.name.startswith(stem + "-")]
    sdists = [p for p in files if p.name == f"{stem}.tar.gz"]
    return wheels, sdists, files


def check_dist_membership(repo: Path, version: str, dist: Path) -> Verdict:
    """(b) both artifacts for this version present; nothing newer from another."""
    if not dist.is_dir():
        return UNVERIFIABLE, f"no dist/ directory at {dist}"
    name = _project_name(repo)
    if not name:
        return UNVERIFIABLE, "cannot read [project] name from pyproject.toml"
    wheels, sdists, files = _artifacts(dist, name, version)
    if not files:
        return FAIL, "dist/ is empty; nothing to publish"
    problems = []
    if not wheels:
        problems.append(f"no wheel {_norm(name)}-{version}-*.whl")
    if not sdists:
        problems.append(f"no sdist {_norm(name)}-{version}.tar.gz")
    newest = files[-2:] if len(files) >= 2 else files
    foreign = [p.name for p in newest if p not in wheels and p not in sdists]
    if foreign:
        problems.append("newest file(s) in dist/ belong to another version: " + ", ".join(foreign))
    strays = [p.name for p in files if p not in wheels and p not in sdists]
    if problems:
        return FAIL, "; ".join(problems)
    note = f" (other files also present, twine upload dist/* would ship them: {', '.join(strays)})" if strays else ""
    return PASS, f"{wheels[-1].name} + {sdists[-1].name}{note}"


def _head_commit_time(repo: Path) -> int | None:
    try:
        out = subprocess.run(["git", "log", "-1", "--format=%ct"], cwd=str(repo),
                             capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0 or not out.stdout.strip().isdigit():
        return None
    return int(out.stdout.strip())


def check_staleness(repo: Path, version: str, dist: Path) -> Verdict:
    """(c) wheel mtime >= HEAD commit time, else the wheel predates HEAD."""
    name = _project_name(repo)
    wheels = _artifacts(dist, name, version)[0] if (name and dist.is_dir()) else []
    if not wheels:
        return UNVERIFIABLE, f"no wheel for {version} in dist/ to date"
    head = _head_commit_time(repo)
    if head is None:
        return UNVERIFIABLE, "git unavailable or not a git repo; HEAD commit time unread"
    wheel = wheels[-1]
    mtime = int(wheel.stat().st_mtime)
    if mtime < head:
        return FAIL, f"wheel predates HEAD: {wheel.name} mtime {mtime} < HEAD commit {head} ({head - mtime}s older)"
    return PASS, f"{wheel.name} built {mtime - head}s after HEAD commit"


def check_wheel_contents(repo: Path, version: str, dist: Path) -> Verdict:
    """(d) the wheel carries <pkg>/__init__.py and METADATA Version: == --version."""
    name = _project_name(repo)
    wheels = _artifacts(dist, name, version)[0] if (name and dist.is_dir()) else []
    if not wheels:
        return UNVERIFIABLE, f"no wheel for {version} in dist/ to open"
    wheel = wheels[-1]
    try:
        with zipfile.ZipFile(wheel) as z:
            names = z.namelist()
            meta = [n for n in names if n.endswith(".dist-info/METADATA")]
            metadata = z.read(meta[0]).decode("utf-8", errors="replace") if meta else ""
    except zipfile.BadZipFile as e:
        return FAIL, f"{wheel.name} is not a valid zip: {e}"
    problems = []
    init = f"{_norm(name)}/__init__.py"
    if init not in names:
        problems.append(f"{init} missing from wheel")
    m = re.search(r"^Version:\s*(\S+)", metadata, re.M)
    if not meta:
        problems.append("no .dist-info/METADATA in wheel")
    elif not m or m.group(1) != version:
        problems.append(f"METADATA Version: is {m.group(1) if m else None!r}")
    if problems:
        return FAIL, "; ".join(problems)
    return PASS, f"{wheel.name} has {init} and METADATA Version: {version}"


def check_tag_agreement(version: str) -> Verdict:
    """(e) only meaningful under a tag-triggered CI run; otherwise say so."""
    ref = os.environ.get("GITHUB_REF_NAME", "")
    if not ref.startswith("v"):
        return PASS, "not a tag-triggered CI run (GITHUB_REF_NAME unset or not v*); nothing to compare"
    if ref != f"v{version}":
        return FAIL, f"tag {ref} != v{version}"
    return PASS, f"tag {ref} matches"


def check_provenance(repo: Path) -> Verdict:
    """The package must be able to answer, from its own record, what changed.

    Added 2026-09-06, from a genuinely embarrassing find. `arcaeon-recall` had
    been PUBLISHED TO PyPI from a directory that was not a git repository at
    all. No history, no diff, no answer to "what changed in 0.1.1" for anyone
    who asked -- shipped by the outfit whose entire product line is
    tamper-evident provenance. A sweep found a second one the same way, the
    GitHub Action, which is worse in kind because an Action is consumed by ref.

    Why this is a FAIL and not UNVERIFIABLE, which is the whole point of the
    check: the other git-dependent checks here degrade to UNVERIFIABLE because
    "git is not installed" genuinely means the tool could not look. "There is no
    repository" is a different fact. It is not that we could not check the
    history; it is that there IS no history, and the artifact cannot answer the
    question this company sells the answer to. That is a defect in the release,
    not a gap in the instrument.

    Missing git BINARY stays UNVERIFIABLE. Absent repository is FAIL.
    """
    try:
        out = subprocess.run(["git", "rev-parse", "--git-dir"], cwd=str(repo),
                             capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        return UNVERIFIABLE, "git binary unavailable; could not look for a repository"
    except Exception as e:  # noqa: BLE001 - a probe failure is data, not a crash
        return UNVERIFIABLE, f"git probe failed: {type(e).__name__}: {e}"
    if out.returncode != 0:
        return FAIL, ("no git repository: this package cannot answer what changed "
                      "or when, which is the property we sell. Run `git init`, "
                      "commit, and publish from a tracked tree.")
    try:
        log = subprocess.run(["git", "log", "-1", "--format=%H"], cwd=str(repo),
                             capture_output=True, text=True, timeout=10)
    except Exception as e:  # noqa: BLE001
        return UNVERIFIABLE, f"git log failed: {type(e).__name__}: {e}"
    if log.returncode != 0 or not log.stdout.strip():
        return FAIL, "git repository has no commits; nothing to publish from"
    return PASS, f"tracked, HEAD {log.stdout.strip()[:12]}"


def run_gate(repo: Path, version: str, dist: Path | None = None) -> dict:
    dist = dist or repo / "dist"
    checks = {
        "provenance": check_provenance(repo),
        "version-agreement": check_version_agreement(repo, version),
        "dist-membership": check_dist_membership(repo, version, dist),
        "staleness": check_staleness(repo, version, dist),
        "wheel-contents": check_wheel_contents(repo, version, dist),
        "tag-agreement": check_tag_agreement(version),
    }
    fails = sum(1 for v, _ in checks.values() if v == FAIL)
    unver = sum(1 for v, _ in checks.values() if v == UNVERIFIABLE)
    summary = "GATE PASS" if not fails and not unver else (f"GATE FAIL ({fails})" if fails else f"GATE UNVERIFIABLE ({unver})")
    return {"repo": str(repo), "version": version, "dist": str(dist),
            "checks": {k: {"verdict": v, "reason": r} for k, (v, r) in checks.items()},
            "summary": summary, "exit_code": 1 if fails else (2 if unver else 0)}


def format_report(result: dict) -> str:
    lines = [f"prepublish_gate {result['repo']} @ {result['version']}"]
    for name, c in result["checks"].items():
        lines.append(f"[{c['verdict']}] {name}: {c['reason']}")
    lines.append(result["summary"])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Portable pre-publish dist-integrity gate.")
    ap.add_argument("--repo", required=True, help="path to the package repo (pyproject.toml, dist/)")
    ap.add_argument("--version", required=True, help="version being published, e.g. 0.7.5 (no leading v)")
    ap.add_argument("--dist", default=None, help="artifact directory (default: <repo>/dist)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of the text report")
    args = ap.parse_args(argv)
    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        print(f"prepublish_gate: repo path does not exist: {repo}", file=sys.stderr)
        return 2
    result = run_gate(repo, args.version.lstrip("v"), Path(args.dist).resolve() if args.dist else None)
    print(json.dumps(result, indent=2) if args.json else format_report(result))
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
