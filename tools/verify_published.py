"""The post-publish verify gate: did the index serve the exact bytes we built?

    py tools/verify_published.py manifest dist/ --version 0.11.0 --out release-manifest.json
    py tools/verify_published.py fetch --manifest release-manifest.json \
        --index-url https://pypi.org/simple/ --dest downloaded/ [--attempts 10 --wait 30]
    py tools/verify_published.py compare --manifest release-manifest.json --download-dir downloaded/

`manifest` runs in the build job: it records the sha256 of every file in dist/
before anything is uploaded. `fetch` runs after the publish job, in a clean
venv: `pip download arcaeon==<version> --no-deps` from the index just published
to, once for the wheel and once for the sdist, retrying (bounded) while the
index catches up, then `compare`.

Verdicts and exit codes:
  VERIFIED        0  every recorded file came back, byte for byte, nothing else did
  BROKEN          1  a file came back with different bytes, or a file we did not build
  COULD NOT LOOK  2  a recorded file never came back from the index
Both non-zero codes fail the release run.

What it cannot prove: that the code is safe, or that the bytes on the index will
stay the same tomorrow. It checks one moment: the index served what this run built.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

NAME = "arcaeon"
DIST_SUFFIXES = (".whl", ".tar.gz")
EXIT = {"VERIFIED": 0, "BROKEN": 1, "COULD NOT LOOK": 2}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _dist_files(d: Path) -> list[Path]:
    return sorted(p for p in Path(d).iterdir() if p.is_file() and p.name.endswith(DIST_SUFFIXES))


def build_manifest(dist_dir: Path, version: str) -> dict:
    files = _dist_files(dist_dir)
    if not files:
        raise ValueError(f"no .whl or .tar.gz in {dist_dir}")
    return {"name": NAME, "version": version,
            "files": {p.name: sha256_file(p) for p in files}}


def compare(manifest: dict, download_dir: Path) -> tuple[str, list[str]]:
    want = manifest["files"]
    got = {p.name: sha256_file(p) for p in _dist_files(download_dir)} if Path(download_dir).is_dir() else {}
    problems, broken, missing = [], False, False
    for name, digest in sorted(want.items()):
        if name not in got:
            problems.append(f"MISSING {name}: the index did not serve it")
            missing = True
        elif got[name] != digest:
            problems.append(f"MISMATCH {name}: built {digest}, index served {got[name]}")
            broken = True
    for name in sorted(set(got) - set(want)):
        problems.append(f"EXTRA {name}: served by the index, not built by this run")
        broken = True
    if broken:
        return "BROKEN", problems
    if missing:
        return "COULD NOT LOOK", problems
    return "VERIFIED", problems


def _pip_cmds(manifest: dict, index_url: str, dest: Path, python: str) -> list[list[str]]:
    spec = f"{manifest['name']}=={manifest['version']}"
    base = [python, "-m", "pip", "download", "--no-deps", "--no-cache-dir",
            "--dest", str(dest), "--index-url", index_url]
    names = manifest["files"]
    cmds = []
    if any(n.endswith(".whl") for n in names):
        cmds.append(base + ["--only-binary=:all:", spec])
    if any(n.endswith(".tar.gz") for n in names):
        # --no-build-isolation: pip prepares the sdist's metadata with the
        # setuptools already in the venv, not one fetched from this index
        # (TestPyPI does not carry a trustworthy setuptools).
        cmds.append(base + ["--no-binary=:all:", "--no-build-isolation", spec])
    return cmds


def fetch(manifest: dict, index_url: str, dest: Path, attempts: int = 10, wait: float = 30,
          runner=subprocess.run, sleep=time.sleep, python: str = sys.executable) -> tuple[str, list[str]]:
    dest = Path(dest)
    if dest.exists() and any(dest.iterdir()):
        raise ValueError(f"{dest} is not empty; the gate starts from an empty directory")
    dest.mkdir(parents=True, exist_ok=True)
    attempts = max(1, int(attempts))
    verdict, problems = "COULD NOT LOOK", ["MISSING: no attempt ran"]
    for i in range(attempts):
        for cmd in _pip_cmds(manifest, index_url, dest, python):
            r = runner(cmd, capture_output=True, text=True, timeout=600)
            if r.returncode != 0:
                tail = (r.stderr or "").strip().splitlines()[-1:] or [""]
                print(f"attempt {i + 1}/{attempts}: pip exit {r.returncode}: {tail[0]}", file=sys.stderr)
        verdict, problems = compare(manifest, dest)
        if verdict != "COULD NOT LOOK":
            return verdict, problems
        if i + 1 < attempts:
            sleep(wait)
    return verdict, problems


def _report(verdict: str, problems: list[str], manifest: dict) -> int:
    for p in problems:
        print(p)
    print(f"{verdict}: {manifest['name']} {manifest['version']}, {len(manifest['files'])} file(s) recorded")
    return EXIT[verdict]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("manifest", help="record sha256 of every file in a dist dir")
    m.add_argument("dist_dir")
    m.add_argument("--version", required=True)
    m.add_argument("--out", required=True)
    c = sub.add_parser("compare", help="compare a download dir against a manifest (offline)")
    c.add_argument("--manifest", required=True)
    c.add_argument("--download-dir", required=True)
    f = sub.add_parser("fetch", help="pip download from an index, then compare")
    f.add_argument("--manifest", required=True)
    f.add_argument("--index-url", required=True)
    f.add_argument("--dest", required=True)
    f.add_argument("--attempts", type=int, default=10)
    f.add_argument("--wait", type=float, default=30)
    a = ap.parse_args(argv)

    if a.cmd == "manifest":
        man = build_manifest(Path(a.dist_dir), a.version)
        Path(a.out).write_text(json.dumps(man, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        for name, digest in man["files"].items():
            print(f"{digest}  {name}")
        return 0
    man = json.loads(Path(a.manifest).read_text(encoding="utf-8"))
    if a.cmd == "compare":
        return _report(*compare(man, Path(a.download_dir)), man)
    return _report(*fetch(man, a.index_url, Path(a.dest), a.attempts, a.wait), man)


if __name__ == "__main__":
    sys.exit(main())
