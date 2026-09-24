"""The release runbook, as a script.

    py tools/publish.py                       # dry run (the default): steps 1-6, then print the upload plan
    py tools/publish.py --test-pypi           # dry run against the TestPyPI plan
    py tools/publish.py --upload --i-mean-it  # steps 1-6, then upload (PyPI)

Each step prints one line, a check mark or the failure, and the script stops
at the first failure (exit 1). A refused upload exits 2 before anything runs.

Steps:
  1. git tree clean and on main; tip hash printed
  2. versions agree: pyproject == arcaeon.__version__ == `arcaeon version --short`
     from a fresh build; every shims/*/pyproject.toml depends on arcaeon>=0.9,<1
  3. tests/test_no_private_paths.py and tests/test_docs.py green
  4. sdist + wheel into a clean dist/, each shim wheel into dist/shims/, twine check
  5. the main wheel in a fresh venv: selftest, version --short, the README's first
     run, VERIFIED then BROKEN exactly as the README states
  6. scan the artifacts for "velouria", "Users/USER", "/home/", ".env"
  7. upload order: main package, wait until PyPI serves it, the 13 shim wheels,
     then the next steps that are not this script's job

Credentials: read by NAME only (PYPI_TOKEN, or TESTPYPI_TOKEN with --test-pypi)
from the environment or the repo's .env, placed as TWINE_USERNAME=__token__ /
TWINE_PASSWORD in the twine subprocess's env only. The value is never printed,
never logged, never put on a command line.
"""
from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHIM_DEP = "arcaeon>=0.9,<1"
EXPECTED_SHIMS = 13
PYPI_URL = "https://upload.pypi.org/legacy/"
TESTPYPI_URL = "https://test.pypi.org/legacy/"
TESTPYPI_SIMPLE = "https://test.pypi.org/simple/"
POLL_SECONDS = 300
POLL_EVERY = 15
BS = chr(92)
# ".env" is matched as its own word: "os.environ" is not a dotenv file.
SCAN = [("velouria", re.compile(r"velouria", re.I)),
        ("Users/USER", re.compile(r"users[/" + re.escape(BS) + r"]user\b", re.I)),
        ("/home/", re.compile(r"/home/", re.I)),
        (".env", re.compile(r"\.env(?![a-z0-9_])", re.I))]

# Known, reviewed mentions that are not leaks: (member path suffix, label, phrase on the line).
# vet's secret check describes the shape it looks for; that comment is the product.
ALLOW = [("arcaeon/prove/vet/checks.py", ".env", ".env-shaped NAME=value line")]

OK, BAD = "✓", "✗"


class StepFailed(Exception):
    pass


# --- plumbing ---------------------------------------------------------------------

def _run(cmd, **kw):
    """Every subprocess goes through here (tests replace it to watch the upload)."""
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    kw.setdefault("encoding", "utf-8")
    kw.setdefault("errors", "replace")
    return subprocess.run([str(c) for c in cmd], **kw)


def _tail(p, n=6) -> str:
    lines = ((p.stdout or "") + (p.stderr or "")).strip().splitlines()
    return " | ".join(lines[-n:])


def _say(ok: bool, n: int, text: str) -> None:
    print(f"{OK if ok else BAD} {n}/7 {text}", flush=True)


def _venv_bin(venv: Path, name: str) -> Path:
    sub = "Scripts" if os.name == "nt" else "bin"
    exe = ".exe" if os.name == "nt" else ""
    return venv / sub / (name + exe)


def _clean_env() -> dict:
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    for k in ("PYTHONPATH", "ARCAEON_KEY", "TWINE_USERNAME", "TWINE_PASSWORD"):
        env.pop(k, None)
    return env


def _fresh_venv(wheel: Path, where: Path) -> Path:
    venv = where / "venv"
    p = _run([sys.executable, "-m", "venv", venv])
    if p.returncode:
        raise StepFailed(f"venv failed: {_tail(p)}")
    p = _run([_venv_bin(venv, "python"), "-m", "pip", "install", "--quiet",
              "--no-deps", "--no-index", wheel], env=_clean_env())
    if p.returncode:
        raise StepFailed(f"pip install {wheel.name} failed: {_tail(p)}")
    return venv


def _build_args() -> list:
    """--no-isolation when a new-enough setuptools is already here (offline, fast)."""
    try:
        import setuptools
        if int(setuptools.__version__.split(".")[0]) >= 77:
            return ["--no-isolation"]
    except Exception:
        pass
    return []


def _build(src: Path, outdir: Path, *kinds: str):
    return _run([sys.executable, "-m", "build", *kinds, *_build_args(),
                 "--outdir", outdir, src], env=_clean_env())


def _pyproject_version() -> str:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def _init_version() -> str:
    text = (ROOT / "src" / "arcaeon" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.M)
    return m.group(1) if m else ""


def _shim_dirs() -> list:
    return sorted(p.parent for p in (ROOT / "shims").glob("*/pyproject.toml"))


def git_state():
    """(branch, tip, porcelain) of the repo."""
    def g(*a):
        p = _run(["git", "-C", ROOT, *a])
        if p.returncode:
            raise StepFailed(f"git {' '.join(a)} failed: {_tail(p)}")
        return p.stdout.strip()
    return g("rev-parse", "--abbrev-ref", "HEAD"), g("rev-parse", "HEAD"), g("status", "--porcelain")


# --- credentials (by name only) ---------------------------------------------------

def _dotenv_value(path: Path, name: str):
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        line = line.strip()
        if line.startswith("export "):
            line = line[7:].strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() == name:
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            return v or None
    return None


def credential(name: str, env_file: Path):
    """The token's value, or None. Callers never print it."""
    return os.environ.get(name) or _dotenv_value(env_file, name)


# --- steps ------------------------------------------------------------------------

def step_git(ctx) -> str:
    branch, tip, porcelain = git_state()
    if porcelain:
        n = len(porcelain.splitlines())
        raise StepFailed(f"git: tree not clean ({n} changed path(s)); commit or stash first")
    if branch != ctx.branch:
        raise StepFailed(f"git: on '{branch}', not '{ctx.branch}'")
    ctx.tip = tip
    return f"git: clean, on {branch}, tip {tip}"


def step_versions(ctx) -> str:
    pv, iv = _pyproject_version(), _init_version()
    if pv != iv:
        raise StepFailed(f"versions: pyproject {pv} != arcaeon.__version__ {iv}")
    shims = _shim_dirs()
    if len(shims) != EXPECTED_SHIMS:
        raise StepFailed(f"versions: {len(shims)} shims found, expected {EXPECTED_SHIMS}")
    for d in shims:
        deps = tomllib.loads((d / "pyproject.toml").read_text(encoding="utf-8"))["project"].get("dependencies", [])
        # extras are allowed (arcaeon-all pulls arcaeon[all]); the range is not negotiable
        if SHIM_DEP not in [re.sub(r"\[[^\]]*\]", "", x.replace(" ", "")) for x in deps]:
            raise StepFailed(f"versions: shims/{d.name} depends on {deps}, not {SHIM_DEP}")
    with tempfile.TemporaryDirectory(prefix="arcaeon-ver-") as t:
        t = Path(t)
        p = _build(ROOT, t / "w", "--wheel")
        if p.returncode:
            raise StepFailed(f"versions: fresh build failed: {_tail(p)}")
        wheel = next((t / "w").glob("arcaeon-*.whl"))
        venv = _fresh_venv(wheel, t)
        p = _run([_venv_bin(venv, "arcaeon"), "version", "--short"], cwd=t, env=_clean_env())
        cv = p.stdout.strip()
        if p.returncode or cv != pv:
            raise StepFailed(f"versions: `arcaeon version --short` from a fresh build said {cv!r}, pyproject {pv}")
    ctx.version = pv
    return f"versions: {pv} in pyproject, __init__ and the built CLI; {len(shims)} shims pin {SHIM_DEP}"


def step_tests(ctx) -> str:
    p = _run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
              "tests/test_no_private_paths.py", "tests/test_docs.py"], cwd=ROOT, env=_clean_env())
    last = (p.stdout or "").strip().splitlines()[-1:] or ["(no output)"]
    if p.returncode:
        raise StepFailed(f"tests: {_tail(p)}")
    return f"tests: test_no_private_paths + test_docs {last[0].strip('= ')}"


def step_build(ctx) -> str:
    dist = ctx.dist
    if dist.name != "dist":
        raise StepFailed(f"build: refusing to clean {dist} (the folder must be named dist)")
    if dist.exists():
        shutil.rmtree(dist)
    p = _build(ROOT, dist, "--sdist", "--wheel")
    if p.returncode:
        raise StepFailed(f"build: arcaeon failed: {_tail(p)}")
    for d in _shim_dirs():
        p = _build(d, dist / "shims", "--wheel")
        if p.returncode:
            raise StepFailed(f"build: shims/{d.name} failed: {_tail(p)}")
    main = sorted(dist.glob(f"arcaeon-{ctx.version}*"))
    shims = sorted((dist / "shims").glob("*.whl"))
    if sorted(x.suffix for x in main) != [".gz", ".whl"]:
        raise StepFailed(f"build: expected an sdist and a wheel for {ctx.version}, got {[x.name for x in main]}")
    if len(shims) != EXPECTED_SHIMS:
        raise StepFailed(f"build: {len(shims)} shim wheels, expected {EXPECTED_SHIMS}")
    # not --strict: the shims have no README on purpose, and twine warns about that
    p = _run([sys.executable, "-m", "twine", "check", *main, *shims])
    passed = (p.stdout or "").count("PASSED")
    warned = (p.stdout or "").count("PASSED with warnings")
    if p.returncode or passed != len(main) + len(shims):
        raise StepFailed(f"build: twine check: {_tail(p)}")
    ctx.main_artifacts, ctx.shim_wheels = main, shims
    return (f"build: {main[0].name} + {main[1].name} + {len(shims)} shim wheels, "
            f"twine check PASSED x{passed} ({warned} with the no-README warning)")


def _readme_first_run():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    m = re.search(r"^## A 60-second first run\s*$(.*?)(?=^## |\Z)", readme, re.M | re.S)
    if not m:
        raise StepFailed("first run: README has no '## A 60-second first run' section")
    block = re.search(r"```console\n(.*?)```", m.group(1), re.S)
    steps = []
    for line in block.group(1).splitlines():
        if line.startswith("$ "):
            steps.append({"cmd": line[2:], "expect": [], "exit": 0})
        elif steps:
            e = re.fullmatch(r"\(exit (\d+)\)", line.strip())
            if e:
                steps[-1]["exit"] = int(e.group(1))
            elif line.strip() in ("", "...") or re.fullmatch(r"<[^>]*>", line.strip()):
                continue
            else:
                steps[-1]["expect"].append(line.strip())
    return steps


def step_venv(ctx) -> str:
    wheel = next(x for x in ctx.main_artifacts if x.suffix == ".whl")
    with tempfile.TemporaryDirectory(prefix="arcaeon-venv-") as t:
        t = Path(t)
        venv = _fresh_venv(wheel, t)
        env, arc, py = _clean_env(), _venv_bin(venv, "arcaeon"), _venv_bin(venv, "python")
        p = _run([arc, "selftest"], cwd=t, env=env)
        if p.returncode or '"failed": []' not in p.stdout:
            raise StepFailed(f"venv: selftest: exit {p.returncode}: {_tail(p)}")
        p = _run([arc, "version", "--short"], cwd=t, env=env)
        if p.returncode or p.stdout.strip() != ctx.version:
            raise StepFailed(f"venv: version --short said {p.stdout.strip()!r}, want {ctx.version}")
        work = t / "first-run"
        work.mkdir()
        readme_steps, seen = _readme_first_run(), []
        for s in readme_steps:
            argv = shlex.split(s["cmd"])
            if argv[0] == "arcaeon":
                argv[0] = arc
            elif argv[0] == "python":
                argv[0] = py
            else:
                raise StepFailed(f"first run: step is not arcaeon or python: {s['cmd']}")
            p = _run(argv, cwd=work, env=env)
            if p.returncode != s["exit"]:
                raise StepFailed(f"first run: `{s['cmd']}` exit {p.returncode}, README says {s['exit']}")
            out = {x.strip() for x in p.stdout.splitlines()}
            for want in s["expect"]:
                if want not in out:
                    raise StepFailed(f"first run: `{s['cmd']}` did not print {want}")
            seen += re.findall(r'"verdict": "([A-Z ]+)"', p.stdout)
        readme_says = [re.search(r'"verdict": "([A-Z ]+)"', w).group(1)
                       for s in readme_steps for w in s["expect"] if '"verdict"' in w]
        if seen != ["VERIFIED", "BROKEN"] or readme_says != ["VERIFIED", "BROKEN"]:
            raise StepFailed(f"first run: verdicts {seen}, README says {readme_says}, want VERIFIED then BROKEN")
    return (f"venv: selftest failed=[], version --short {ctx.version}, README first run "
            f"({len(readme_steps)} commands) VERIFIED then BROKEN")


def _members(path: Path):
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as z:
            for i in z.infolist():
                if not i.is_dir():
                    yield i.filename, z.read(i)
    else:
        with tarfile.open(path, "r:gz") as tf:
            for m in tf.getmembers():
                if m.isfile():
                    yield m.name, tf.extractfile(m).read()


def step_scan(ctx) -> str:
    arts = [*ctx.main_artifacts, *ctx.shim_wheels]
    hits, allowed, files = [], [], 0
    for a in arts:
        for name, data in _members(a):
            files += 1
            for label, rx in SCAN:
                if rx.search(name):
                    hits.append(f"{a.name}:{name} (file name) has {label!r}")
            for line in data.decode("utf-8", errors="replace").splitlines():
                for label, rx in SCAN:
                    if not rx.search(line):
                        continue
                    if any(name.endswith(f) and label == lb and ph in line for f, lb, ph in ALLOW):
                        allowed.append(f"{a.name}:{name}")
                    else:
                        hits.append(f"{a.name}:{name} has {label!r}")
    if hits:
        raise StepFailed("scan: " + "; ".join(hits[:8]) + (" ..." if len(hits) > 8 else ""))
    note = f" ({len(allowed)} allowlisted: vet/checks.py's '.env-shaped' comment)" if allowed else ""
    return (f"scan: {len(arts)} artifacts, {files} files, none has velouria / Users/USER / "
            f"/home/ / .env{note}")


def _twine_env(token: str) -> dict:
    env = _clean_env()
    env["TWINE_USERNAME"] = "__token__"
    env["TWINE_PASSWORD"] = token
    return env


def _pip_download(ctx, into: Path):
    cmd = [sys.executable, "-m", "pip", "download", f"arcaeon=={ctx.version}", "--no-deps",
           "--no-cache-dir", "--quiet", "-d", into]
    if ctx.test_pypi:
        cmd += ["--index-url", TESTPYPI_SIMPLE]
    return _run(cmd, env=_clean_env())


def _show(p: Path) -> str:
    try:
        return p.relative_to(ROOT).as_posix()
    except ValueError:
        return p.as_posix()


def next_steps(ctx) -> list:
    idx = f" --index-url {TESTPYPI_SIMPLE}" if ctx.test_pypi else ""
    return [
        "Not this script's job, in this order:",
        "  a. MCP registry entry for arcaeon " + ctx.version
        + ' (PyPI package, packageArguments ["mcp"]).',
        "  b. The site: products.yaml status -> shipped, then `py site.py build`, then the deploy.",
        "  c. Read-back from a fresh venv:",
        "       py -m venv /tmp/arcaeon-readback",
        f"       /tmp/arcaeon-readback/Scripts/python -m pip install{idx} arcaeon",
        "       /tmp/arcaeon-readback/Scripts/arcaeon version",
    ]


def step_upload(ctx) -> str:
    where = "TestPyPI" if ctx.test_pypi else "PyPI"
    url = TESTPYPI_URL if ctx.test_pypi else PYPI_URL
    main = [_show(x) for x in ctx.main_artifacts]
    pw = f'"${ctx.token_name}"'
    plan = [
        f"Order of upload to {where} ({url}):",
        f"  i.   TWINE_USERNAME=__token__ TWINE_PASSWORD={pw} py -m twine upload"
        f" --non-interactive --repository-url {url} " + " ".join(main),
        f"  ii.  wait until `pip download arcaeon=={ctx.version} --no-deps` succeeds from {where}"
        f" (every {POLL_EVERY}s, up to {POLL_SECONDS // 60} minutes)",
        f"  iii. TWINE_USERNAME=__token__ TWINE_PASSWORD={pw} py -m twine upload"
        f" --non-interactive --repository-url {url} {_show(ctx.dist / 'shims')}/*.whl ({len(ctx.shim_wheels)} wheels)",
        *next_steps(ctx),
    ]
    if not ctx.upload:
        print(f"{OK} 7/7 plan (dry run, nothing uploaded; {ctx.token_name} "
              f"{'present' if ctx.token else 'NOT present'} by name):", flush=True)
        for line in plan:
            print("    " + line, flush=True)
        return ""
    env = _twine_env(ctx.token)
    base = [sys.executable, "-m", "twine", "upload", "--non-interactive", "--repository-url", url]
    p = _run([*base, *ctx.main_artifacts], env=env)
    if p.returncode:
        raise StepFailed(f"upload: arcaeon to {where} failed: {_tail(p)}")
    print(f"  uploaded arcaeon {ctx.version} to {where}; waiting for it to be served", flush=True)
    deadline = time.monotonic() + POLL_SECONDS
    with tempfile.TemporaryDirectory(prefix="arcaeon-dl-") as t:
        while True:
            if _pip_download(ctx, Path(t)).returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise StepFailed(f"upload: arcaeon=={ctx.version} not downloadable from {where} after "
                                 f"{POLL_SECONDS // 60} minutes; shims NOT uploaded")
            time.sleep(POLL_EVERY)
    print(f"  {where} serves arcaeon=={ctx.version}", flush=True)
    p = _run([*base, *ctx.shim_wheels], env=env)
    if p.returncode:
        raise StepFailed(f"upload: shims to {where} failed: {_tail(p)}")
    _say(True, 7, f"upload: arcaeon {ctx.version} then {len(ctx.shim_wheels)} shim wheels to {where}")
    for line in next_steps(ctx):
        print("    " + line, flush=True)
    return ""


STEPS = [step_git, step_versions, step_tests, step_build, step_venv, step_scan]


# --- main -------------------------------------------------------------------------

class Ctx:
    def __init__(self, a):
        self.branch = a.branch
        self.dist = Path(a.dist).resolve()
        self.upload = a.upload
        self.test_pypi = a.test_pypi
        self.token_name = "TESTPYPI_TOKEN" if a.test_pypi else "PYPI_TOKEN"
        self.token = credential(self.token_name, Path(a.env_file))
        self.tip = self.version = ""
        self.main_artifacts, self.shim_wheels = [], []


def parse(argv):
    ap = argparse.ArgumentParser(prog="publish.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("--upload", action="store_true", help="actually upload (needs --i-mean-it)")
    ap.add_argument("--i-mean-it", dest="i_mean_it", action="store_true")
    ap.add_argument("--test-pypi", dest="test_pypi", action="store_true",
                    help="TestPyPI instead of PyPI; reads TESTPYPI_TOKEN")
    ap.add_argument("--branch", default="main", help="branch step 1 expects (dry run only)")
    ap.add_argument("--dist", default=str(ROOT / "dist"), help="output folder, must be named dist")
    ap.add_argument("--env-file", dest="env_file", default=str(ROOT / ".env"))
    return ap.parse_args(argv)


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    a = parse(argv)
    ctx = Ctx(a)
    mode = "UPLOAD" if a.upload else "dry run"
    print(f"arcaeon publish, {mode}, target {'TestPyPI' if a.test_pypi else 'PyPI'}", flush=True)
    if a.upload:
        if not a.i_mean_it:
            print("refused: --upload needs --i-mean-it as well. Nothing ran.", flush=True)
            return 2
        if a.branch != "main":
            print("refused: --upload only runs on main; --branch is for dry runs. Nothing ran.", flush=True)
            return 2
        if not ctx.token:
            print(f"refused: {ctx.token_name} is not set in the environment or {Path(a.env_file).name}. "
                  "Nothing ran.", flush=True)
            return 2
    for n, step in enumerate(STEPS, 1):
        try:
            _say(True, n, step(ctx))
        except StepFailed as e:
            _say(False, n, str(e))
            return 1
    try:
        step_upload(ctx)
    except StepFailed as e:
        _say(False, 7, str(e))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
