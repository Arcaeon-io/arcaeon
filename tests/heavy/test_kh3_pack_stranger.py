"""KH3: the evidence pack, end to end, as a stranger.

BUILD SIDE (this checkout, PYTHONPATH=src): one ledger holding a matched deal
(docs/DEAL.md's d-demo1 steps, buyer tape) and one mandate-gated session, a
local pin over its head, a second-read comparison receipt with its ledger, and
`arcaeon evidence-pack` over a --from/--to window with --deal, --mandate,
--readings, --format aat, --zip and a fixed --built-at. Built twice into two
folders: the two zips are byte-identical (the deterministic zip).

The wheel is built from a COPY of the source tree (pyproject, README, LICENSE,
MANIFEST.in, src/) in a temp dir, so the checkout gets no build/ or egg-info:
`py -m build --wheel --no-isolation` when `build` is importable, else
`py -m pip wheel <copy> --no-deps --no-build-isolation`. No index, no network.

STRANGER SIDE: a fresh `py -m venv` in a temp dir, ONLY that wheel installed
(`pip install --no-index --find-links <dir> arcaeon`), and every check run
through the venv's own `arcaeon` executable with an environment built from
nothing (no PYTHONPATH, HOME and ARCAEON_HOME in temp, cwd outside the repo).
The stranger holds the zip and the pin file, nothing else.

  - `evidence-pack verify PACK.zip --witness PINS`: VERIFIED, exit 0.
  - four tamper cases on the zip, each exit 1 or 3, never 0:
      one changed byte in a record (records.jsonl),
      a stripped pin (manifest pins emptied, manifest.sha256 recomputed),
      a rewritten manifest (a count changed, manifest.sha256 recomputed),
      a forged subfolder (an entry `extra/notes.json` added to the zip).
  - the venv holds arcaeon and pip's own packages and nothing else, and the
    installed arcaeon declares no unconditional dependency (zero-dependency).

Skips, with the reason, when a venv cannot be created or no wheel builder
(setuptools) is available offline. Marked slow.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from arcaeon.record.ledger import Ledger
from arcaeon.record.receipt.core import build_receipt, save_receipt

pytestmark = pytest.mark.slow

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
NS = "kh3-stranger"
WINDOW = ("2026-01-01T00:00:00Z", "2099-12-31T00:00:00Z")
MANDATE = {"who": "kh3-agent", "allowed_acts": ["echo"]}
#: pip's own packages a fresh venv may hold besides arcaeon (3.12+ has only pip)
PIP_OWN = {"pip", "setuptools", "wheel"}


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _run(cmd, *, env, cwd, timeout=300) -> subprocess.CompletedProcess:
    return subprocess.run([str(c) for c in cmd], env=env, cwd=str(cwd), capture_output=True,
                          text=True, encoding="utf-8", timeout=timeout)


# --- build side --------------------------------------------------------------

def _build_env(home: Path) -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    env["ARCAEON_HOME"] = str(home)
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "SOURCE_DATE_EPOCH"):
        env.pop(k, None)
    return env


def _deal_steps() -> list[list[str]]:
    """docs/DEAL.md's d-demo1 steps (the MATCHED deal), dispute and pack left out."""
    import re
    text = (ROOT / "docs" / "DEAL.md").read_text(encoding="utf-8")
    steps = []
    for block in re.findall(r"```console\n(.*?)```", text, flags=re.S):
        for line in block.splitlines():
            if not line.startswith("$ arcaeon deal "):
                continue
            argv = shlex.split(line[2:])[1:]
            if argv[1] in ("dispute", "pack") or "d-demo1" not in argv:
                continue
            steps.append(argv)
    return steps


def _append_gated_session(ledger: Path, mandate: Path) -> None:
    """One gated session, rows shaped as proxy.py writes them: two inside,
    one outside, one could-not-look."""
    sha = _sha(mandate.read_bytes())
    lg = Ledger(ledger)
    base = {"seam": "mcp_stdio", "session": "kh3-s1", "server": "echo"}
    lg.append({**base, "evt": "session_begin", "seq": 1})
    lg.append({**base, "evt": "mandate_loaded", "seq": 2, "mandate": str(mandate),
               "mandate_status": "loaded", "mandate_file_sha256": sha,
               "mandate_mode": "record-only"})
    lg.append({**base, "evt": "tool_call", "seq": 3, "tool": "echo"})
    lg.append({**base, "evt": "mandate_outside", "seq": 4, "verdict": "outside",
               "rule": "allowed_acts", "reason": "refund is not an allowed act",
               "tool": "refund", "mandate_file_sha256": sha, "action": "forwarded"})
    lg.append({**base, "evt": "mandate_could_not_look", "seq": 5,
               "verdict": "could_not_look", "rule": "frame", "reason": "unparsed",
               "looked_for": "a JSON-RPC request", "where": "client stdin",
               "reason_word": "unreadable", "action": "forwarded"})
    lg.append({**base, "evt": "session_end", "seq": 6, "reason": "eof",
               "mandate_inside": 2, "mandate_outside": 1, "mandate_could_not_look": 1})


def _receipt(work: Path) -> tuple[Path, Path]:
    led = work / "receipts.jsonl"
    rc = build_receipt(
        "second_read_compare",
        {"a": {"ledger": "reader-a.jsonl", "rows": 5, "chain": "a" * 32},
         "b": {"ledger": "reader-b.jsonl", "rows": 5, "chain": "b" * 32}},
        [{"name": "compare", "read": 5, "agreed": 3, "disagreed": 2,
          "not_yet_informative": True}],
        {"proves": ["the two ledgers' heads and the compare counts at issue"],
         "does_not_prove": ["that either reading is true"]},
        ledger_path=led, namespace="second-read", witness=False, anchor=False,
        issued_at="2026-09-27T12:00:00Z")
    return save_receipt(rc, work / "compare.receipt.json"), led


def _build_wheel(tmp: Path) -> tuple[Path, str]:
    """The wheel, from a copy of the source tree. Returns (wheel, how)."""
    copy = tmp / "srccopy"
    copy.mkdir()
    for name in ("pyproject.toml", "README.md", "LICENSE", "MANIFEST.in"):
        shutil.copy2(ROOT / name, copy / name)
    shutil.copytree(SRC, copy / "src",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info"))
    out = tmp / "wheelhouse"
    out.mkdir()
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["PIP_NO_INDEX"] = "1"
    try:
        import build  # noqa: F401
        cmd = [sys.executable, "-m", "build", "--wheel", "--no-isolation",
               "--outdir", out, copy]
        how = "py -m build --wheel --no-isolation"
    except ImportError:
        cmd = [sys.executable, "-m", "pip", "wheel", copy, "--no-deps",
               "--no-build-isolation", "--no-index", "-w", out]
        how = "py -m pip wheel --no-deps --no-build-isolation --no-index"
    try:
        import setuptools  # noqa: F401
    except ImportError:
        pytest.skip("no setuptools to build the wheel offline (--no-isolation needs it)")
    cp = _run(cmd, env=env, cwd=tmp)
    assert cp.returncode == 0, f"{how} failed:\n{cp.stdout[-2000:]}\n{cp.stderr[-2000:]}"
    wheels = sorted(out.glob("arcaeon-*.whl"))
    assert len(wheels) == 1, (wheels, cp.stdout[-1000:])
    return wheels[0], how


# --- stranger side -----------------------------------------------------------

def _venv_bin(venv: Path) -> Path:
    return venv / ("Scripts" if os.name == "nt" else "bin")


def _stranger_env(house: Path, venv: Path) -> dict:
    """An environment built from nothing: the house, the venv, the OS binaries."""
    home = house / "home"
    tmp = house / "tmp"
    for d in (home, tmp, house / "arcaeon-home"):
        d.mkdir(parents=True, exist_ok=True)
    env = {"HOME": str(home), "USERPROFILE": str(home), "APPDATA": str(home),
           "LOCALAPPDATA": str(home), "XDG_CONFIG_HOME": str(home), "XDG_DATA_HOME": str(home),
           "XDG_CACHE_HOME": str(home), "TEMP": str(tmp), "TMP": str(tmp), "TMPDIR": str(tmp),
           "ARCAEON_HOME": str(house / "arcaeon-home"), "PIP_NO_INDEX": "1",
           "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONIOENCODING": "utf-8",
           "PYTHONNOUSERSITE": "1"}
    if os.name == "nt":
        sysroot = os.environ.get("SYSTEMROOT", r"C:\Windows")
        env.update({"SYSTEMROOT": sysroot, "WINDIR": sysroot, "PATHEXT": ".COM;.EXE;.BAT;.CMD",
                    "PATH": os.pathsep.join([str(_venv_bin(venv)),
                                             os.path.join(sysroot, "System32"), sysroot])})
    else:
        env["PATH"] = os.pathsep.join([str(_venv_bin(venv)), "/usr/bin", "/bin"])
    return env


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("kh3")
    work = tmp / "work"
    work.mkdir()

    # the stranger's venv first: if it cannot be made, nothing else is worth building
    house = tmp / "house"
    house.mkdir()
    venv = house / "venv"
    cp = subprocess.run([sys.executable, "-m", "venv", str(venv)], capture_output=True,
                        text=True, timeout=300)
    py = _venv_bin(venv) / ("python.exe" if os.name == "nt" else "python")
    if cp.returncode != 0 or not py.exists():
        pytest.skip(f"cannot create a venv here: {(cp.stderr or cp.stdout).strip()[-300:]}")
    senv = _stranger_env(house, venv)
    probe = _run([py, "-m", "pip", "--version"], env=senv, cwd=house)
    if probe.returncode != 0:
        pytest.skip(f"the new venv has no working pip: {probe.stderr.strip()[-300:]}")

    # build side
    benv = _build_env(tmp / "build-home")
    (tmp / "build-home").mkdir()

    def arcaeon(*args):
        return _run([sys.executable, "-m", "arcaeon", *args], env=benv, cwd=work)

    for argv in _deal_steps():
        # the pack's --ledger is the buyer tape; the seller tape rides as --seller
        r = arcaeon(*argv)
        assert r.returncode == 0, (argv, r.stdout, r.stderr)
    ledger, seller = work / "buyer.jsonl", work / "seller.jsonl"
    mandate = work / "mandate.json"
    mandate.write_text(json.dumps(MANDATE), encoding="utf-8")
    _append_gated_session(ledger, mandate)
    pins = work / "pins.jsonl"
    r = arcaeon("pin", ledger, "--witness", pins, "--ns", NS)
    assert r.returncode == 0, r.stdout + r.stderr
    receipt, receipt_ledger = _receipt(work)
    built_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def pack(out: Path) -> dict:
        r = arcaeon("evidence-pack", "--ledger", ledger, "--out", out,
                    "--from", WINDOW[0], "--to", WINDOW[1],
                    "--witness", pins, "--namespace", NS,
                    "--system-id", "kh3-system", "--provider", "kh3-provider",
                    "--format", "aat", "--deal", "d-demo1", "--seller", seller,
                    "--mandate", mandate, "--readings", receipt,
                    "--readings-ledger", receipt_ledger,
                    "--zip", "--built-at", built_at, "--json")
        assert r.returncode == 0, r.stdout + r.stderr
        return json.loads(r.stdout)

    res1 = pack(work / "pack1")
    res2 = pack(work / "pack2")

    wheel, how = _build_wheel(tmp)
    # only that wheel, no index
    inst = _run([py, "-m", "pip", "install", "--no-index", "--no-cache-dir",
                 "--find-links", wheel.parent, "arcaeon"], env=senv, cwd=house)
    assert inst.returncode == 0, inst.stdout + inst.stderr

    # the stranger gets copies, in a folder of their own, away from the repo
    inbox = house / "inbox"
    inbox.mkdir()
    shutil.copy2(res1["zip"], inbox / "pack.zip")
    shutil.copy2(pins, inbox / "pins.jsonl")
    exe = _venv_bin(venv) / ("arcaeon.exe" if os.name == "nt" else "arcaeon")
    return {"tmp": tmp, "res1": res1, "res2": res2, "wheel": wheel, "how": how,
            "py": py, "exe": exe, "env": senv, "house": house, "inbox": inbox}


def _verify(world, zp: Path) -> tuple[subprocess.CompletedProcess, dict]:
    cp = _run([world["exe"], "evidence-pack", "verify", zp,
               "--witness", world["inbox"] / "pins.jsonl", "--json"],
              env=world["env"], cwd=world["house"])
    assert cp.stdout.strip(), f"no stdout; stderr: {cp.stderr}"
    return cp, json.loads(cp.stdout)


def _entries(zp: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(zp) as z:
        return {n: z.read(n) for n in z.namelist()}


def _rezip(entries: dict[str, bytes], zp: Path) -> Path:
    with zipfile.ZipFile(zp, "w", compression=zipfile.ZIP_STORED) as z:
        for n in sorted(entries):
            z.writestr(n, entries[n])
    return zp


def _reseal(entries: dict[str, bytes], manifest: dict) -> None:
    """Write the manifest back and recompute manifest.sha256, as a rewriter would."""
    mb = json.dumps(manifest, indent=2).encode("utf-8")
    entries["manifest.json"] = mb
    entries["manifest.sha256"] = f"{_sha(mb)}  manifest.json\n".encode("ascii")


# --- the checks --------------------------------------------------------------

def test_build_side_pack_has_every_section_and_zips_deterministically(world):
    r1, r2 = world["res1"], world["res2"]
    assert r1["verdict"] == "VERIFIED" and r1["exit"] == 0, r1
    assert Path(r1["zip"]).read_bytes() == Path(r2["zip"]).read_bytes()
    assert r1["zip_sha256"] == r2["zip_sha256"] == _sha(Path(r1["zip"]).read_bytes())
    names = set(_entries(Path(r1["zip"])))
    m = json.loads(_entries(Path(r1["zip"]))["manifest.json"])
    assert m["deal"]["id"] == "d-demo1" and m["deal"]["verdict"] == "MATCHED"
    assert m["mandate"] and m["readings"]["ok"] is True
    assert m["aat"]["file"] == "aat.jsonl" and m["aat"]["gaps_file"] == "aat_gaps.json"
    assert len(m["pins"]) == 1
    for n in ("records.jsonl", "window.jsonl", "manifest.json", "manifest.sha256",
              "aat.jsonl", "aat_gaps.json", "mandate_rows.json", "mandate_file.json",
              "readings_receipt.json", "readings_receipt.ledger.jsonl", "timeline.md"):
        assert n in names, (n, sorted(names))
    assert all("/" not in n for n in names)


def test_the_wheel_carries_every_file_under_src(world):
    """A packaging defect shows here first: a data file the checkout has and
    the wheel lacks (package-data / MANIFEST.in) would pass every in-repo test."""
    with zipfile.ZipFile(world["wheel"]) as z:
        names = set(z.namelist())
    missing = sorted(p.relative_to(SRC).as_posix() for p in (SRC / "arcaeon").rglob("*")
                     if p.is_file() and "__pycache__" not in p.parts
                     and p.suffix not in (".pyc", ".pyo")
                     and p.relative_to(SRC).as_posix() not in names)
    assert not missing, missing
    assert not any(n.startswith(("tests/", "tools/")) for n in names)


def test_the_venv_runs_the_wheel_not_the_checkout(world):
    cp = _run([world["py"], "-c", "import arcaeon, sys; print(arcaeon.__file__)"],
              env=world["env"], cwd=world["house"])
    assert cp.returncode == 0, cp.stderr
    where = Path(cp.stdout.strip()).resolve()
    assert str(where).startswith(str(Path(world["house"]).resolve())), where
    assert "site-packages" in where.parts, where
    assert not str(where).startswith(str(SRC.resolve()))


def test_stranger_verifies_the_zip(world):
    cp, res = _verify(world, world["inbox"] / "pack.zip")
    assert cp.returncode == 0 and res["verdict"] == "VERIFIED" and res["exit"] == 0, res
    human = _run([world["exe"], "evidence-pack", "verify", world["inbox"] / "pack.zip",
                  "--witness", world["inbox"] / "pins.jsonl"],
                 env=world["env"], cwd=world["house"])
    assert human.returncode == 0 and human.stdout.startswith("VERIFIED: evidence pack ")


def _tampered(world, name: str, mutate) -> tuple[subprocess.CompletedProcess, dict]:
    entries = _entries(world["inbox"] / "pack.zip")
    mutate(entries)
    zp = _rezip(entries, world["inbox"] / f"tampered-{name}.zip")
    cp, res = _verify(world, zp)
    assert cp.returncode in (1, 3), (name, cp.returncode, res)
    assert res["exit"] == cp.returncode and res["verdict"] != "VERIFIED", res
    return cp, res


def test_one_changed_byte_in_a_record(world):
    def flip(e):
        b = bytearray(e["records.jsonl"])
        i = b.index(b"d-demo1")
        b[i + 6] = ord("2")          # d-demo1 -> d-demo2, one byte
        e["records.jsonl"] = bytes(b)
    cp, res = _tampered(world, "byte", flip)
    assert cp.returncode == 1 and "records.jsonl" in res["finding"]


def test_a_stripped_pin(world):
    def strip(e):
        m = json.loads(e["manifest.json"])
        assert m["pins"]
        m["pins"] = []
        _reseal(e, m)
    cp, res = _tampered(world, "pin", strip)
    assert cp.returncode == 1 and "witness block" in res["finding"], res


def test_a_rewritten_manifest_with_a_recomputed_sidecar(world):
    def rewrite(e):
        m = json.loads(e["manifest.json"])
        m["counts"]["could_not_look"] = m["counts"].get("could_not_look", 0) + 1
        m["mandate"]["outside"] = 0 if m["mandate"].get("outside") else 1
        _reseal(e, m)
    cp, res = _tampered(world, "manifest", rewrite)
    assert cp.returncode == 1 and "counts mismatch" in res["finding"], res


def test_a_forged_subfolder(world):
    def forge(e):
        e["extra/notes.json"] = b'{"note": "planted"}\n'
    cp, res = _tampered(world, "subfolder", forge)
    assert cp.returncode == 1 and "extra/notes.json" in json.dumps(res)


def test_zero_dependencies_in_the_fresh_venv(world):
    cp = _run([world["py"], "-c",
               "import importlib.metadata as m, json; print(json.dumps(sorted("
               "{(d.metadata['Name'] or '').lower(): d.requires or [] "
               "for d in m.distributions()}.items())))"],
              env=world["env"], cwd=world["house"])
    assert cp.returncode == 0, cp.stderr
    dists = dict(json.loads(cp.stdout))
    assert "arcaeon" in dists
    assert set(dists) - {"arcaeon"} <= PIP_OWN, sorted(dists)
    # every Requires-Dist arcaeon declares sits behind an extra
    assert all("extra ==" in r for r in dists["arcaeon"]), dists["arcaeon"]
    pl = _run([world["py"], "-m", "pip", "list", "--format=json"],
              env=world["env"], cwd=world["house"])
    assert pl.returncode == 0, pl.stderr
    listed = {d["name"].lower() for d in json.loads(pl.stdout)}
    assert "arcaeon" in listed and listed - {"arcaeon"} <= PIP_OWN, sorted(listed)
