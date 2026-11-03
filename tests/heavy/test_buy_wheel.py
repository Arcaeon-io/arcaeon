"""`arcaeon buy` from the built wheel, in a clean venv, with and without network.

The rule under test: no price, no checkout link and no plan name is printed
unless the price list at arcaeon.io answered. When it did not answer (no
network, a refused connection, a connection that never answers, or
ARCAEON_OFFERS_OFFLINE=1) the whole output is one line. For bare `arcaeon
buy` that line is, with exit 0:

    Prices and how to buy: https://arcaeon.io/pricing

For `arcaeon buy <plan>` it is a COULD NOT LOOK line saying why, ending in
that same pricing sentence, with exit 3.

The wheel is built from this checkout (`pip wheel --no-deps
--no-build-isolation --no-index`, so the build itself needs no network) and
installed with `--no-index` into a new venv; `arcaeon buy` then runs as a
separate process from that venv, not from src/.

"No network" is a proxy on 127.0.0.1 that this test owns: the child is
pointed at it with HTTPS_PROXY, so every request it makes lands here and is
counted. That works the same on Windows, macOS and Linux and needs no
privileges. The case with network is marked `live` (skipped by default; run
with `-m live`): it reads the price list itself and checks that every price,
link and plan name `buy` printed is one the list marks live.

Marked slow: it builds a wheel and a venv.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

import pytest

pytestmark = pytest.mark.slow

ROOT = Path(__file__).resolve().parents[2]
PRICING = "Prices and how to buy: https://arcaeon.io/pricing"
CATALOG_URL = "https://arcaeon.io/.well-known/offers.json"
PLAN_WORDS = ("witnessed", "mini", "starter", "standard", "bulk", "grant", "stamp")
NO_OFFER = re.compile(r"\$|buy\.stripe\.com|checkout|credits?\b|pins? a month|/month", re.I)


def _run(cmd, **kw):
    cp = subprocess.run(cmd, capture_output=True, text=True, timeout=600, **kw)
    assert cp.returncode == 0, f"{cmd} failed:\n{cp.stdout[-2000:]}\n{cp.stderr[-2000:]}"
    return cp


@pytest.fixture(scope="module")
def arcaeon_exe(tmp_path_factory) -> Path:
    """The `arcaeon` script of a fresh venv holding the wheel built from this checkout."""
    base = tmp_path_factory.mktemp("buy-wheel")
    dist = base / "dist"
    _run([sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation",
          "--no-index", "-q", "-w", str(dist), str(ROOT)])
    wheels = list(dist.glob("arcaeon-*.whl"))
    assert len(wheels) == 1, wheels
    venv = base / "venv"
    clean = _env(base / "home")
    _run([sys.executable, "-m", "venv", str(venv)], env=clean)
    bindir = venv / ("Scripts" if os.name == "nt" else "bin")
    py = bindir / ("python.exe" if os.name == "nt" else "python")
    _run([str(py), "-m", "pip", "install", "-q", "--no-index", "--no-deps", str(wheels[0])],
         env=clean)
    exe = bindir / ("arcaeon.exe" if os.name == "nt" else "arcaeon")
    assert exe.exists(), exe
    # the venv runs the wheel, not this checkout
    where = _run([str(py), "-c", "import arcaeon, sys; sys.stdout.write(arcaeon.__file__)"],
                 cwd=str(base), env=clean).stdout
    assert str(venv) in where and str(ROOT / "src") not in where, where
    return exe


def _env(home: Path, proxy: str | None = None, offline: bool = False) -> dict:
    """A child environment with nothing of ours leaking in: no ARCAEON_*, no
    proxy, no PYTHONPATH (which would put src/ ahead of the wheel)."""
    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith(("ARCAEON_", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                                        "NO_PROXY", "PYTHON"))}
    home.mkdir(parents=True, exist_ok=True)
    env.update(HOME=str(home), USERPROFILE=str(home), ARCAEON_HOME=str(home),
               ARCAEON_JOURNAL="0", PYTHONIOENCODING="utf-8")
    if proxy:
        env["HTTPS_PROXY"] = env["https_proxy"] = proxy
    if offline:
        env["ARCAEON_OFFERS_OFFLINE"] = "1"
    return env


class Sink:
    """A loopback 'proxy' that counts connections and then either closes them
    at once (a refused or broken network) or holds them open saying nothing
    (a network that never answers)."""

    def __init__(self, hang: bool = False):
        self.hang, self.count, self.held = hang, 0, []
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(16)
        self.url = f"http://127.0.0.1:{self.srv.getsockname()[1]}"
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            self.count += 1
            if self.hang:
                self.held.append(conn)
            else:
                conn.close()

    def close(self):
        for c in self.held:
            c.close()
        self.srv.close()


def _buy(exe: Path, env: dict, *args) -> tuple[str, float]:
    t0 = time.monotonic()
    cp = subprocess.run([str(exe), "buy", *args], capture_output=True, text=True,
                        timeout=60, env=env, cwd=env["HOME"])
    took = time.monotonic() - t0
    # bare `buy` with no answer still answers (exit 0); `buy <plan>` could not look (exit 3)
    want = 3 if args else 0
    assert cp.returncode == want, (cp.returncode, cp.stdout, cp.stderr)
    return cp.stdout, took


def _assert_no_offer(out: str, plan: bool = False):
    if plan:
        assert out.startswith("COULD NOT LOOK: ") and out.endswith(f"; no plan link to give. "
                                                                   f"{PRICING}\n"), out
        assert out.count("\n") == 1, out
    else:
        assert out == PRICING + "\n", out
    assert not NO_OFFER.search(out.replace(PRICING, "")), out
    low = out.lower()
    assert not any(re.search(rf"\b{w}\b", low) for w in PLAN_WORDS), out


@pytest.mark.parametrize("args", [(), ("mini",), ("witnessed",)])
def test_no_network_prints_only_one_line(arcaeon_exe, tmp_path, args):
    sink = Sink()
    try:
        out, _ = _buy(arcaeon_exe, _env(tmp_path / "home", proxy=sink.url), *args)
    finally:
        sink.close()
    _assert_no_offer(out, plan=bool(args))
    if args:
        assert "did not answer" in out
    assert sink.count == 1, "buy should try the price list exactly once"


def test_a_network_that_never_answers_gives_up_after_three_seconds(arcaeon_exe, tmp_path):
    sink = Sink(hang=True)
    try:
        out, took = _buy(arcaeon_exe, _env(tmp_path / "home", proxy=sink.url))
    finally:
        sink.close()
    _assert_no_offer(out)
    assert sink.count == 1
    assert 2.5 <= took < 15, took


@pytest.mark.parametrize("args", [(), ("mini",)])
def test_the_opt_out_makes_no_request_at_all(arcaeon_exe, tmp_path, args):
    sink = Sink()
    try:
        out, _ = _buy(arcaeon_exe, _env(tmp_path / "home", proxy=sink.url, offline=True), *args)
    finally:
        sink.close()
    _assert_no_offer(out, plan=bool(args))
    if args:
        assert "ARCAEON_OFFERS_OFFLINE=1 is set" in out
    assert sink.count == 0


def test_a_failure_is_not_remembered(arcaeon_exe, tmp_path):
    home = tmp_path / "home"
    for _ in range(2):
        sink = Sink()
        try:
            out, _ = _buy(arcaeon_exe, _env(home, proxy=sink.url))
        finally:
            sink.close()
        _assert_no_offer(out)
        assert sink.count == 1, "a failed read must not be kept; the next run tries again"
    assert not (home / "offers-cache.json").exists()


def _live_tiers(cat) -> list[dict]:
    out = []
    for p in cat.get("products", []):
        for t in p.get("tiers") or []:
            if isinstance(t, dict) and t.get("status") == "live" and \
                    str(t.get("checkout", "")).startswith("https://buy.stripe.com/"):
                out.append(t)
    return out


@pytest.mark.live
def test_with_network_every_offer_printed_is_one_the_list_marks_live(arcaeon_exe, tmp_path):
    home = tmp_path / "home"
    env = _env(home)
    for k in ("HTTPS_PROXY", "https_proxy", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    out, _ = _buy(arcaeon_exe, env)
    try:
        with urllib.request.urlopen(CATALOG_URL, timeout=10) as r:
            cat = json.loads(r.read(1024 * 1024 + 1))
    except Exception:  # noqa: BLE001
        cat = None
    if cat is None or not (home / "offers-cache.json").exists():
        _assert_no_offer(out)  # the list did not answer buy: nothing offered
        return
    lines = out.splitlines()
    assert lines[-1] == PRICING
    live = {t["plan"]: t for t in _live_tiers(cat)}
    for line in lines[:-1]:
        if line.startswith("Free: "):
            assert re.fullmatch(r"Free: [\d,]+ pins a month on the hosted witness\.", line), line
            n = line.split()[1]
            assert n in json.dumps(cat), line
            continue
        plan, *_, link = line.split()
        assert plan in live, f"{plan!r} printed but not marked live: {line}"
        assert link == live[plan]["checkout"], line
        price = live[plan].get("price_usd_month", live[plan].get("price_usd"))
        assert f"${price:,}" in line, line
    printed = {ln.split()[0] for ln in lines[:-1] if not ln.startswith("Free: ")}
    assert printed == set(live), (printed, set(live))
