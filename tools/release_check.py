"""The paid path's release check, from an empty house.

    py tools/release_check.py                      # the wheel in dist/ for pyproject's version
    py tools/release_check.py --wheel <path.whl>   # a specific wheel
    py tools/release_check.py --from-pypi          # arcaeon==<version> as PyPI serves it

WHY THIS EXISTS. `arcaeon seal` passed its release check for a year while it
worked on exactly one laptop. publish.py's fresh-venv step built a new venv,
but it ran from a home directory that still held the maintainer's key and
namespace setup, so the check proved "works here", never "works for a
stranger". kindred labs proposed three checks (Colony comment 43770a24 on the
release post), and they were accepted as the fix:

  A. EMPTY HOUSE. The check starts from an empty home and config directory,
     not just a new venv. `arcaeon seal` with no key must refuse, clearly,
     with a non-zero exit, and must not succeed by finding anything.
  B. OUTCOME vs READ-BACK. What the CLI says it did is read separately from
     an independent read-back of the witness pin it claims to have made. The
     pin must hold the head of the ledger the CLI wrote, recomputed here from
     the file with this script's own copy of the chain rule, and that ledger's
     row must carry the sha256 of the fixture that was sealed.
  C. NAMESPACE FENCE. An explicit namespace outside the key's permitted prefix
     must be refused by the witness (403), and the CLI must report the
     refusal, not a success.

THE HOUSE. One temp directory holds four siblings: `home` (empty; HOME,
USERPROFILE, APPDATA, LOCALAPPDATA and every XDG_* dir point at it), `venv`,
`work` and `tmp`. Every subprocess gets an environment built from nothing:
the house paths, a PATH of the venv plus the OS's own binary folders, and the
handful of variables this script names below. Nothing is inherited, so no
ARCAEON_KEY, no PYTHONPATH, no pip config, no witness URL leaks in from the
machine running the check. The home is listed before check A and again after
it; a file there is a FAIL.

THE KEY. Read by NAME only (default ARCAEON_TEST_KEY, via publish.py's
credential(): the environment, then the repo's .env or --env-file), placed in
the subprocess env for B and C only, never printed. It should be a throwaway
witness key with a narrow namespace prefix. ARCAEON_KEY is deliberately not
the default: the operator's own key is the one whose wide prefix made the old
check pass, and a key whose prefix covers every namespace cannot show C.
With no test key, B and C run against a stub witness this script starts on
127.0.0.1 (same pin/latest protocol, same 403 wording), and the report says
STUBBED in capitals. Check A always points the CLI at that local stub as a
tripwire: with no key, nothing may reach it.

Output: one line per check, PASS / FAIL / STUBBED plus its evidence (B's two
facts on their own lines). Exit 1 on any FAIL, 2 if the house could not be
built (venv or install failed), else 0. STUBBED is not a FAIL; it is a check
that ran against the stub instead of the real witness, and says so.

EXCEPT when the paid path changed. If the diff since the last release tag
(or, with no tags, the last commit that bumped pyproject's version) touches
src/arcaeon/remote/, cli._seal, cli._credits, or cli._pin's remote branch
(with its helper _pin_ns_from_key), a STUBBED check has not exercised the code
that changed: the script prints "BLOCKED paid path changed and not exercised:
set ARCAEON_TEST_KEY (...)" and exits 1. If git cannot say what changed, that
blocks too. No key is minted here; the fix is a real throwaway test key.

First line out: the site's products.yaml `version` (for id arcaeon) against
pyproject.toml. A mismatch is a WARN, a missing site checkout (looked for at
ARCAEON_SITE_ROOT, then ../<any>/projects/arcaeon_site) a COULD NOT LOOK;
neither changes the exit code.

Second line out: the registered verbs (K001). A verb in cli.LAZY_VERBS whose
module is not in src/, or a `TODO(K` marker still in docs/VERBS.md, is a FAIL
(exit 1): a verb that answers "not built in this checkout" must not ship.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = Path(__file__).resolve().parent

DEFAULT_KEY_NAME = "ARCAEON_TEST_KEY"
STUB_PREFIX = "rc-stub-"
#: Outside every test prefix this script mints or expects (a test key's prefix
#: must not start with "zz-"). Valid under the witness's [a-z0-9-]{1,64} rule,
#: so a refusal is about the fence, not the name's shape.
OUTSIDE_NS = "zz-release-check-outside-fence"
DEFAULT_NS = "mcp-vet-sealed-scans"
NS_RE = re.compile(r"^[a-z0-9-]{1,64}$")
REFUSAL_NO_KEY = "no ARCAEON_KEY is set, so nothing was sent"
REFUSAL_FENCE = "may not pin namespace"
CLI_TIMEOUT = 300
GENESIS = "genesis"
CHAIN_LEN = 32

#: The fixture: a one-tool MCP server module with no findings in the checked
#: classes (no entrypoint, so the audit-record check stays silent). Sealed as a
#: single file, so the badge's artifact_digest is the sha256 of these bytes.
FIXTURE = (
    '"""A one-tool MCP server module: the release check\'s sealing fixture."""\n'
    "from mcp.server.fastmcp import FastMCP\n"
    "\n"
    'mcp = FastMCP("release-check-fixture")\n'
    "\n"
    "\n"
    "@mcp.tool()\n"
    "def add(a: int, b: int) -> int:\n"
    '    """Add two integers and return the sum."""\n'
    "    return a + b\n"
)


def _load_publish():
    spec = importlib.util.spec_from_file_location("arcaeon_publish_tool", TOOLS / "publish.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- the stub witness ------------------------------------------------------------

class StubWitness:
    """POST /api/pin and GET /api/latest, in memory, on 127.0.0.1.

    Same contract as the hosted witness where the checks look: a bearer key,
    the namespace regex, the prefix fence answered as 403 with the witness's
    own sentence (`this key may only pin namespaces starting with "<p>"`),
    the monotonic guard, 201 with the pin on success, 404 on no pin. Every
    request is logged as (method, path, namespace, status) so a check can say
    how many reached it."""

    def __init__(self, key: str | None = None, prefix: str = STUB_PREFIX):
        self.key = key or ("wk_stub_" + secrets.token_hex(16))
        self.prefix = prefix
        self.pins: dict[str, dict] = {}
        self.log: list[tuple[str, str, str, int]] = []
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "StubWitness":
        stub = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _send(self, status, body, ns=""):
                raw = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                with stub._lock:
                    stub.log.append((self.command, self.path.split("?")[0], ns, status))

            def do_GET(self):
                u = urllib.parse.urlsplit(self.path)
                if u.path != "/api/latest":
                    return self._send(404, {"error": "not found"})
                ns = (urllib.parse.parse_qs(u.query).get("ns") or [""])[0]
                if not NS_RE.match(ns):
                    return self._send(400, {"error": "ns must match [a-z0-9-]{1,64}"}, ns)
                with stub._lock:
                    pin = stub.pins.get(ns)
                if pin is None:
                    return self._send(404, {"error": f'no pin recorded for namespace "{ns}"'}, ns)
                return self._send(200, {"ok": True, "pin": pin, "source": "release-check-stub"}, ns)

            def do_POST(self):
                if urllib.parse.urlsplit(self.path).path != "/api/pin":
                    return self._send(404, {"error": "not found"})
                n = int(self.headers.get("Content-Length") or 0)
                try:
                    body = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
                except ValueError:
                    return self._send(400, {"error": "body is not JSON"})
                ns = str(body.get("namespace") or "")
                auth = self.headers.get("Authorization") or ""
                key = auth[7:].strip() if auth.startswith("Bearer ") else ""
                if not key or key != stub.key:
                    return self._send(401, {"error": "invalid or missing bearer key"}, ns)
                rows, chain = body.get("rows"), body.get("chain")
                if not NS_RE.match(ns) or not isinstance(rows, int) or rows < 0 \
                        or not isinstance(chain, str) or not chain:
                    return self._send(400, {"error": "need namespace, rows, chain"}, ns)
                if not ns.startswith(stub.prefix):
                    return self._send(403, {"error": "this key may only pin namespaces "
                                                     f'starting with "{stub.prefix}"'}, ns)
                with stub._lock:
                    cur = stub.pins.get(ns)
                    if cur and rows < cur["rows"]:
                        status, out = 409, {"error": "monotonic violation: a witness never goes backward"}
                    else:
                        pin = {"namespace": ns, "rows": rows, "chain": chain,
                               "pinned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
                        stub.pins[ns] = pin
                        status, out = 201, {"ok": True, "pin": pin}
                return self._send(status, out, ns)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def count(self, method: str | None = None) -> int:
        with self._lock:
            return sum(1 for m, *_ in self.log if method is None or m == method)

    def statuses_for(self, ns: str, method: str = "POST") -> list[int]:
        with self._lock:
            return [s for m, _, n, s in self.log if m == method and n == ns]


# --- the house -------------------------------------------------------------------

@dataclass
class House:
    root: Path
    home: Path
    venv: Path
    work: Path
    tmp: Path

    @classmethod
    def build(cls, root: Path) -> "House":
        h = cls(root, root / "home", root / "venv", root / "work", root / "tmp")
        for d in (h.home, h.work, h.tmp):
            d.mkdir(parents=True, exist_ok=True)
        return h

    def home_files(self) -> list[str]:
        return sorted(p.relative_to(self.home).as_posix()
                      for p in self.home.rglob("*") if p.is_file())


def venv_bin(venv: Path) -> Path:
    return venv / ("Scripts" if os.name == "nt" else "bin")


def house_env(house: House, extra: dict | None = None) -> dict:
    """The whole environment of every subprocess, built from nothing.

    The only values read from this machine are where the OS keeps its own
    binaries (SYSTEMROOT / WINDIR on Windows, which Python needs to start;
    /usr/bin and /bin elsewhere). Nothing arcaeon, pip or Python reads as
    configuration is carried over."""
    home = str(house.home)
    env = {
        "HOME": home, "USERPROFILE": home, "APPDATA": home, "LOCALAPPDATA": home,
        "XDG_CONFIG_HOME": home, "XDG_DATA_HOME": home, "XDG_CACHE_HOME": home,
        "XDG_STATE_HOME": home,
        "TMP": str(house.tmp), "TEMP": str(house.tmp), "TMPDIR": str(house.tmp),
        "PYTHONIOENCODING": "utf-8", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INPUT": "1", "PIP_CONFIG_FILE": os.devnull,
        # The activity journal (arcaeon.journal) would write ~/.arcaeon/activity.jsonl
        # into the house's empty home, and check A's empty-house test proves no
        # file lands there. The journal is a local convenience, not part of what
        # a release must do, so every command in the house runs with it off.
        "ARCAEON_JOURNAL": "0",
    }
    if os.name == "nt":
        sysroot = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or "C:" + chr(92) + "Windows"
        drive, rest = os.path.splitdrive(home)
        env.update({"SYSTEMROOT": sysroot, "WINDIR": sysroot, "HOMEDRIVE": drive, "HOMEPATH": rest,
                    "PATHEXT": ".COM;.EXE;.BAT;.CMD",
                    "PATH": os.pathsep.join([str(venv_bin(house.venv)),
                                             os.path.join(sysroot, "System32"), sysroot])})
    else:
        env.update({"PATH": os.pathsep.join([str(venv_bin(house.venv)), "/usr/bin", "/bin"]),
                    "LANG": "C.UTF-8"})
    if extra:
        env.update(extra)
    return env


def _run(cmd, env, cwd, timeout=CLI_TIMEOUT):
    return subprocess.run([str(c) for c in cmd], env=env, cwd=str(cwd), capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=timeout)


class SetupFailed(Exception):
    pass


def install(house: House, *, wheel: Path | None = None, version: str | None = None,
            index_url: str | None = None) -> list[str]:
    """A fresh venv inside the house, the wheel (or arcaeon==version) in it.
    Returns the argv that runs the installed CLI."""
    env = house_env(house)
    p = _run([sys.executable, "-m", "venv", house.venv], env, house.work)
    if p.returncode:
        raise SetupFailed(f"venv failed: {_tail(p)}")
    py = venv_bin(house.venv) / ("python.exe" if os.name == "nt" else "python")
    cmd = [py, "-m", "pip", "install", "--quiet", "--no-deps", "--no-cache-dir"]
    if wheel is not None:
        cmd += ["--no-index", wheel]
    else:
        for name in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"):  # the network, not config
            if os.environ.get(name):
                env[name] = os.environ[name]
        cmd += [f"arcaeon=={version}"] + (["--index-url", index_url] if index_url else [])
    p = _run(cmd, env, house.work)
    if p.returncode:
        raise SetupFailed(f"pip install failed: {_tail(p)}")
    exe = venv_bin(house.venv) / ("arcaeon.exe" if os.name == "nt" else "arcaeon")
    if not exe.exists():
        raise SetupFailed(f"installed, but no {exe.name} in the venv")
    return [str(exe)]


def _tail(p, n=4) -> str:
    lines = ((p.stdout or "") + (p.stderr or "")).strip().splitlines()
    return " | ".join(lines[-n:])


# --- independent read-back -------------------------------------------------------

def http_get_json(url: str, timeout: float = 20.0) -> tuple[int, dict]:
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "arcaeon-release-check"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status, raw = r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status, raw = e.code, (e.read().decode("utf-8", "replace") if e.fp else "")
    except (urllib.error.URLError, OSError) as e:
        return 0, {"error": f"unreachable: {getattr(e, 'reason', e)}"}
    try:
        body = json.loads(raw) if raw.strip() else {}
    except ValueError:
        body = {"error": raw[:200]}
    return status, body if isinstance(body, dict) else {"result": body}


def read_pin(witness_url: str, ns: str) -> tuple[int, dict | None]:
    status, body = http_get_json(f"{witness_url.rstrip('/')}/api/latest?"
                                 + urllib.parse.urlencode({"ns": ns}))
    pin = body.get("pin") if status == 200 and isinstance(body.get("pin"), dict) else None
    return status, pin


def ledger_head(path: Path) -> tuple[int, str, dict | None, str | None]:
    """(rows, chain, last_row, problem) recomputed from the file with this
    script's own copy of the frozen chain rule (arcaeon.record.row), not the
    package's: sha256(prev + json.dumps(row minus chain, ensure_ascii=False,
    sort_keys=True))[:32], first prev "genesis"."""
    try:
        lines = [x for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    except OSError as e:
        return 0, GENESIS, None, f"no ledger at {path.name} ({e.strerror or e})"
    prev, row = GENESIS, None
    for i, line in enumerate(lines, 1):
        try:
            row = json.loads(line)
        except ValueError:
            return i - 1, prev, None, f"line {i} is not JSON"
        body = json.dumps({k: v for k, v in row.items() if k != "chain"},
                          ensure_ascii=False, sort_keys=True)
        want = hashlib.sha256((prev + body).encode("utf-8", "surrogatepass")).hexdigest()[:CHAIN_LEN]
        if row.get("chain") != want:
            return i - 1, prev, row, f"line {i}'s chain does not recompute"
        prev = want
    return len(lines), prev, row, None


def cli_report(stdout: str) -> dict | None:
    """The JSON block `arcaeon seal` prints after the Markdown badge line."""
    i = stdout.find("\n{")
    text = stdout[i + 1:] if i >= 0 else (stdout if stdout.lstrip().startswith("{") else "")
    try:
        d = json.loads(text)
    except ValueError:
        return None
    return d if isinstance(d, dict) else None


# --- the checks ------------------------------------------------------------------

@dataclass
class Check:
    letter: str
    title: str
    status: str = "FAIL"            # PASS / FAIL / STUBBED
    summary: str = ""
    lines: list[str] = field(default_factory=list)

    def render(self) -> str:
        head = f"{self.status:<8}{self.letter} {self.title}: {self.summary}"
        return "\n".join([head, *[" " * 10 + x for x in self.lines]])


@dataclass
class Run:
    cli: list[str]
    house: House
    fixture: Path
    witness_url: str                # where B and C pin, and where the read-back reads
    key: str | None
    stubbed: bool
    stub: StubWitness               # always running: C's log, and A's tripwire
    extra_env: dict = field(default_factory=dict)   # tests only (e.g. PYTHONPATH)

    def seal(self, *args, key: str | None = None, url: str | None = None, log: Path):
        extra = dict(self.extra_env, ARCAEON_SEALED_SCAN_LOG=str(log))
        extra["ARCAEON_WITNESS_URL"] = url or self.witness_url
        if key:
            extra["ARCAEON_KEY"] = key
        env = house_env(self.house, extra)
        if not key:
            env.pop("ARCAEON_KEY", None)    # check A: no key, whatever a caller passed
        log.parent.mkdir(parents=True, exist_ok=True)
        return _run([*self.cli, "seal", str(self.fixture), *args], env, log.parent)


def _short(s, n=12) -> str:
    return (str(s)[:n] + "...") if s and len(str(s)) > n else str(s)


def check_a(run: Run) -> Check:
    c = Check("A", "empty house")
    before = run.house.home_files()
    n_before = run.stub.count()
    log = run.house.work / "a" / "sealed_scans.jsonl"
    p = run.seal(key=None, url=run.stub.url, log=log)
    out = (p.stdout or "") + (p.stderr or "")
    rep = cli_report(p.stdout or "") or {}
    sealed = (rep.get("sealed_scan") or {}).get("sealed")
    reached = run.stub.count() - n_before
    after = run.house.home_files()
    fails = []
    if before:
        fails.append(f"home held {len(before)} file(s) before the run: {before[:3]}")
    if p.returncode == 0:
        fails.append("exit 0")
    if REFUSAL_NO_KEY not in out:
        fails.append(f"no refusal sentence ({REFUSAL_NO_KEY!r})")
    if sealed is not False:
        fails.append(f"sealed_scan.sealed is {sealed!r}, not false")
    if reached:
        fails.append(f"{reached} request(s) reached the witness")
    if log.exists():
        fails.append("a ledger row was written for a scan with no key")
    if after:
        fails.append(f"home holds {len(after)} file(s) after the run: {after[:3]}")
    c.status = "FAIL" if fails else "PASS"
    c.summary = ("; ".join(fails) if fails else
                 f"`arcaeon seal` with no key exited {p.returncode}, said \"{REFUSAL_NO_KEY}\", "
                 f"sealed=false, {reached} requests reached the witness, no ledger row; "
                 f"home had 0 files before and after")
    return c


def check_c(run: Run) -> tuple[Check, str | None]:
    """Also returns the prefix the witness named in its refusal, if any."""
    c = Check("C", "namespace fence")
    log = run.house.work / "c" / "sealed_scans.jsonl"
    p = run.seal("--ns", OUTSIDE_NS, key=run.key, log=log)
    out = (p.stdout or "") + (p.stderr or "")
    rep = cli_report(p.stdout or "") or {}
    ss = rep.get("sealed_scan") or {}
    pin = ss.get("pin") or {}
    m = re.search(r'starting with "([a-z0-9-]{1,64})"', str(pin.get("error") or ""))
    prefix = m.group(1) if m else None
    rb_status, rb_pin = read_pin(run.witness_url, OUTSIDE_NS)
    rows, chain, _, _ = ledger_head(log)
    ours_pinned = bool(rb_pin and rb_pin.get("chain") == chain and rb_pin.get("rows") == rows)
    fails = []
    if p.returncode == 0:
        fails.append("CLI exit 0")
    if ss.get("sealed") is not False:
        fails.append(f"CLI reported sealed={ss.get('sealed')!r}")
    if pin.get("status") != 403:
        fails.append(f"witness answered {pin.get('status')!r}, not 403")
    if REFUSAL_FENCE not in out:
        fails.append(f"CLI did not report the refusal ({REFUSAL_FENCE!r})")
    if ours_pinned:
        fails.append(f"the witness HOLDS our head under {OUTSIDE_NS}")
    if run.stubbed and run.stub.statuses_for(OUTSIDE_NS) != [403]:
        fails.append(f"stub saw {run.stub.statuses_for(OUTSIDE_NS)} for {OUTSIDE_NS}, not [403]")
    c.status = "FAIL" if fails else ("STUBBED" if run.stubbed else "PASS")
    c.summary = ("; ".join(fails) if fails else
                 f"`arcaeon seal --ns {OUTSIDE_NS}`: witness 403 "
                 f"(\"{str(pin.get('error'))[:70]}\"), CLI exit {p.returncode} reported "
                 f"\"{REFUSAL_FENCE} '{OUTSIDE_NS}'\", sealed=false; read-back "
                 f"/api/latest?ns={OUTSIDE_NS} -> {rb_status}, our head not held")
    return c, prefix


def check_b(run: Run, prefix: str | None) -> Check:
    c = Check("B", "outcome vs read-back")
    args = []
    if prefix:
        stamp = time.strftime("%Y%m%dt%H%M%S", time.gmtime())
        ns = prefix + ("" if prefix.endswith("-") else "-") + "release-check-" + stamp
        if NS_RE.match(ns):
            args = ["--ns", ns]
    log = run.house.work / "b" / "sealed_scans.jsonl"
    p = run.seal(*args, key=run.key, log=log)
    rep = cli_report(p.stdout or "") or {}
    ss = rep.get("sealed_scan") or {}
    claimed_ns = ss.get("namespace") or (args[1] if args else DEFAULT_NS)
    claimed = ss.get("ledger_head") or {}
    said_ok = p.returncode == 0 and ss.get("sealed") is True
    c.lines.append(f"outcome:   CLI exit {p.returncode}, sealed={json.dumps(ss.get('sealed'))}, "
                   f"namespace {claimed_ns}, head rows={claimed.get('rows')} "
                   f"chain={_short(claimed.get('chain'))}")

    fixture_sha = hashlib.sha256(run.fixture.read_bytes()).hexdigest()
    rows, chain, last, problem = ledger_head(log)
    rb_status, pin = read_pin(run.witness_url, claimed_ns)
    pin = pin or {}
    row_sha = (last or {}).get("artifact_digest")
    c.lines.append(f"read-back: witness /api/latest?ns={claimed_ns} -> {rb_status}"
                   + (f" rows={pin.get('rows')} chain={_short(pin.get('chain'))}" if pin else " no pin")
                   + f"; ledger recomputed here rows={rows} chain={_short(chain)}"
                   + (f" ({problem})" if problem else "")
                   + f"; its row's artifact_digest {'==' if row_sha == fixture_sha else '!='} "
                     f"sha256(fixture) {_short(fixture_sha)}")
    fails = []
    if not said_ok:
        fails.append("the CLI did not report a seal")
    if problem:
        fails.append(problem)
    if not pin:
        fails.append(f"the witness holds no pin for {claimed_ns}")
    elif (pin.get("rows"), pin.get("chain")) != (rows, chain):
        fails.append("the witness's pin is not the ledger's recomputed head")
    if (claimed.get("rows"), claimed.get("chain")) != (rows, chain):
        fails.append("the CLI's claimed head is not the ledger's recomputed head")
    if row_sha != fixture_sha:
        fails.append("the ledger row does not carry the fixture's sha256")
    if said_ok and fails:
        fails.insert(0, "the CLI said sealed but the read-back disagrees")
    c.status = "FAIL" if fails else ("STUBBED" if run.stubbed else "PASS")
    c.summary = "; ".join(fails) if fails else "outcome and read-back agree"
    return c


def run_checks(run: Run) -> list[Check]:
    """A, then C (whose 403 names the key's prefix), then B under that prefix.
    Printed A, B, C."""
    a = check_a(run)
    c, prefix = check_c(run)
    b = check_b(run, prefix)
    return [a, b, c]


def render(checks: list[Check], key: str | None = None) -> str:
    text = "\n".join(x.render() for x in checks)
    return text.replace(key, "<key>") if key else text


# --- the paid path: did it change since the last release? -------------------------

#: What "the paid path" means for B041: everything under src/arcaeon/remote/,
#: and these pieces of cli.py. `_pin` counts only from its remote branch on
#: (the line that imports arcaeon.remote); its --witness half is local.
PAID_DIR = "src/arcaeon/remote/"
CLI_PATH = "src/arcaeon/cli.py"
PAID_CLI_FUNCS = ("_seal", "_credits", "_pin_ns_from_key")
PIN_REMOTE_MARK = "from arcaeon import remote"
PAID_BLOCK = "paid path changed and not exercised: set ARCAEON_TEST_KEY"


def _git(*args, cwd: Path = ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def release_base(cwd: Path = ROOT) -> tuple[str | None, str]:
    """(commit, how) the diff is taken from: the newest tag reachable from HEAD,
    or, with no tags, the last commit that changed pyproject's `version =` line.
    (None, reason) when git cannot say. ARCAEON_RC_PAID_BASE=<rev> names the
    base outright (the test of publish's dry run uses HEAD); the line the
    script prints always says which base it used."""
    override = os.environ.get("ARCAEON_RC_PAID_BASE")
    if override:
        p = _git("rev-parse", "--verify", "--quiet", override + "^{commit}", cwd=cwd)
        if p.returncode or not p.stdout.strip():
            return None, f"ARCAEON_RC_PAID_BASE={override} is not a commit here"
        return p.stdout.strip(), f"{override} (ARCAEON_RC_PAID_BASE)"
    p = _git("describe", "--tags", "--abbrev=0", cwd=cwd)
    if p.returncode == 0 and p.stdout.strip():
        tag = p.stdout.strip()
        return _git("rev-list", "-n", "1", tag, cwd=cwd).stdout.strip() or None, f"tag {tag}"
    p = _git("log", "-1", "--format=%H", "-G", r"^version\s*=", "--", "pyproject.toml", cwd=cwd)
    if p.returncode == 0 and p.stdout.strip():
        h = p.stdout.strip()
        return h, f"version bump {h[:7]} (no tags)"
    return None, ("git could not name a release tag or a version-bump commit"
                  + (f": {p.stderr.strip()[:120]}" if p.stderr.strip() else ""))


def paid_cli_segments(text: str) -> dict[str, str]:
    """{name: source} of the paid pieces of a cli.py text. Missing = ''."""
    import ast
    out = {n: "" for n in (*PAID_CLI_FUNCS, "_pin[remote]")}
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {n: "<unparseable cli.py>" for n in out}
    lines = text.splitlines()
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        src = "\n".join(lines[node.lineno - 1:node.end_lineno])
        if node.name in PAID_CLI_FUNCS:
            out[node.name] = src
        elif node.name == "_pin":
            i = src.find(PIN_REMOTE_MARK)
            out["_pin[remote]"] = src[i:] if i >= 0 else ""
    return out


def paid_path_changes(cwd: Path = ROOT) -> tuple[list[str] | None, str]:
    """(what changed, base description). What changed is a list of paths and
    cli pieces; None when git could not look. The diff runs from the base to
    the working tree, so uncommitted edits count too."""
    base, how = release_base(cwd)
    if not base:
        return None, how
    p = _git("diff", "--name-only", base, "--", PAID_DIR, cwd=cwd)
    if p.returncode:
        return None, f"git diff failed: {p.stderr.strip()[:120]}"
    changed = sorted(x for x in p.stdout.splitlines() if x.strip())
    q = _git("ls-files", "--others", "--exclude-standard", "--", PAID_DIR, cwd=cwd)
    changed += sorted(x for x in q.stdout.splitlines() if x.strip() and x not in changed)
    old = _git("show", f"{base}:{CLI_PATH}", cwd=cwd)
    old_text = old.stdout if old.returncode == 0 else ""
    try:
        new_text = (cwd / CLI_PATH).read_text(encoding="utf-8")
    except OSError:
        new_text = ""
    norm = lambda s: s.replace("\r\n", "\n")  # noqa: E731  line endings are not a change
    a, b = paid_cli_segments(norm(old_text)), paid_cli_segments(norm(new_text))
    changed += [f"cli.{k}" for k in a if a[k] != b[k]]
    return changed, how


def paid_path_gate(checks: list[Check], cwd: Path = ROOT) -> str | None:
    """The blocking line when B or C is STUBBED and the paid path changed since
    the last release; None when nothing blocks. Could not look = blocks: a
    stubbed check is only good enough when we know the paid path is as released."""
    if not any(x.status == "STUBBED" for x in checks):
        return None
    changed, how = paid_path_changes(cwd)
    if changed is None:
        return f"BLOCKED {PAID_BLOCK} (COULD NOT LOOK at the diff: {how})"
    if not changed:
        print(f"paid path unchanged since {how}: STUBBED does not block", flush=True)
        return None
    shown = ", ".join(changed[:6]) + (f" (+{len(changed) - 6} more)" if len(changed) > 6 else "")
    return f"BLOCKED {PAID_BLOCK} (since {how}: {shown})"


# --- the site's version (a WARN, never a FAIL) -----------------------------------

def site_root() -> Path | None:
    """ARCAEON_SITE_ROOT, else a sibling checkout at ../<any>/projects/arcaeon_site."""
    env = os.environ.get("ARCAEON_SITE_ROOT")
    if env:
        return Path(env)
    found = sorted(ROOT.parent.glob("*/projects/arcaeon_site"))
    return found[0] if found else None


def products_yaml_version(text: str) -> str | None:
    """`version:` of the `- id: arcaeon` entry under `products:`, read line by
    line (this script stays stdlib-only; products.yaml is plain block YAML)."""
    in_products = in_entry = False
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "-")):
            in_products, in_entry = line.startswith("products:"), False
            continue
        if not in_products:
            continue
        if line.startswith("- "):
            in_entry = line[2:].strip() in ("id: arcaeon", "id: 'arcaeon'", 'id: "arcaeon"')
            continue
        m = re.match(r"^  version:\s*(.*?)\s*$", line)
        if in_entry and m:
            v = m.group(1).strip("'\"")
            return v or None
    return None


def site_version_line(pyproject_version: str, root: Path | None = None) -> str:
    """One line: OK, WARN (the site says another version) or COULD NOT LOOK."""
    root = root if root is not None else site_root()
    if root is None:
        return ("COULD NOT LOOK site version: no site checkout (set ARCAEON_SITE_ROOT); "
                "not a fail")
    p = root / "products.yaml"
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        return f"COULD NOT LOOK site version: no products.yaml at the site root ({e.strerror or e}); not a fail"
    v = products_yaml_version(text)
    if v is None:
        return "COULD NOT LOOK site version: products.yaml has no `version` for id arcaeon; not a fail"
    if v != pyproject_version:
        return (f"WARN    site version: products.yaml says {v}, pyproject.toml says "
                f"{pyproject_version}; sync the site before the release (not a fail)")
    return f"OK      site version: products.yaml and pyproject.toml both say {v}"


# --- registered verbs: every one built, every section written (K001) -------------

VERBS_DOC = "docs/VERBS.md"
TODO_MARK = "TODO(K"


def lazy_verb_modules(cli_text: str) -> dict[str, str] | None:
    """{verb: dotted module} from cli.py's LAZY_VERBS literal, read with ast
    (the check never imports the package it is checking). None if cli.py has
    no LAZY_VERBS literal it can read."""
    import ast
    try:
        tree = ast.parse(cli_text)
    except SyntaxError:
        return None
    for node in tree.body:
        target = (node.targets[0] if isinstance(node, ast.Assign) and len(node.targets) == 1
                  else node.target if isinstance(node, ast.AnnAssign) else None)
        if isinstance(target, ast.Name) and target.id == "LAZY_VERBS" and node.value is not None:
            try:
                table = ast.literal_eval(node.value)
            except ValueError:
                return None
            return {v: (m[0] if isinstance(m, (tuple, list)) else m) for v, m in table.items()}
    return None


def _module_file(root: Path, dotted: str) -> Path | None:
    base = root / "src" / Path(*dotted.split("."))
    for cand in (base.with_suffix(".py"), base / "__init__.py"):
        if cand.is_file():
            return cand
    return None


def verbs_problems(root: Path = ROOT) -> list[str]:
    """Why a release must not ship with the verbs as they are: a registered
    verb whose module is not in src/, or a TODO(K marker left in VERBS.md.
    Empty when there is nothing to fix. A cli.py or VERBS.md that cannot be
    read is a problem too: a check that could not look does not pass."""
    problems = []
    try:
        cli_text = (root / CLI_PATH).read_text(encoding="utf-8")
    except OSError as e:
        return [f"cannot read {CLI_PATH} ({e.strerror or type(e).__name__})"]
    table = lazy_verb_modules(cli_text)
    if table is None:
        problems.append(f"{CLI_PATH} has no readable LAZY_VERBS table")
    else:
        missing = [f"{v} ({m})" for v, m in table.items() if _module_file(root, m) is None]
        if missing:
            problems.append("registered verb(s) with no module: " + ", ".join(missing))
    try:
        doc = (root / VERBS_DOC).read_text(encoding="utf-8")
    except OSError as e:
        problems.append(f"cannot read {VERBS_DOC} ({e.strerror or type(e).__name__})")
    else:
        marks = sorted(set(re.findall(re.escape(TODO_MARK) + r"\d*\)?", doc)))
        if marks:
            problems.append(f"{VERBS_DOC} still holds {', '.join(marks)}")
    return problems


def verbs_line(problems: list[str]) -> str:
    if problems:
        return "FAIL    verbs: " + "; ".join(problems)
    return "OK      verbs: every registered verb has its module and a written section"


# --- main ------------------------------------------------------------------------

def _pyproject_version() -> str:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def parse(argv):
    ap = argparse.ArgumentParser(prog="release_check.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", default=None, help="default: pyproject.toml's version")
    ap.add_argument("--wheel", default=None, help="default: dist/arcaeon-<version>-py3-none-any.whl")
    ap.add_argument("--from-pypi", dest="from_pypi", action="store_true",
                    help="install arcaeon==<version> from the index instead of a local wheel")
    ap.add_argument("--index-url", dest="index_url", default=None, help="with --from-pypi")
    ap.add_argument("--key-name", dest="key_name", default=DEFAULT_KEY_NAME,
                    help=f"env var NAME of a throwaway witness key (default {DEFAULT_KEY_NAME})")
    ap.add_argument("--env-file", dest="env_file", default=str(ROOT / ".env"))
    ap.add_argument("--stub", action="store_true", help="use the stub witness even if a key exists")
    ap.add_argument("--keep", action="store_true", help="keep the house for inspection")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    a = parse(argv)
    version = a.version or _pyproject_version()
    print(site_version_line(_pyproject_version()), flush=True)
    verb_problems = verbs_problems()
    print(verbs_line(verb_problems), flush=True)
    key = None if a.stub else _load_publish().credential(a.key_name, Path(a.env_file))
    stub = StubWitness().start()
    stubbed = not key
    witness_url = stub.url if stubbed else os.environ.get("ARCAEON_RELEASE_CHECK_WITNESS",
                                                          "https://witness.arcaeon.io")
    root = Path(tempfile.mkdtemp(prefix="arcaeon-rc-"))
    try:
        house = House.build(root)
        if a.from_pypi:
            source = f"arcaeon=={version} from {a.index_url or 'PyPI'}"
            cli = install(house, version=version, index_url=a.index_url)
        else:
            wheel = Path(a.wheel) if a.wheel else ROOT / "dist" / f"arcaeon-{version}-py3-none-any.whl"
            if not wheel.exists():
                print(f"FAIL    setup: no wheel at {wheel.name}; build first or pass --wheel / --from-pypi")
                return 2
            source = wheel.name
            cli = install(house, wheel=wheel.resolve())
        fixture = house.work / "server.py"
        fixture.write_text(FIXTURE, encoding="utf-8", newline="\n")
        who = (f"STUB witness on {stub.url} (no {a.key_name} by name)" if stubbed
               else f"{witness_url} with the key named {a.key_name}")
        print(f"arcaeon release check: {source}; B and C against the {who}", flush=True)
        print(f"house: HOME, USERPROFILE, APPDATA, LOCALAPPDATA, XDG_* -> an empty temp dir; "
              f"subprocess env built from nothing, these names only: "
              f"{' '.join(sorted(house_env(house)))} (+ ARCAEON_WITNESS_URL, "
              f"ARCAEON_SEALED_SCAN_LOG; ARCAEON_KEY for B and C only)", flush=True)
        run = Run(cli=cli, house=house, fixture=fixture, witness_url=witness_url,
                  key=stub.key if stubbed else key, stubbed=stubbed, stub=stub)
        checks = run_checks(run)
        print(render(checks, key), flush=True)
        blocked = paid_path_gate(checks)
        if blocked:
            print(blocked, flush=True)
        return 1 if blocked or verb_problems or any(x.status == "FAIL" for x in checks) else 0
    except SetupFailed as e:
        print(f"FAIL    setup: {e}", flush=True)
        return 2
    finally:
        stub.stop()
        if a.keep:
            print(f"house kept at {root}", flush=True)
        else:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
