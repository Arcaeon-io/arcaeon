"""KH1: one API, three languages.

One real `arcaeon serve --port 0` (the CLI, a subprocess, loopback only) with
a temporary ARCAEON_HOME and served root. Against that one server:

- the Python client (arcaeon.client.Client(), url and token read from the
  home it wrote, so the home token goes only to loopback),
- the JS client (clients/js/arcaeon.mjs, Client.connect(), in a node
  subprocess; skipped with a reason when node is absent),
- plain curl (a subprocess; skipped with a reason when curl is absent),

each drive the same log, verify, reconcile and evidence-pack calls, and every
answer must carry the same verdict word, the same integer `exit` and the same
HTTP status as the EXPECTED table. So the three agree with each other because
each agrees with one table, and the read-only checks are held to the CLI's own
process exit code too.

Then every example in clients/curl/EXAMPLES.md (generated from the OpenAPI
document by tools/gen_curl_examples.py) is run, in order, with curl against
the same server, and the answer each example names is checked. The drift test
holds EXAMPLES.md to the generator.

WSL: the Windows half runs here. The WSL half is a documented manual step,
not run from this test, because `wsl -d Ubuntu-22.04` boots a VM that
outlives the test and WSL's loopback is not Windows' loopback. By hand, from
an Ubuntu-22.04 shell (python3 with pytest, curl, and node for the JS half):

    cd /mnt/c/<your checkout>/arcaeon-public
    PYTHONPATH=src python3 -m pytest tests/heavy/test_kh1_three_languages.py -q
    node --test clients/js

The file is written to run unchanged there (sys.executable, no Windows paths).
Nothing here reaches past 127.0.0.1; the server is stopped at teardown.
"""
from __future__ import annotations

import importlib.util
import json
import os
import queue
import re
import shlex
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src"
JS_CLIENT = REPO / "clients" / "js" / "arcaeon.mjs"
EXAMPLES = REPO / "clients" / "curl" / "EXAMPLES.md"
GEN = REPO / "tools" / "gen_curl_examples.py"

#: reconcile's JSON has always spelled it this way (arcaeon.verdict.COULD_NOT_LOOK_TOKEN):
#: same word, same exit 3. The three languages must agree on the spelling too.
COULD_NOT_LOOK_TOKEN = "COULD_NOT_LOOK"

NODE = shutil.which("node")
CURL = shutil.which("curl")
LANGS = ("py", "js", "curl")


def _gen():
    spec = importlib.util.spec_from_file_location("gen_curl_examples", GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- the one server ---------------------------------------------------------------

class Served:
    def __init__(self, base: Path):
        self.home = base / "home"
        self.root = base / "served"
        self.root.mkdir(parents=True)
        self.env = {**os.environ, "ARCAEON_HOME": str(self.home), "ARCAEON_JOURNAL": "0",
                    "PYTHONPATH": os.pathsep.join(
                        [str(SRC), *filter(None, [os.environ.get("PYTHONPATH")])])}
        self.env.pop("ARCAEON_KEY", None)
        self.errlog = open(base / "serve.stderr.txt", "wb")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "arcaeon", "serve", "--port", "0", "--root", str(self.root)],
            cwd=self.root, env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=self.errlog, text=True, encoding="utf-8")
        lines: queue.Queue = queue.Queue()
        threading.Thread(target=self._drain, args=(lines,), daemon=True).start()
        self.url = None
        try:
            while self.url is None:
                line = lines.get(timeout=30)
                if line is None:
                    raise RuntimeError("arcaeon serve exited before it printed its address")
                m = re.search(r"listening on (http://127\.0\.0\.1:\d+)", line)
                if m:
                    self.url = m.group(1)
        except BaseException:
            self.stop()
            raise
        tok = subprocess.run([sys.executable, "-m", "arcaeon", "serve", "--print-token"],
                             env=self.env, capture_output=True, text=True, timeout=60)
        assert tok.returncode == 0, "serve --print-token failed"
        self.token = tok.stdout.strip()

    def _drain(self, lines):
        for line in self.proc.stdout:
            lines.put(line)
        lines.put(None)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(15)
        self.errlog.close()


@pytest.fixture(scope="module")
def served(tmp_path_factory):
    s = Served(tmp_path_factory.mktemp("kh1"))
    mp = pytest.MonkeyPatch()
    mp.setenv("ARCAEON_HOME", str(s.home))     # Client() reads serve.json + serve.token here
    mp.setenv("ARCAEON_JOURNAL", "0")
    mp.delenv("ARCAEON_KEY", raising=False)
    try:
        _fixtures(s.root, s.env)
        yield s
    finally:
        mp.undo()
        s.stop()
    assert s.proc.poll() is not None, "the server outlived the test"


# --- fixtures in the served root ------------------------------------------------------

def _fixtures(root: Path, env: dict) -> None:
    from arcaeon.prove.reconcile import TAPE_FORMAT
    from arcaeon.record.ledger import Ledger, digest_json

    good = root / "kh1_good.jsonl"
    good.touch()
    lg = Ledger(good)
    for k in range(1, 4):
        lg.append({"tool": "search", "query": f"refund policy {k}"})
    broken = root / "kh1_broken.jsonl"
    text = good.read_text(encoding="utf-8")
    assert "refund policy 2" in text
    broken.write_text(text.replace("refund policy 2", "refund policy X"), encoding="utf-8")

    def tape(name, side, n=3, skip=None, alter=None):
        p = root / name
        p.touch()
        t = Ledger(p)
        for k in range(1, n + 1):
            if k == skip:
                continue
            arg = "changed" if k == alter else f"c{k}"
            t.append({"evt": "tape_call", "tape": TAPE_FORMAT, "side": side, "ns": f"kh1-{side}",
                      "idx": k, "tool": "echo",
                      "req": digest_json({"name": "echo", "arguments": {"text": arg}}),
                      "resp": digest_json({"result": {"text": arg}}), "status": "ok"})

    tape("kh1_agent.jsonl", "agent")
    tape("kh1_tool.jsonl", "tool")
    tape("kh1_tool_short.jsonl", "tool", skip=3)
    tape("kh1_tool_altered.jsonl", "tool", alter=2)

    base = root / "kh1_base_pack"
    r = subprocess.run([sys.executable, "-m", "arcaeon", "evidence-pack", "--ledger", str(good),
                        "--out", str(base), "--json"], cwd=root, capture_output=True,
                       text=True, timeout=120, env=env)
    assert r.returncode == 0, r.stderr
    tampered = root / "kh1_tampered_pack"
    shutil.copytree(base, tampered)
    rec = tampered / "records.jsonl"
    assert rec.is_file(), sorted(p.name for p in tampered.iterdir())
    rec.write_bytes(rec.read_bytes().replace(b"refund policy 2", b"refund policy X"))


# --- the calls, the same for every language -------------------------------------------

def cases(lang: str) -> list[dict]:
    """(name, client method, route, body, expected verdict, exit, HTTP status)."""
    L = f"kh1_{lang}_calls.jsonl"

    def c(name, method, path, body, verdict, code, http=200):
        return {"name": name, "method": method, "path": path, "body": body,
                "verdict": verdict, "exit": code, "http": http}
    return [
        c("log_first", "log", "/v1/log", {"ledger": L, "fields": {"tool": "search", "n": 1}},
          None, 0),
        c("log_second", "log", "/v1/log", {"ledger": L, "row": {"tool": "quote", "n": 2}},
          None, 0),
        c("log_no_row", "log", "/v1/log", {"ledger": L}, None, 2, 400),
        c("verify_logged", "verify", "/v1/verify", {"ledger": L}, "VERIFIED", 0),
        c("verify_good", "verify", "/v1/verify", {"ledger": "kh1_good.jsonl"}, "VERIFIED", 0),
        c("verify_broken", "verify", "/v1/verify", {"ledger": "kh1_broken.jsonl"}, "BROKEN", 1),
        c("verify_absent", "verify", "/v1/verify", {"ledger": "kh1_absent.jsonl"},
          "COULD NOT LOOK", 3),
        c("verify_outside_root", "verify", "/v1/verify", {"ledger": "../outside.jsonl"},
          None, 2, 400),
        c("reconcile_matched", "reconcile", "/v1/reconcile",
          {"tape_a": "kh1_agent.jsonl", "tape_b": "kh1_tool.jsonl"}, "MATCHED", 0),
        c("reconcile_missing", "reconcile", "/v1/reconcile",
          {"tape_a": "kh1_agent.jsonl", "tape_b": "kh1_tool_short.jsonl"}, "MISSING", 1),
        c("reconcile_altered", "reconcile", "/v1/reconcile",
          {"tape_a": "kh1_agent.jsonl", "tape_b": "kh1_tool_altered.jsonl"}, "ALTERED", 1),
        c("reconcile_absent", "reconcile", "/v1/reconcile",
          {"tape_a": "kh1_agent.jsonl", "tape_b": "kh1_nope.jsonl"}, COULD_NOT_LOOK_TOKEN, 3),
        c("pack_build", "evidence_pack", "/v1/evidence-pack",
          {"ledger": "kh1_good.jsonl", "out": f"kh1_{lang}_pack"}, "VERIFIED", 0),
        c("pack_verify_built", "evidence_pack_verify", "/v1/evidence-pack/verify",
          {"pack": f"kh1_{lang}_pack"}, "VERIFIED", 0),
        c("pack_verify_tampered", "evidence_pack_verify", "/v1/evidence-pack/verify",
          {"pack": "kh1_tampered_pack"}, "BROKEN", 1),
        c("pack_verify_absent", "evidence_pack_verify", "/v1/evidence-pack/verify",
          {"pack": "kh1_absent_pack"}, "COULD NOT LOOK", 3),
    ]


def _normal(ans: dict, http: int) -> dict:
    return {"verdict": ans.get("verdict"), "exit": ans.get("exit"), "http": http}


def _check(lang: str, got: list[dict]) -> None:
    want = cases(lang)
    assert len(got) == len(want)
    bad = []
    for case, (ans, http) in zip(want, got):
        norm = _normal(ans, http)
        exp = {"verdict": case["verdict"], "exit": case["exit"], "http": case["http"]}
        if norm != exp:
            bad.append(f"{lang} {case['name']}: got {norm}, want {exp}")
        if case["method"] == "log" and case["exit"] == 0:
            if not re.fullmatch(r"[0-9a-f]{16,}", str(ans.get("chain", ""))):
                bad.append(f"{lang} {case['name']}: no chain value in {ans}")
        if case["exit"] == 3:
            assert ans.get("exit") != 0      # COULD NOT LOOK never reads as a pass
    assert not bad, "\n".join(bad)


# --- the three drivers ----------------------------------------------------------------

def run_python(served) -> list:
    from arcaeon.client import Client
    c = Client()                       # url and token both from the home serve wrote
    assert c.url == served.url
    out = []
    for case in cases("py"):
        ans = getattr(c, case["method"])(case["body"])
        out.append((ans, ans.get("http_status", 200)))
    return out


def _camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(w.title() for w in rest)


def run_js(served, tmp: Path) -> list:
    tmp.mkdir(parents=True, exist_ok=True)
    spec = tmp / "cases.json"
    spec.write_text(json.dumps([{"m": _camel(k["method"]), "body": k["body"]}
                                for k in cases("js")]), encoding="utf-8")
    driver = tmp / "drive.mjs"
    driver.write_text(
        f'import {{ Client }} from {json.dumps(JS_CLIENT.as_uri())};\n'
        'import { readFileSync } from "node:fs";\n'
        'const spec = JSON.parse(readFileSync(process.argv[2], "utf8"));\n'
        'const c = await Client.connect();\n'
        'const out = [];\n'
        'for (const k of spec) out.push(await c[k.m](k.body));\n'
        'process.stdout.write(JSON.stringify({ url: c.url, out }));\n', encoding="utf-8")
    r = subprocess.run([NODE, str(driver), str(spec)], env=served.env, capture_output=True,
                       text=True, encoding="utf-8", timeout=300)
    assert r.returncode == 0, r.stderr[-2000:]
    got = json.loads(r.stdout)
    assert got["url"] == served.url
    return [(a, a.get("http_status", 200)) for a in got["out"]]


def _curl(served, argv: list[str], cwd: Path, save: Path) -> tuple[int, bytes]:
    r = subprocess.run([CURL, *argv, "-w", "%{http_code}"] +
                       ([] if "-o" in argv else ["-o", str(save)]),
                       cwd=cwd, capture_output=True, timeout=300)
    assert r.returncode == 0, f"curl exit {r.returncode}: {r.stderr[-500:]!r}"
    status = int(r.stdout.decode("ascii").strip()[-3:])
    target = cwd / argv[argv.index("-o") + 1] if "-o" in argv else save
    return status, target.read_bytes()


def run_curl(served, tmp: Path) -> list:
    tmp.mkdir(parents=True, exist_ok=True)
    out = []
    for i, case in enumerate(cases("curl")):
        body = tmp / f"body_{i}.json"
        body.write_text(json.dumps(case["body"]), encoding="utf-8")
        status, raw = _curl(served, ["-s", "-X", "POST",
                                     "-H", f"Authorization: Bearer {served.token}",
                                     "-H", "Content-Type: application/json",
                                     "--data-binary", f"@{body}", served.url + case["path"]],
                            tmp, tmp / f"answer_{i}.json")
        out.append((json.loads(raw.decode("utf-8")), status))
    return out


# --- the tests ------------------------------------------------------------------------

def test_the_one_server_is_loopback_and_wrote_its_home(served):
    assert served.url.startswith("http://127.0.0.1:")
    rec = json.loads((served.home / "serve.json").read_text(encoding="utf-8"))
    assert rec["url"] == served.url
    assert (served.home / "serve.token").read_text(encoding="utf-8").strip() == served.token


def test_python_client_answers_match_the_table(served):
    _check("py", run_python(served))


@pytest.mark.skipif(NODE is None, reason="node is not on PATH: the JS half cannot run here")
def test_js_client_answers_match_the_table(served, tmp_path):
    _check("js", run_js(served, tmp_path / "js"))


@pytest.mark.skipif(CURL is None, reason="curl is not on PATH: the curl half cannot run here")
def test_plain_curl_answers_match_the_table(served, tmp_path):
    _check("curl", run_curl(served, tmp_path / "curl"))


READ_ONLY_CLI = {
    "verify": lambda b: ["verify", b["ledger"]],
    "reconcile": lambda b: ["reconcile", b["tape_a"], b["tape_b"]],
    "evidence_pack_verify": lambda b: ["evidence-pack", "verify", b["pack"]],
}


def test_the_cli_exits_the_same_codes(served):
    """The read-only checks, run as `arcaeon <verb>` processes, exit as the body says."""
    bad = []
    for case in cases("cli"):
        build = READ_ONLY_CLI.get(case["method"])
        if build is None or case["http"] != 200 or case["name"].endswith(("_logged", "_built")):
            continue
        r = subprocess.run([sys.executable, "-m", "arcaeon", *build(case["body"])],
                           cwd=served.root, env=served.env, capture_output=True, timeout=120)
        if r.returncode != case["exit"]:
            bad.append(f"{case['name']}: arcaeon exited {r.returncode}, want {case['exit']}")
    assert not bad, "\n".join(bad)


def test_examples_md_has_not_drifted():
    r = subprocess.run([sys.executable, str(GEN), "--check"], capture_output=True, text=True,
                       timeout=60)
    assert r.returncode == 0, r.stderr


def test_one_example_per_free_route():
    gen = _gen()
    doc = gen.load()
    free = {o for o, (_, _, op) in gen.operations(doc).items()
            if op.get("x-arcaeon-tier") == "free"}
    shown = [s[1] for s in gen.STEPS if s[0] == "example"]
    assert sorted(shown) == sorted(free)
    text = EXAMPLES.read_text(encoding="utf-8")
    for s in gen.STEPS:
        if s[0] in ("setup", "example"):
            assert gen.curl_line(doc, s[1], s[2]) in text
    assert "/v1/seal\"" not in text          # the paid route is named, never exampled


def test_the_generator_refuses_a_bad_sample(monkeypatch):
    gen = _gen()
    doc = gen.load()
    monkeypatch.setattr(gen, "STEPS", [s if s[:2] != ("example", "verify")
                                       else ("example", "verify", {"ledgr": "x"}, s[3])
                                       for s in gen.STEPS])
    with pytest.raises(gen.Bad, match="ledgr"):
        gen.render(doc)
    monkeypatch.setattr(gen, "STEPS", [s for s in gen.STEPS if s[:2] != ("example", "status")])
    with pytest.raises(gen.Bad):
        gen.render(doc)


@pytest.mark.skipif(CURL is None, reason="curl is not on PATH: the examples cannot run here")
def test_every_curl_example_runs_against_the_server(served, tmp_path):
    gen = _gen()
    doc = gen.load()
    # The examples name files the table above never touches (no kh1_ prefix), so
    # they run in the one served root with no collision, curl started in it.
    work = served.root
    text = EXAMPLES.read_text(encoding="utf-8")
    bad = []
    for i, step in enumerate(gen.STEPS):
        kind = step[0]
        if kind == "file":
            (work / step[1]).write_text(step[2], encoding="utf-8")
            assert step[2].rstrip("\n") in text
            continue
        if kind == "cli":
            assert " ".join(step[1]) in text
            r = subprocess.run([sys.executable, "-m", "arcaeon", *step[1][1:]], cwd=work,
                               env=served.env, capture_output=True, timeout=120)
            if r.returncode != 0:
                bad.append(f"step {i} {' '.join(step[1])}: exit {r.returncode}")
            continue
        if kind == "python":
            assert gen.python_line(step[1]) in text
            r = subprocess.run([sys.executable, "-c", step[1]], cwd=work, capture_output=True,
                               timeout=60)
            if r.returncode != 0:
                bad.append(f"step {i} python: exit {r.returncode}: {r.stderr[-300:]!r}")
            continue
        oid, body = step[1], step[2]
        line = gen.curl_line(doc, oid, body)
        assert line in text
        argv = shlex.split(line)
        assert argv[0] == "curl"
        argv = [a.replace("$ARCAEON", served.url).replace("$TOKEN", served.token)
                for a in argv[1:]]
        status, raw = _curl(served, argv, work, tmp_path / f"answer_{i}")
        if status != 200:
            bad.append(f"step {i} {oid}: HTTP {status}")
            continue
        if oid == "index":
            if b"<html" not in raw.lower():
                bad.append(f"step {i} index: not an HTML page")
            continue
        ans = json.loads(raw.decode("utf-8"))
        if kind == "example":
            verdict, code = step[3]
            if code is not None and ans.get("exit") != code:
                bad.append(f"step {i} {oid}: exit {ans.get('exit')}, want {code}: {ans}")
            if verdict is not None and ans.get("verdict") != verdict:
                bad.append(f"step {i} {oid}: verdict {ans.get('verdict')}, want {verdict}")
        elif ans.get("exit") != 0:
            bad.append(f"step {i} setup {oid}: exit {ans.get('exit')}: {ans}")
    assert not bad, "\n".join(bad)


@pytest.mark.skip(reason="manual step: run this file inside `wsl -d Ubuntu-22.04` by hand "
                         "(see the module docstring); starting WSL from a test boots a VM "
                         "that outlives the test, and WSL loopback is not Windows loopback")
def test_wsl_half():
    pass
