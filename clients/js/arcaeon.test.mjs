// SPDX-License-Identifier: MIT
// node --test clients/js/arcaeon.test.mjs
// Spawns `python -m arcaeon serve --port 0` on loopback, reads the printed
// url, and checks a fixture ledger through the JS client. No other network.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Client, ROUTE_METHODS, isLoopback } from "./arcaeon.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SRC = join(REPO, "src");

function python() {
  // An interpreter path, not the `py` launcher, so kill() stops the server itself.
  if (process.env.ARCAEON_PYTHON) return process.env.ARCAEON_PYTHON;
  const launcher = process.platform === "win32" ? "py" : "python3";
  return execFileSync(launcher, ["-c", "import sys; print(sys.executable)"],
                      { encoding: "utf8" }).trim();
}

const PY = python();
const TMP = mkdtempSync(join(tmpdir(), "arcaeon-js-"));
const HOME = join(TMP, "home");
const ROOT = join(TMP, "served");
mkdirSync(ROOT, { recursive: true });
const ENV = { ...process.env, ARCAEON_HOME: HOME, ARCAEON_JOURNAL: "0",
              PYTHONPATH: SRC };
delete ENV.ARCAEON_KEY;
process.env.ARCAEON_HOME = HOME;       // Client.connect() reads the serve files here

let child;
let url;

before(async () => {
  child = spawn(PY, ["-m", "arcaeon", "serve", "--port", "0", "--root", ROOT],
                { env: ENV, cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] });
  url = await new Promise((ok, fail) => {
    let buf = "";
    const timer = setTimeout(() => fail(new Error("server did not print its url")), 30000);
    child.stdout.on("data", (d) => {
      buf += d;
      const m = buf.match(/listening on (http:\/\/127\.0\.0\.1:\d+)/);
      if (m) { clearTimeout(timer); ok(m[1]); }
    });
    child.on("exit", (code) => { clearTimeout(timer); fail(new Error(`serve exited ${code}`)); });
  });
});

after(async () => {
  if (child && child.exitCode === null) {
    const gone = new Promise((r) => child.once("exit", r));
    child.kill();
    await gone;
  }
  rmSync(TMP, { recursive: true, force: true });
});

function freePort() {
  return new Promise((ok) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => ok(p)); });
  });
}

test("every route but the dashboard has a method", () => {
  const out = execFileSync(PY, ["-c",
    "import json; from arcaeon.serve.routes import ROUTES; " +
    "print(json.dumps(sorted([r.method, r.path] for r in ROUTES if r.path != '/')))"],
    { env: ENV, encoding: "utf8" });
  const want = JSON.parse(out);
  const got = Object.values(ROUTE_METHODS).map((x) => [...x]).sort((a, b) =>
    (a[0] + a[1]) < (b[0] + b[1]) ? -1 : 1);
  const key = (xs) => xs.map((x) => x.join(" ")).sort();
  assert.deepEqual(key(got), key(want));
});

test("connect() reads serve.json and the token, then verifies a fixture", async () => {
  const c = await Client.connect();
  assert.equal(c.url, url);
  assert.ok(c.token);
  assert.deepEqual(await c.health(), { ok: true });
  assert.equal((await c.log({ ledger: "fixture.jsonl", fields: { n: 1 } })).exit, 0);
  assert.equal((await c.log({ ledger: "fixture.jsonl", row: { n: 2 } })).exit, 0);
  const r = await c.verify({ ledger: "fixture.jsonl" });
  assert.equal(r.verdict, "VERIFIED");
  assert.equal(r.rows, 2);
  assert.equal(r.exit, 0);
  assert.equal(r.http_status, undefined);
});

test("one edited byte is BROKEN, exit 1", async () => {
  const c = await Client.connect();
  await c.log({ ledger: "t.jsonl", fields: { n: 1 } });
  await c.log({ ledger: "t.jsonl", fields: { n: 2 } });
  const p = join(ROOT, "t.jsonl");
  writeFileSync(p, readFileSync(p, "utf8").replace('"n": 1', '"n": 7'));
  const r = await c.verify({ ledger: "t.jsonl" });
  assert.equal(r.verdict, "BROKEN");
  assert.equal(r.exit, 1);
});

test("a missing ledger is COULD NOT LOOK in a 200 body", async () => {
  const r = await (await Client.connect()).verify({ ledger: "nope.jsonl" });
  assert.equal(r.verdict, "COULD NOT LOOK");
  assert.equal(r.exit, 3);
});

test("refusals carry http_status and never exit 0", async () => {
  const bad = await new Client({ url, token: "wrong" }).verify({ ledger: "x.jsonl" });
  assert.equal(bad.http_status, 401);
  assert.equal(bad.exit, 2);
  const out = await (await Client.connect()).verify({ ledger: "../x.jsonl" });
  assert.equal(out.http_status, 400);
  assert.notEqual(out.exit, 0);
});

test("the token is not in JSON.stringify(client)", async () => {
  const c = await Client.connect();
  assert.ok(!JSON.stringify(c).includes(c.token));
});

test("no server is network COULD NOT LOOK, never a rejection", async () => {
  const r = await new Client({ url: `http://127.0.0.1:${await freePort()}`, token: "t",
                               timeoutMs: 5000 }).verify({ ledger: "x.jsonl" });
  assert.equal(r.verdict, "COULD NOT LOOK");
  assert.equal(r.exit, 3);
  assert.equal(r.reason_word, "network");
  const none = await new Client().verify({ ledger: "x.jsonl" });
  assert.equal(none.reason_word, "network");
});

// K016R: the serve token never leaves loopback. fetch is swapped for a
// recorder, so nothing goes anywhere.
async function recorded(fn) {
  const seen = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (u, init) => {
    seen.push({ u, headers: init.headers });
    return new Response('{"verdict": "VERIFIED", "exit": 0}', { status: 200 });
  };
  try { await fn(); } finally { globalThis.fetch = real; }
  return seen;
}

test("loopback hosts are loopback, others are not", () => {
  for (const h of ["127.0.0.1", "127.0.0.9", "localhost", "[::1]", "::1"]) assert.ok(isLoopback(h), h);
  for (const h of ["example.invalid", "10.0.0.1", "127.example.com", ""]) assert.ok(!isLoopback(h), h);
});

test("the home token never goes to another host", async () => {
  const seen = await recorded(async () => {
    const c = new Client({ url: "http://example.invalid:8787", homeToken: "home-secret",
                           allowInsecure: true });
    assert.equal((await c.verify({ ledger: "x" })).exit, 0);
  });
  assert.equal(seen.length, 1);
  assert.equal(seen[0].headers.Authorization, undefined);
});

test("an explicit token goes where the caller sends it", async () => {
  const seen = await recorded(async () => {
    await new Client({ url: "http://example.invalid:8787", token: "mine",
                       allowInsecure: true }).verify({ ledger: "x" });
  });
  assert.equal(seen[0].headers.Authorization, "Bearer mine");
});

test("plain http to another host is refused unless allowed", async () => {
  const seen = await recorded(async () => {
    for (const token of [null, "mine"]) {
      const r = await new Client({ url: "http://example.invalid:8787", token,
                                   homeToken: "home-secret" }).verify({ ledger: "x" });
      assert.equal(r.exit, 2);
      assert.equal(r.reason_word, "insecure");
    }
  });
  assert.equal(seen.length, 0);
});
