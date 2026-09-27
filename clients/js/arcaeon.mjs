// SPDX-License-Identifier: MIT
// arcaeon.mjs: a zero-dependency JavaScript client for `arcaeon serve` (K017).
//
//   import { Client } from "./arcaeon.mjs";
//   const c = await Client.connect();          // reads serve.json + serve.token
//   const r = await c.verify({ ledger: "calls.jsonl" });
//   r.verdict, r.exit                          // "VERIFIED", 0
//
// fetch only, no packages. `Client.connect()` reads the url from
// <ARCAEON_HOME or ~/.arcaeon>/serve.json and the token from serve.token
// (Node, Deno and Bun; in a browser pass { url, token }). It never creates
// a token.
//
// NEVER A PASS BY ACCIDENT. A server that cannot be reached is COULD NOT
// LOOK, exit 3, reason_word "network". A reply that is not a JSON object is
// COULD NOT LOOK, reason_word "unreadable". A refusal the server sent (400,
// 401, 404, 405, 413) comes back as its body plus http_status, always with a
// non-zero exit (2 when the body names none). Methods resolve, never reject.
//
// THE TOKEN NEVER LEAVES LOOPBACK (K016R). The token read from serve.token
// goes only to a loopback host (127.x, ::1, localhost). To any other host no
// token is sent unless the caller passed { token } itself, and a plain
// http:// url to a non-loopback host is refused (exit 2, reason_word
// "insecure", nothing sent) unless { allowInsecure: true } is passed.

export const COULD_NOT_LOOK = "COULD NOT LOOK";
export const EXIT_USAGE = 2;
export const EXIT_COULD_NOT_LOOK = 3;
export const DEFAULT_TIMEOUT_MS = 60000;

// Client method name -> [HTTP method, route path]. Same routes as the
// Python client (arcaeon.client.ROUTE_METHODS), camelCase names.
export const ROUTE_METHODS = Object.freeze({
  health: ["GET", "/health"],
  openapi: ["GET", "/openapi.json"],
  log: ["POST", "/v1/log"],
  verify: ["POST", "/v1/verify"],
  reconcile: ["POST", "/v1/reconcile"],
  auditVerify: ["POST", "/v1/audit/verify"],
  auditExport: ["POST", "/v1/audit/export"],
  receiptVerify: ["POST", "/v1/receipt/verify"],
  status: ["GET", "/v1/status"],
  pin: ["POST", "/v1/pin"],
  seal: ["POST", "/v1/seal"],
  evidencePack: ["POST", "/v1/evidence-pack"],
  evidencePackVerify: ["POST", "/v1/evidence-pack/verify"],
  exportAat: ["POST", "/v1/export/aat"],
  mandateCheck: ["POST", "/v1/mandate/check"],
  readings: ["POST", "/v1/readings"],
  secondReadCompare: ["POST", "/v1/second-read/compare"],
  handshakePropose: ["POST", "/v1/handshake/propose"],
  handshakeAccept: ["POST", "/v1/handshake/accept"],
  handshakeVerify: ["POST", "/v1/handshake/verify"],
});

export function isLoopback(host) {
  if (!host) return false;
  const h = String(host).toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (h === "localhost" || h === "::1" || h === "0:0:0:0:0:0:0:1") return true;
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}

function couldNotLook(where, reasonWord, reason) {
  return { verdict: COULD_NOT_LOOK, exit: EXIT_COULD_NOT_LOOK,
           looked_for: "an arcaeon serve answer", where,
           reason_word: reasonWord, reason };
}

async function readHome() {
  // { url, token } from the serve files, each null when absent.
  let fs, path, os;
  try {
    fs = await import("node:fs/promises");
    path = await import("node:path");
    os = await import("node:os");
  } catch {
    return { url: null, token: null };
  }
  const env = (globalThis.process && globalThis.process.env) || {};
  const override = (env.ARCAEON_HOME || "").trim();
  const home = override || path.join(os.homedir(), ".arcaeon");
  let url = null;
  let token = null;
  try {
    const j = JSON.parse(await fs.readFile(path.join(home, "serve.json"), "utf8"));
    if (j && typeof j.url === "string" && j.url) url = j.url;
  } catch { /* no server recorded */ }
  try {
    token = (await fs.readFile(path.join(home, "serve.token"), "utf8")).trim() || null;
  } catch { /* no token yet */ }
  return { url, token };
}

export class Client {
  constructor({ url = null, token = null, timeoutMs = DEFAULT_TIMEOUT_MS,
                allowInsecure = false, homeToken = null } = {}) {
    this.url = url ? String(url).replace(/\/+$/, "") : null;
    // Not enumerable, so JSON.stringify(client) and console.log never show it.
    Object.defineProperty(this, "token", { value: token != null ? token : homeToken,
                                           writable: true, enumerable: false });
    Object.defineProperty(this, "tokenGiven", { value: token != null, writable: true,
                                                enumerable: false });
    this.timeoutMs = timeoutMs;
    this.allowInsecure = Boolean(allowInsecure);
  }

  // A client whose missing url and token are read from the serve files.
  static async connect(opts = {}) {
    const found = (opts.url && opts.token) ? {} : await readHome();
    return new Client({ ...opts, url: opts.url || found.url,
                        token: opts.token != null ? opts.token : null,
                        homeToken: found.token || null });
  }

  async call(method, path, body = null) {
    if (!this.url) {
      return couldNotLook(null, "network",
        "no server found: serve.json is absent (start `arcaeon serve`, or pass url)");
    }
    const where = this.url + path;
    if (!/^http:\/\/[^/]+/.test(this.url)) {
      return couldNotLook(where, "network", `not an http:// server url: ${this.url}`);
    }
    const host = new URL(this.url).hostname;
    const loopback = isLoopback(host);
    if (!loopback && !this.allowInsecure) {
      return { error: `refusing plain http:// to a non-loopback host ${host}: ` +
                      "pass allowInsecure: true to send anyway",
               exit: EXIT_USAGE, reason_word: "insecure", where };
    }
    const headers = { Accept: "application/json" };
    const init = { method, headers, redirect: "manual" };
    if (method !== "GET") {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body || {});
    }
    if (this.token && (loopback || this.tokenGiven)) headers.Authorization = `Bearer ${this.token}`;
    if (typeof AbortSignal !== "undefined" && AbortSignal.timeout) {
      init.signal = AbortSignal.timeout(this.timeoutMs);
    }
    let status;
    let text;
    try {
      const resp = await fetch(where, init);
      status = resp.status;
      text = await resp.text();
    } catch (e) {
      return couldNotLook(where, "network",
        `could not reach the server (${(e && e.name) || "Error"})`);
    }
    let out = null;
    try { out = JSON.parse(text); } catch { out = null; }
    if (!out || typeof out !== "object" || Array.isArray(out)) {
      return couldNotLook(where, "unreadable",
        `the server's answer (HTTP ${status}) is not a JSON object`);
    }
    if (status !== 200) {
      out.http_status = status;
      if (!Number.isInteger(out.exit) || out.exit === 0) out.exit = EXIT_USAGE;
    }
    return out;
  }
}

for (const [name, [method, path]] of Object.entries(ROUTE_METHODS)) {
  Client.prototype[name] = function (body = {}) {
    return this.call(method, path, method === "POST" ? body : null);
  };
}
