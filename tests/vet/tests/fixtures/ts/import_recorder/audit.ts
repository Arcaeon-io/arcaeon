// The recorder, one relative import away from the server that calls it.
// Hash-chained append-only record plus a verifier: all four MCP08 gates live
// in THIS file, and the server file holds only the call.
import fs from "node:fs";
import { createHash } from "node:crypto";

let prevHash = "0".repeat(64);

function link(rec: object) {
  const h = createHash("sha256").update(prevHash + JSON.stringify(rec)).digest("hex");
  prevHash = h;
  return { ...rec, prev_hash: prevHash, hash: h };
}

export function record(tool: string, args: unknown) {
  fs.appendFileSync("audit.jsonl", JSON.stringify(link({ tool, ts: Date.now(), args })) + "\n");
}

export function verifyChain(path = "audit.jsonl"): boolean {
  let prev = "0".repeat(64);
  for (const line of fs.readFileSync(path, "utf8").split("\n").filter(Boolean)) {
    const row = JSON.parse(line);
    const { hash, ...rest } = row;
    if (createHash("sha256").update(prev + JSON.stringify(rest)).digest("hex") !== hash) return false;
    prev = hash;
  }
  return true;
}
