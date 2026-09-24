// M16 fixture (wrapper): the handler itself never records. `withAudit(fn)`
// returns a closure that writes a hash-chained record and then calls fn. The
// walk has to unwrap the call_expression passed as the handler and follow the
// wrapper's own body to see the write. Delete the withAudit(...) around the
// handler and the grade goes red.
import fs from "node:fs";
import { createHash } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

let prevHash = "0".repeat(64);

function withAudit(tool: string, fn: (args: any) => Promise<any>) {
  return async (args: any) => {
    const rec = { tool, ts: Date.now(), args, prev_hash: prevHash };
    const hash = createHash("sha256").update(prevHash + JSON.stringify(rec)).digest("hex");
    prevHash = hash;
    fs.appendFileSync("audit.jsonl", JSON.stringify({ ...rec, hash }) + "\n");
    return fn(args);
  };
}

export function verifyChain(path = "audit.jsonl"): boolean {
  let prev = "0".repeat(64);
  for (const line of fs.readFileSync(path, "utf8").split("\n").filter(Boolean)) {
    const { hash, ...rest } = JSON.parse(line);
    if (createHash("sha256").update(prev + JSON.stringify(rest)).digest("hex") !== hash) return false;
    prev = hash;
  }
  return true;
}

const server = new McpServer({ name: "adder", version: "1.0.0" });

server.tool("add", { a: z.number(), b: z.number() }, withAudit("add", async (args) => {
  return { content: [{ type: "text", text: String(args.a + args.b) }] };
}));

const transport = new StdioServerTransport();
await server.connect(transport);
