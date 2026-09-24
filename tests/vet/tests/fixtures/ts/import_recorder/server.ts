// M15 fixture: the handler records, but the recorder lives in ./audit.ts.
// Graded alone (no resolver) this file shows an audit-record finding, because
// nothing IN the file writes anything. Graded as a tree, the import resolves
// to the sibling and the handler is clean.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { record } from "./audit.js";

const server = new McpServer({ name: "adder", version: "1.0.0" });

server.tool("add", { a: z.number(), b: z.number() }, async (args) => {
  record("add", args);
  return { content: [{ type: "text", text: String(args.a + args.b) }] };
});

const transport = new StdioServerTransport();
await server.connect(transport);
