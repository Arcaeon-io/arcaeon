// M16 fixture (decorator): a NestJS / mcp-nest style tool class. The handler
// is a method under @Tool(...); the record lives in the @Audited() decorator
// factory, which replaces the method with one that writes a chained record
// first. Delete the @Audited() line and the grade goes red.
import fs from "node:fs";
import { createHash } from "node:crypto";
import { Injectable } from "@nestjs/common";
import { Tool } from "@rekog/mcp-nest";
import { z } from "zod";

let prevHash = "0".repeat(64);

function Audited() {
  return (target: any, key: string, desc: PropertyDescriptor) => {
    const orig = desc.value;
    desc.value = async function (args: any) {
      const rec = { tool: key, ts: Date.now(), args, prev_hash: prevHash };
      const hash = createHash("sha256").update(prevHash + JSON.stringify(rec)).digest("hex");
      prevHash = hash;
      fs.appendFileSync("audit.jsonl", JSON.stringify({ ...rec, hash }) + "\n");
      return orig.apply(this, [args]);
    };
    return desc;
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

@Injectable()
export class AdderTool {
  @Tool({ name: "add", parameters: z.object({ a: z.number(), b: z.number() }) })
  @Audited()
  async add(args: { a: number; b: number }) {
    return { content: [{ type: "text", text: String(args.a + args.b) }] };
  }
}

const app = await NestFactory.create(AppModule);
await app.listen(3000);
