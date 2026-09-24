"""TS/JS front end for `audit-record`. Mirrors the Python check's rules; every
test names the rule it pins. Runs only when the [ts] extra is installed --
without it the front end must report NOT SCANNED, and the last test pins that."""
import pytest

from arcaeon.prove.vet import ts_checks as tc

pytestmark = pytest.mark.skipif(not tc.available(), reason="tree-sitter extra absent")

HEAD = '''
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import fs from "node:fs";
const server = new McpServer({ name: "x", version: "1" });
'''
TAIL = '''
const transport = new StdioServerTransport();
await server.connect(transport);
'''

# The TS front end ran TWO checks from 0.0.17 (2026-09-04, `except-returns-
# success` joined `audit-record`), so these assertions read the registry
# instead of a literal: a hand-kept copy of the check list is exactly the
# drift `checks.CHECKS` exists to prevent.
TS_CHECK_NAMES = [name for name, _ in tc.TS_CHECKS]


def _scan(body, rel="server.ts", head=HEAD, tail=TAIL):
    findings, ran = tc.scan_source_ts_ex(head + body + tail, rel)
    assert ran == TS_CHECK_NAMES
    return [f for f in findings if f.check == "audit-record"]


def _gate(fs):
    assert len(fs) == 1
    return fs[0]


# --- presence ----------------------------------------------------------------

def test_no_record_is_gate1_high():
    f = _gate(_scan('''
server.tool("add", { a: 1 }, async ({ a }) => {
  return { content: [{ type: "text", text: String(a) }] };
});
'''))
    assert f.severity == "high"
    assert f.gates["presence"] is False
    assert "gate 1 (presence)" in f.detail


def test_console_log_without_tool_name_is_not_a_record():
    f = _gate(_scan('''
server.tool("add", { a: 1 }, async ({ a }) => {
  console.log("called");
  return { content: [] };
});
'''))
    assert f.gates["presence"] is False


def test_logger_naming_the_tool_is_presence():
    f = _gate(_scan('''
server.tool("add", { a: 1 }, async ({ a }) => {
  logger.info({ tool: "add" }, "call");
  return { content: [] };
});
'''))
    assert f.gates["presence"] is True


def test_append_file_is_presence_only_when_bare():
    f = _gate(_scan('''
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  fs.appendFileSync("log.jsonl", "x\\n");
  return {};
});
'''))
    assert f.gates["presence"] is True
    assert f.gates["completeness"] is False
    assert "gate 2 (completeness)" in f.detail


def test_list_tools_handler_is_not_a_root():
    # Only tools/call answers "did the call leave a record". No CallTool handler,
    # no finding -- the file is not a server that handles calls.
    assert _scan('''
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [] }));
''') == []


def test_fragment_without_entrypoint_gets_no_finding():
    assert _scan('''
server.tool("add", { a: 1 }, async ({ a }) => ({ content: [] }));
''', tail="") == []


# --- reachability -------------------------------------------------------------

def test_record_two_hops_down_counts():
    f = _gate(_scan('''
function persist(rec) { fs.appendFileSync("audit.jsonl", JSON.stringify(rec) + "\\n"); }
const record = (name, args) => persist({ tool: name, ts: Date.now(), args });
server.tool("add", { a: 1 }, async (args) => {
  record("add", args);
  return { content: [] };
});
'''))
    assert f.gates["presence"] is True
    assert f.gates["completeness"] is True


def test_record_three_hops_down_is_not_seen():
    # Depth cap 2, same as the Python check. A record buried deeper is
    # unobserved, and unobserved is reported as absent -- with the depth stated
    # in the docstring, not hidden.
    f = _gate(_scan('''
function persist(rec) { fs.appendFileSync("audit.jsonl", JSON.stringify(rec)); }
function mid(rec) { persist(rec); }
function record(name) { mid({ tool: name, ts: Date.now() }); }
server.tool("add", { a: 1 }, async (args) => { record("add"); return { content: [] }; });
'''))
    assert f.gates["presence"] is False


def test_handler_passed_by_name_is_followed():
    f = _gate(_scan('''
async function handleCall(req) {
  fs.appendFileSync("audit.jsonl", JSON.stringify({ tool: req.params.name, at: new Date().toISOString(), args: req.params.arguments }));
  return {};
}
server.setRequestHandler(CallToolRequestSchema, handleCall);
'''))
    assert f.gates["completeness"] is True


# --- completeness / registration shapes --------------------------------------

def test_register_tool_and_add_tool_shapes():
    f = _gate(_scan('''
server.registerTool("sub", { inputSchema: {} }, async (args) => {
  audit.append({ toolName: "sub", timestamp: Date.now(), input: args });
  return { content: [] };
});
'''))
    assert f.gates["completeness"] is True
    assert "gate 3 (tamper-evidence)" in f.detail

    f = _gate(_scan('''
server.addTool({
  name: "mul",
  execute: async (args) => {
    db.insertOne({ tool: "mul", createdAt: new Date(), args });
    return "ok";
  },
});
'''))
    assert f.gates["completeness"] is True


def test_shorthand_properties_count_as_fields():
    f = _gate(_scan('''
server.tool("add", { a: 1 }, async (args) => {
  const tool = "add", ts = Date.now();
  fs.appendFileSync("a.jsonl", JSON.stringify({ tool, ts, args }));
  return { content: [] };
});
'''))
    assert f.gates["completeness"] is True


# --- tamper evidence / reconstructability -------------------------------------

def test_hash_chain_and_verify_clear_all_gates():
    assert _scan('''
import { createHash } from "node:crypto";
let prevHash = "0".repeat(64);
function link(rec) {
  const h = createHash("sha256").update(prevHash + JSON.stringify(rec)).digest("hex");
  prevHash = h;
  return { ...rec, prev_hash: prevHash, hash: h };
}
export function verifyChain(path) { return true; }
server.tool("add", { a: 1 }, async (args) => {
  fs.appendFileSync("audit.jsonl", JSON.stringify(link({ tool: "add", ts: Date.now(), args })) + "\\n");
  return { content: [] };
});
''') == []


def test_hmac_without_verify_stops_at_gate4():
    f = _gate(_scan('''
import { createHmac } from "node:crypto";
server.tool("add", { a: 1 }, async (args) => {
  const rec = { tool: "add", ts: Date.now(), args };
  const mac = createHmac("sha256", KEY).update(JSON.stringify(rec)).digest("hex");
  fs.appendFileSync("audit.jsonl", JSON.stringify({ ...rec, mac }));
  return { content: [] };
});
'''))
    assert f.gates["tamper_evidence"] is True
    assert f.gates["reconstructability"] is False
    assert f.severity == "low"


# --- mutation: the check must be able to go red -------------------------------

def test_mutation_removing_the_audit_line_flips_presence():
    good = '''
server.tool("add", { a: 1 }, async (args) => {
  fs.appendFileSync("audit.jsonl", JSON.stringify({ tool: "add", ts: Date.now(), args }));
  return { content: [] };
});
'''
    bad = good.replace('  fs.appendFileSync("audit.jsonl", JSON.stringify({ tool: "add", ts: Date.now(), args }));\n', "")
    assert bad != good
    assert _gate(_scan(good)).gates["presence"] is True
    assert _gate(_scan(bad)).gates["presence"] is False


# --- surface ------------------------------------------------------------------

def test_tsx_and_js_paths_parse():
    for rel in ("server.tsx", "server.js", "server.mjs"):
        assert tc.is_ts_path(rel)
        _gate(_scan('server.tool("add", { a: 1 }, async () => ({ content: [] }));\n', rel=rel))


def test_finding_shape_matches_python_check():
    d = _gate(_scan('server.tool("add", { a: 1 }, async () => ({ content: [] }));\n')).as_dict()
    assert set(d) >= {"check", "severity", "file", "line", "detail", "gates"}
    assert set(d["gates"]) == {"presence", "completeness", "tamper_evidence", "reconstructability"}


def test_grade_source_routes_ts_and_reports_only_what_ran():
    from arcaeon.prove.vet.grade import grade_source
    g = grade_source(HEAD + 'server.tool("add", { a: 1 }, async () => ({ content: [] }));\n' + TAIL, "server.ts")
    assert g.checks_run == TS_CHECK_NAMES            # the TS registry, never the Python battery
    assert g.verdict == "high-severity findings"


def test_unavailable_front_end_reports_not_scanned(monkeypatch):
    monkeypatch.setattr(tc, "_ts", None)
    findings, ran = tc.scan_source_ts_ex("server.tool('a', {}, () => {});", "s.ts")
    assert ran == []
    assert findings and findings[0].check == "parse"
