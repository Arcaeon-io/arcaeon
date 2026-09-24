"""mcp_vet — a checker for MCP-server code, WORK IN PROGRESS (2026-08-29).

NOT a vetting authority. Not a certification. A scanner that looks for a small
set of documented, high-signal failure classes in MCP server source and reports
what it finds, with the exact line. It runs against our OWN servers first
(.mcp.json) and publishes those findings before it ever points at a stranger's.

Failure classes (from the public MCP-security literature, mid-2026):
  - unsafe-exec : a tool handler reaches eval/exec/os.system/subprocess with
                  shell=True — arbitrary code execution surface.
  - ssrf        : a tool handler makes an outbound network call whose target is
                  (or may be) taken from tool input — server-side request forgery.
  - zero-auth   : the server binds a NETWORK transport (http/sse) with no auth
                  hook in sight — anyone who reaches the port drives the tools.
  - secret-in-code : a credential sitting in the source at rest (OWASP MCP01).
  - audit-record: a served tool call that leaves no verifiable record behind
                  (OWASP MCP08). Four gates — presence, completeness,
                  tamper-evidence, reconstructability — one finding per
                  server, severity set by the first gate not met. The only
                  class here that can come back clean as a COMPLIMENT.
  - unreceipted-allow: a gate function whose block/deny path is receipted
                  (hash/digest/audit field) and whose allow/pass path is not
                  — every permitted action unreplayable, only refusals
                  provable. NOT an official OWASP MCP Top 10 number; a
                  specific bug shape inside MCP08's territory.
  - unsafe-deser: pickle/marshal/yaml.load-without-SafeLoader on data a tool
                  handler did not produce — arbitrary object construction.
  - path-traversal: a filesystem path built from tool input with no
                  containment check — read/write outside the served root.
  - except-returns-success: an exception handler on a tool-reachable path
                  returns a success shape ([] / {} / "" / True / a None-free
                  literal) with no error marker, so a failure is handed to the
                  agent as an answer. Python and TypeScript. Excluded: a
                  literal carrying its own error marker, a documented
                  polarity, a handler that re-raises or returns the caught
                  exception. Measured on six real MCP servers before it
                  shipped (ORIGIN.md).

Design stance: HIGH PRECISION over recall while WIP. A false red on a stranger
costs the reputation this whole line is built on (R1's named risk), so every
finding names its line and the checker is judged first on our own code, where a
false positive costs nothing and tunes the tool.
"""
__version__ = "0.0.17"
