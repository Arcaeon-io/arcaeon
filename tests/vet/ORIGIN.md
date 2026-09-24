# Origin

<!-- attribution wording is Daniel's call; default is the public alias -->

**Origin note, September 2026.** The "third verdict" (a check with only two
outcomes cannot report that it could not look, and converts its own failure into
a finding) and the "wrong-layer positive control" (a passing control that
exercises the channel but not the binding launders a false absence) were first
stated and instrumented by Nora / Arcaeon on 2026-09-03 and 2026-09-04, in the
theory note THIRD_VERDICT_THEORY_2026-09-03 and scar 161, with the detectors
`negative_control_audit.py` and `vacuous_pass_lint.py`. The borrowed-index
principle (an index that has to already know what it is hunting is the wrong
index) was arrived at jointly with colonist-one and deep-seeker in the same
week, and is credited to that exchange.

**Measured before it shipped, 2026-09-04.** The rule family was run against six
real MCP servers (66,909 non-test lines across modelcontextprotocol/servers
filesystem, memory, git and fetch, supabase-community/supabase-mcp, and
sooperset/mcp-atlassian) and all 196 hits were opened by hand. The family as a
whole scored 21 real of 196 (10.7%) and FAILED its 30% gate; one idiom cleared
it alone, "an exception handler returns a success-shaped value that reaches a
tool result with no error marker", at 20 real of 57 opened (35.1%). That one
idiom is what became the `except-returns-success` check and it is the only part
of the family in this package. The other six (except-swallow 1 real of 101,
all-empty 0 of 22, default-true 0 of 8, except-true 0 of 3, absence-pass 0 of 3,
catch-null 0 of 2) were measured and deliberately not shipped.

**Reproduction, same day, stated plainly.** The 35.1% above is the idiom's
number from the scratch harness, not this check's. Run on the same six repos on
2026-09-04, the shipped check fired ONCE and reproduced 1 of the 20 real
findings: the other 19 lived in mcp-atlassian fetcher classes the reachability
walk never entered, because it could not follow an instance returned from a call
(`jira = await get_jira_fetcher(ctx)`), and the git and fetch servers'
`@server.call_tool()` handlers were not recognised as handlers at all.
Record: `projects/online_business/mcp_vet_rule_reproduction_2026-09-04.md`.

**Runtime truth, same night (2026-09-04).** Static reachability is a proxy for the
question that matters: does a dependency failure reach the tool's caller as an
error, or as a success? All 27 findings the shipped check produces on the six
repos were driven at runtime with a real failure injected under them (HTTP
layer replaced before any socket call; the filesystem server run as a child
process with `fs.stat` made to throw). 24 of 27 could be reached. Of those, 22
returned a success shape to the tool caller (empty list, a created-issue
message with the wrong body, a 0 B file with no error flag) and 2 raised. So
against the runtime truth the check's precision on the sites a harness could
drive is 22 of 24. Three sites could not be driven: two are shadowed by a
sibling site that swallows the same failure one layer down, one is a dead
except over `.get()` calls. The 27 findings sit on 18 distinct try blocks, so
the count overstates the number of independent defects. One hand-read false
was wrong the other way: `jira/client.py:327` is silent at runtime. Record with
per-site verdicts: `projects/online_business/mcp_runtime_observability_2026-09-04.json`.


**Reproduction, after the reachability fix (same day).** The walk now binds a
local to the class a factory returns and resolves a method call on it, and the
low-level `@server.call_tool()` decorator is recognised as a handler root. Re-run
on the same six trees, the check fires **27 times**, up from 1. Of gate 2's 20
real findings, 11 are recoverable from its record by file:line and **9 of those
11 are reproduced exactly**; the two that are not are a body no tool handler
reaches at all (`jira/worklog.py:182`, whose only caller is itself uncalled) and
one three call hops down behind a property-held adapter
(`confluence/v2_adapter.py:300`), which the two-hop cap confesses. Of the 53
candidate hits gate 2 drew its 19 mcp-atlassian reals from, **24 now fire**
(0 did before). All 27 findings were opened by hand: **24 real, 3 false** (88.9%).
The three false are one degraded-but-faithful fallback and two fail-closed
guards whose polarity is stated in a log message rather than a comment, which is
where exclusion (b) cannot read. Record:
`projects/online_business/mcp_vet_reachability_fix_2026-09-04.md`.

Gate record: `projects/online_business/GATE2_THIRD_VERDICT_MCP_SERVERS_2026-09-04.md`.
