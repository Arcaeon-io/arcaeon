"""`except-returns-success`: the one third-verdict idiom that cleared gate 2.

Gate 2 (2026-09-04, projects/online_business/GATE2_THIRD_VERDICT_MCP_SERVERS_
2026-09-04.md) opened all 196 hits of the wider "vacuous pass" family by hand
across six real MCP servers and 66,909 non-test lines. This idiom scored 20 real
of 57 opened (35.1%); the other six idioms scored 1 real across 139 and are NOT
shipped. Both halves are pinned here: the shapes that must fire, and the shapes
the gate said to leave alone.

Every branch of the rule gets a must-hit AND a must-miss, and every must-miss
carries a minimally different control that DOES fire, so a zero proves the
exclusion rather than an inert fixture. The must-hits are modelled on the named
real cases: mcp-atlassian `jira/projects.py:49` (a fetcher a tool calls turns a
caught exception into `[]`) and modelcontextprotocol/servers
`src/filesystem/index.ts:500` (a failed `stat` reported as a zero-byte file
dated 1970).

DEMOTED 2026-09-05 (board row 227): "modelled on" means written by me in the
shape the check already handles, which proves the check handles my shape. The
must-hit for the mcp-atlassian case is now the VERBATIM pinned code in
test_except_returns_success_verbatim.py (fixtures/mcp_atlassian_4067d1d, MIT).
The `_atlassian_tree` miniature below stays as a regression guard for the
resolver's individual steps (factory call, annotated return, mixin hop,
except-site location), each of which it isolates better than the real file.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from arcaeon.prove.vet.checks import (check_names, except_success_coverage,  # noqa: E402
                            scan_source)
from arcaeon.prove.vet import ts_checks as tc  # noqa: E402

needs_ts = pytest.mark.skipif(not tc.available(),
                              reason="tree-sitter [ts] extra not installed")

CHECK = "except-returns-success"
HDR = "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"


def _hits(src):
    return [f for f in scan_source(src, "t.py") if f.check == CHECK]


def _ts_hits(src, rel="index.ts"):
    findings, _ran = tc.scan_source_ts_ex(src, rel)
    return [f for f in findings if f.check == CHECK]


def _line_of(src, needle):
    for i, line in enumerate(src.splitlines(), start=1):
        if needle in line:
            return i
    raise AssertionError("fixture does not contain %r" % needle)


# --- the registry ------------------------------------------------------------

def test_the_check_is_registered_on_both_front_ends():
    """An unregistered check is an artifact with no reader. Both front ends run
    it, and the receipts read the registries, not a literal."""
    assert CHECK in check_names()
    assert CHECK in [name for name, _ in tc.TS_CHECKS]


# --- Python: the must-hit ----------------------------------------------------

# mcp-atlassian's house style, the shape behind 19 of the 21 real hits: the
# fetcher catches bare Exception, logs, and hands back an empty list. The tool
# wrapper's own careful except-clause never fires, because the failure was
# already converted one layer down.
ATLASSIAN = HDR + '''
import json
import logging

logger = logging.getLogger(__name__)


def get_all_projects():
    try:
        return _client.get("/rest/api/3/project")
    except Exception:
        logger.error("failed to fetch projects")
        return []


@mcp.tool()
def projects():
    return json.dumps(get_all_projects())
'''


def test_fetcher_a_tool_calls_returning_empty_list_fires():
    fs = _hits(ATLASSIAN)
    assert fs, "the mcp-atlassian shape must fire"
    assert fs[0].severity == "medium", fs
    assert fs[0].line == _line_of(ATLASSIAN, "        return []"), fs
    assert "no error marker" in fs[0].detail


def test_direct_handler_shapes_fire():
    """The same conversion written inline in the handler, one shape per line of
    the success-shape definition."""
    for value in ("[]", "{}", '""', "True", "list()", "dict()",
                  '{"projects": []}', "json.dumps([])"):
        src = HDR + ("@mcp.tool()\ndef f(a):\n    import json\n    try:\n"
                     "        return _go(a)\n    except Exception:\n"
                     "        return %s\n" % value)
        assert _hits(src), value


# --- Python: exclusion (a), the literal carries an error marker --------------

# jira/attachments.py, five hits: the exact OPPOSITE of the defect. A handler
# reporting its third verdict must never be told it is hiding one.
ERROR_MARKER = HDR + '''
@mcp.tool()
def upload(path):
    try:
        return _upload(path)
    except Exception as exc:
        msg = str(exc)
        return {"success": False, "error": msg}
'''
# Minimally different control: the same return with the marker taken out.
ERROR_MARKER_CONTROL = HDR + '''
@mcp.tool()
def upload(path):
    try:
        return _upload(path)
    except Exception:
        return {"success": True}
'''


def test_error_marker_in_the_literal_is_silent():
    assert _hits(ERROR_MARKER) == []


def test_error_marker_control_fires():
    assert _hits(ERROR_MARKER_CONTROL), "the 0 above must come from the marker"


def test_each_error_marker_key_excludes_on_its_own():
    for value in ('{"error": msg}', '{"isError": True}', '{"errors": [msg]}',
                  '{"success": False}', '{"ok": False}'):
        src = HDR + ("@mcp.tool()\ndef f(a):\n    try:\n        return _go(a)\n"
                     "    except Exception:\n        return %s\n" % value)
        assert _hits(src) == [], value


# --- Python: exclusion (b), the polarity is documented ----------------------

# All three of the lint's own gate-2 hits were this: `return True` where True is
# the SAFE answer, with the author's reasoning sitting right there.
DOCUMENTED = HDR + '''
@mcp.tool()
def delete_property(key):
    try:
        return _delete(key)
    except NotFound:
        # A 404 means the property is already absent, which is the requested
        # end state, so True here is fail-closed on purpose.
        return True
'''
# Minimally different control: the same return, nobody ever justified it.
DOCUMENTED_CONTROL = HDR + '''
@mcp.tool()
def delete_property(key):
    try:
        return _delete(key)
    except NotFound:
        return True
'''


def test_documented_polarity_is_silent():
    assert _hits(DOCUMENTED) == []


def test_undocumented_same_return_fires():
    assert _hits(DOCUMENTED_CONTROL), "the 0 above must come from the comment"


def test_polarity_stated_in_the_returned_value_counts():
    """Ported behaviour: polarity documented in a returned string is documented.
    A five-line comment is not the only way to say it."""
    src = HDR + ('@mcp.tool()\ndef f(a):\n    try:\n        return _go(a)\n'
                 '    except Exception:\n'
                 '        return {"note": "index unavailable, refusing to guess"}\n')
    assert _hits(src) == []


# --- Python: exclusion (c), the failure is reported, not converted ----------

RERAISE = HDR + '''
@mcp.tool()
def fetch(url):
    try:
        return _get(url)
    except Exception:
        _log()
        raise
'''
EXC_MESSAGE = HDR + '''
@mcp.tool()
def fetch(url):
    try:
        return _get(url)
    except Exception as e:
        return {"detail": str(e)}
'''
# Minimally different control for both: same handler, neither raising nor
# handing the exception back.
REPORTED_CONTROL = HDR + '''
@mcp.tool()
def fetch(url):
    try:
        return _get(url)
    except Exception as e:
        _log(e)
        return []
'''


def test_reraising_handler_is_silent():
    assert _hits(RERAISE) == []


def test_returning_the_caught_exception_is_silent():
    assert _hits(EXC_MESSAGE) == []


def test_swallowing_control_fires():
    assert _hits(REPORTED_CONTROL), "the two 0s above must come from the exclusion"


# --- Python: reachability ---------------------------------------------------

# Section 6: the same `return []` in a helper no tool reaches is a contract, not
# a lie, and that is where the gate's 25 arguable hits lived.
UNREACHABLE = HDR + '''
def helper():
    try:
        return _go()
    except Exception:
        return []


@mcp.tool()
def unrelated(x):
    return x
'''
REACHABLE_CONTROL = HDR + '''
def helper():
    try:
        return _go()
    except Exception:
        return []


@mcp.tool()
def uses(x):
    return helper()
'''


def test_helper_no_tool_reaches_is_silent():
    assert _hits(UNREACHABLE) == []


def test_same_helper_called_by_a_tool_fires():
    assert _hits(REACHABLE_CONTROL), "the 0 above must come from reachability"


def test_a_file_with_no_tool_handler_is_never_asked():
    src = ("def helper():\n    try:\n        return _go()\n"
           "    except Exception:\n        return []\n")
    assert _hits(src) == []


# --- Python: a modelled third state is not a success shape ------------------

# supabase-mcp api-platform.ts:381 in Python spelling: the field is None
# precisely BECAUSE the lookup did not run. That is the pattern done right.
THIRD_STATE = HDR + '''
@mcp.tool()
def keys():
    try:
        return {"legacy_keys_enabled": _lookup()}
    except Exception:
        return {"legacy_keys_enabled": None}
'''
THIRD_STATE_CONTROL = HDR + '''
@mcp.tool()
def keys():
    try:
        return {"legacy_keys_enabled": _lookup()}
    except Exception:
        return {"legacy_keys_enabled": False}
'''


def test_none_in_the_literal_reads_as_a_third_state():
    assert _hits(THIRD_STATE) == []


def test_a_flat_false_in_the_same_slot_fires():
    assert _hits(THIRD_STATE_CONTROL), "the 0 above must come from the None"


def test_returning_none_is_not_a_success_shape():
    """catch-null scored 0 real of 2 at gate 2. Not our idiom."""
    src = HDR + ("@mcp.tool()\ndef f(a):\n    try:\n        return _go(a)\n"
                 "    except Exception:\n        return None\n")
    assert _hits(src) == []


# --- Python: the six idioms gate 2 said NOT to ship --------------------------

def test_the_family_members_that_failed_the_gate_are_not_shipped():
    """1 real hit across 139 opened. Shipping them would put noise on a
    stranger's file, which is the one cost this project cannot pay. If any of
    these starts firing, someone widened the rule past its evidence."""
    swallow = HDR + ("@mcp.tool()\ndef f(a):\n    try:\n        _go(a)\n"
                     "    except Exception:\n        pass\n    return 1\n")
    all_empty = HDR + ("@mcp.tool()\ndef f(rows):\n"
                       "    ok = all(r.valid for r in rows)\n    return ok\n")
    default_true = HDR + ("@mcp.tool()\ndef f(cfg):\n"
                          "    ok = cfg.get('ok', True)\n    return ok\n")
    for src in (swallow, all_empty, default_true):
        assert _hits(src) == [], src


# --- coverage ----------------------------------------------------------------

def test_coverage_counts_what_was_actually_examined():
    c = except_success_coverage(ATLASSIAN, "t.py")
    assert c["tool_handlers"] == 1
    assert c["bodies_examined"] == 2          # the handler and the fetcher it calls
    assert c["except_handlers_examined"] == 1
    assert c["files_unparsed"] == 0


def test_coverage_separates_nothing_found_from_nothing_looked_at():
    """A file with no tool handler and a file with a clean handler both produce
    zero findings. The counts are what tells them apart."""
    no_handler = except_success_coverage(
        "def helper():\n    try:\n        return _go()\n"
        "    except Exception:\n        return []\n", "t.py")
    clean = except_success_coverage(
        HDR + "@mcp.tool()\ndef f(a):\n    try:\n        return _go(a)\n"
              "    except Exception:\n        raise\n", "t.py")
    assert no_handler["tool_handlers"] == 0
    assert no_handler["except_handlers_examined"] == 0
    assert clean["tool_handlers"] == 1
    assert clean["except_handlers_examined"] == 1


def test_coverage_counts_a_file_it_could_not_parse():
    assert except_success_coverage("def broken(:\n    pass\n", "t.py")["files_unparsed"] == 1


def test_the_scan_summary_prints_the_counts(tmp_path, capsys):
    from arcaeon.prove.vet.__main__ import main
    p = tmp_path / "server.py"
    p.write_text(ATLASSIAN, encoding="utf-8")
    main(["scan", str(p)])
    out = capsys.readouterr().out
    assert "except-returns-success coverage:" in out
    assert "1 tool handler(s)" in out
    assert "0 file(s) could not be parsed" in out
    # The dedup said out loud: findings are per SITE, and the handler count is a
    # different number that must never be read as the finding count.
    assert "1 site(s) via 1 handler(s)" in out, out


# --- TypeScript --------------------------------------------------------------

TS_HEAD = '''
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
const server = new McpServer({ name: "fs", version: "1" });
'''
TS_TAIL = '''
const transport = new StdioServerTransport();
await server.connect(transport);
'''

# modelcontextprotocol/servers src/filesystem/index.ts:500. A stat failure
# (permissions, a vanished file, a broken symlink) is listed as a zero-byte file
# dated 1970 and folded into the "Combined size" total.
TS_FILESYSTEM = TS_HEAD + '''
server.tool("list_directory_with_sizes", async ({ path }) => {
  const entries = await fs.readdir(path, { withFileTypes: true });
  const detailed = await Promise.all(entries.map(async (entry) => {
    try {
      const stats = await fs.stat(join(path, entry.name));
      return { name: entry.name, size: stats.size, mtime: stats.mtime };
    } catch {
      return { name: entry.name, size: 0, mtime: new Date(0) };
    }
  }));
  return { content: [{ type: "text", text: format(detailed) }] };
});
''' + TS_TAIL


@needs_ts
def test_ts_stat_failure_reported_as_a_zero_byte_file_fires():
    fs = _ts_hits(TS_FILESYSTEM)
    assert fs, "the filesystem index.ts shape must fire"
    assert fs[0].severity == "medium"
    assert fs[0].line == _line_of(TS_FILESYSTEM, "size: 0"), fs
    assert "no isError/error key" in fs[0].detail


@needs_ts
def test_ts_error_key_is_silent_and_its_control_fires():
    marked = TS_HEAD + '''
server.tool("x", async (a) => {
  try { return await go(a); }
  catch (e) { return { isError: true, content: [] }; }
});
''' + TS_TAIL
    control = TS_HEAD + '''
server.tool("x", async (a) => {
  try { return await go(a); }
  catch (e) { return { content: [] }; }
});
''' + TS_TAIL
    assert _ts_hits(marked) == []
    assert _ts_hits(control)


@needs_ts
def test_ts_documented_polarity_is_silent_and_its_control_fires():
    documented = TS_HEAD + '''
server.tool("x", async (a) => {
  try { return await go(a); }
  catch {
    // The entry is already gone, which is the requested end state, so an empty
    // list here is fail-closed on purpose.
    return [];
  }
});
''' + TS_TAIL
    control = TS_HEAD + '''
server.tool("x", async (a) => {
  try { return await go(a); }
  catch {
    return [];
  }
});
''' + TS_TAIL
    assert _ts_hits(documented) == []
    assert _ts_hits(control)


@needs_ts
def test_ts_rethrow_and_returned_error_are_silent_and_the_control_fires():
    rethrow = TS_HEAD + '''
server.tool("x", async (a) => {
  try { return await go(a); }
  catch (e) { log(e); throw e; }
});
''' + TS_TAIL
    returns_error = TS_HEAD + '''
server.tool("x", async (a) => {
  try { return await go(a); }
  catch (e) { return { detail: String(e) }; }
});
''' + TS_TAIL
    control = TS_HEAD + '''
server.tool("x", async (a) => {
  try { return await go(a); }
  catch (e) { log(e); return []; }
});
''' + TS_TAIL
    assert _ts_hits(rethrow) == []
    assert _ts_hits(returns_error) == []
    assert _ts_hits(control)


@needs_ts
def test_ts_unreachable_helper_is_silent_and_the_reachable_one_fires():
    unreachable = TS_HEAD + '''
function helper() { try { return go(); } catch { return []; } }
server.tool("x", async (a) => { return { content: [] }; });
''' + TS_TAIL
    reachable = TS_HEAD + '''
function helper() { try { return go(); } catch { return []; } }
server.tool("x", async (a) => { return helper(); });
''' + TS_TAIL
    assert _ts_hits(unreachable) == []
    assert _ts_hits(reachable)


@needs_ts
def test_ts_modelled_third_state_is_silent_and_the_flat_false_fires():
    """supabase-mcp api-platform.ts:381: `undefined` when the lookup did not
    run, with `disabled` deliberately omitted. The pattern done right."""
    third_state = TS_HEAD + '''
server.tool("x", async (a) => {
  try { return { legacyKeysEnabled: await go(a) }; }
  catch { return { legacyKeysEnabled: undefined }; }
});
''' + TS_TAIL
    control = TS_HEAD + '''
server.tool("x", async (a) => {
  try { return { legacyKeysEnabled: await go(a) }; }
  catch { return { legacyKeysEnabled: false }; }
});
''' + TS_TAIL
    assert _ts_hits(third_state) == []
    assert _ts_hits(control)


@needs_ts
def test_ts_catch_with_no_tool_handler_is_never_asked():
    src = "function helper() { try { return go(); } catch { return []; } }\n"
    assert _ts_hits(src) == []


# --- reachability through an instance a factory returned ---------------------
#
# Added 2026-09-04 after the reproduction run
# (projects/online_business/mcp_vet_rule_reproduction_2026-09-04.md) measured
# the shipped rule at 1 of gate 2's 20 real findings. The whole miss was one
# shape: a tool handler that never names the class doing the work.
#
#     jira = await get_jira_fetcher(ctx)
#     projects = jira.get_all_projects(include_archived=include_archived)
#
# 52 of the 53 candidate bodies on mcp-atlassian sat behind exactly that, so
# jira/projects.py, jira/fields.py, jira/worklog.py, confluence/comments.py and
# confluence/v2_adapter.py were each entered ZERO times. The fixture below is
# that server in miniature, four files deep, because the shape only exists
# across a file boundary: inside one file the resolver's short-name fallback
# already reaches the method and the fixture would prove nothing.

def _atlassian_tree(root, factory_call="jira = await get_jira_fetcher(ctx)"):
    """Write the mcp-atlassian layering under `root` and return the directory
    the graded file lives in (its `package_dir`).

      pkg/servers/jira.py          the @mcp.tool() handler
      pkg/servers/dependencies.py  async def get_jira_fetcher(ctx) -> JiraFetcher
      pkg/jira/__init__.py         class JiraFetcher(ProjectsMixin)
      pkg/jira/projects.py         the mixin whose except handler returns []
    """
    servers = root / "pkg" / "servers"
    jira = root / "pkg" / "jira"
    servers.mkdir(parents=True)
    jira.mkdir(parents=True)
    (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (servers / "__init__.py").write_text("", encoding="utf-8")
    (jira / "projects.py").write_text(
        "import logging\n\nlogger = logging.getLogger(__name__)\n\n\n"
        "class ProjectsMixin:\n"
        "    def get_all_projects(self, include_archived=False):\n"
        "        try:\n"
        "            return self.jira.projects(archived=include_archived)\n"
        "        except Exception as e:\n"
        "            logger.error(f'Error getting all projects: {str(e)}')\n"
        "            return []\n", encoding="utf-8")
    (jira / "__init__.py").write_text(
        "from .projects import ProjectsMixin\n\n\n"
        "class JiraFetcher(ProjectsMixin):\n    pass\n", encoding="utf-8")
    (servers / "dependencies.py").write_text(
        "from pkg.jira import JiraFetcher\n\n\n"
        "async def get_jira_fetcher(ctx) -> JiraFetcher:\n"
        "    return ctx.request_context.lifespan_context.jira\n", encoding="utf-8")
    (servers / "jira.py").write_text(
        HDR + "from pkg.servers.dependencies import get_jira_fetcher\n\n\n"
        "@mcp.tool()\n"
        "async def get_all_projects(ctx, include_archived: bool = False):\n"
        "    " + factory_call + "\n"
        "    projects = jira.get_all_projects(include_archived=include_archived)\n"
        "    return projects\n", encoding="utf-8")
    return servers


def _tree_hits(pkg_dir):
    from arcaeon.prove.vet.checks import scan_source_ex
    src = (pkg_dir / "jira.py").read_text(encoding="utf-8")
    findings, _ran = scan_source_ex(src, "servers/jira.py", package_dir=pkg_dir)
    return [f for f in findings if f.check == CHECK]


def test_a_fetcher_held_in_a_local_from_a_factory_call_is_reached(tmp_path):
    """The must-hit. `await get_jira_fetcher(ctx)` has an annotated return type,
    so the local binds to JiraFetcher, and `jira.get_all_projects(...)` opens
    the mixin method two packages away."""
    pkg = _atlassian_tree(tmp_path)
    fs = _tree_hits(pkg)
    assert fs, "the factory-bound fetcher shape must fire"
    assert fs[0].severity == "medium"
    assert "get_all_projects()" in fs[0].detail
    assert "projects.py" in fs[0].detail, fs[0].detail
    # THE LOCATION. `file`/`line` are the except SITE — the fetcher module,
    # relative to the scan root, and the `return []` inside the handler — not
    # the tool handler that reaches it. Until 2026-09-04 this finding carried
    # `servers/jira.py` and the handler's line, so a buyer who opened the
    # file:line saw a tool handler with no `except` in it and the real line was
    # only in prose.
    site = (pkg.parent / "jira" / "projects.py").read_text(encoding="utf-8")
    assert fs[0].file == "jira/projects.py", fs[0].file
    assert fs[0].line == _line_of(site, "            return []"), fs[0]
    # The handler travels as structure instead: one entry, because one handler
    # reaches it.
    handler = (pkg / "jira.py").read_text(encoding="utf-8")
    assert fs[0].via == [{"file": "servers/jira.py",
                          "handler": "get_all_projects",
                          "line": _line_of(handler, "async def get_all_projects(")}], fs[0].via
    assert "reached from get_all_projects() at servers/jira.py" in fs[0].detail


def test_a_handler_local_except_reports_its_own_line_and_via_itself():
    """The must-miss twin of the location change: when the except site IS in the
    graded file, nothing moves. The line was already the return's own line and
    stays there; `via` is emitted anyway, pointing at the handler the site is
    inside, so a consumer never has to branch on whether the key is present."""
    src = (HDR + "@mcp.tool()\ndef f(a):\n    try:\n        return _go(a)\n"
                 "    except Exception:\n        return []\n")
    fs = _hits(src)
    assert len(fs) == 1, fs
    assert fs[0].file == "t.py"
    assert fs[0].line == _line_of(src, "        return []")
    assert fs[0].via == [{"file": "t.py", "line": _line_of(src, "def f(a):"),
                          "handler": "f"}], fs[0].via


def test_one_site_two_handlers_is_one_finding_with_two_routes(tmp_path):
    """The dedup. The same fetcher method reached from two tool handlers is ONE
    defect at one line, not two findings at two handler lines; the route list
    carries both, and coverage counts one site via two handlers."""
    pkg = _atlassian_tree(tmp_path)
    server = pkg / "jira.py"
    server.write_text(server.read_text(encoding="utf-8")
                      + "\n\n@mcp.tool()\n"
                        "async def list_projects(ctx):\n"
                        "    jira = await get_jira_fetcher(ctx)\n"
                        "    return jira.get_all_projects()\n", encoding="utf-8")
    fs = _tree_hits(pkg)
    assert len(fs) == 1, fs
    assert fs[0].file == "jira/projects.py"
    assert len(fs[0].via) == 2, fs[0].via
    assert {v["handler"] for v in fs[0].via} == {"get_all_projects", "list_projects"}
    assert "and 1 more tool handler(s)" in fs[0].detail, fs[0].detail
    cov = except_success_coverage(server.read_text(encoding="utf-8"),
                                  "servers/jira.py", package_dir=pkg)
    assert cov["sites_reported"] == 1, cov
    assert cov["handlers_reaching"] == 2, cov


def test_a_findings_json_keys_are_unchanged_for_every_other_check():
    """`via` is omitted when absent, exactly as `gates` is. A `via: null` on
    every finding would change the bytes of every grade artifact ever emitted,
    and re-testability is the only thing this tool sells."""
    fs = [f for f in scan_source("import os\nos.system(cmd)\n", "t.py")
          if f.check == "unsafe-exec"]
    assert fs, "the control finding must fire"
    assert list(fs[0].as_dict()) == ["check", "severity", "file", "line", "detail"]
    hit = _hits(HDR + "@mcp.tool()\ndef f(a):\n    try:\n        return _go(a)\n"
                      "    except Exception:\n        return []\n")[0]
    assert list(hit.as_dict()) == ["check", "severity", "file", "line",
                                   "detail", "via"], hit.as_dict()
    assert json.loads(json.dumps(hit.as_dict()))["via"][0]["handler"] == "f"


def test_an_unresolvable_factory_is_counted_not_flagged(tmp_path):
    """The must-miss, one line from the must-hit. The fetcher now comes from a
    call the scan cannot open, so no class is pinned. Nothing is guessed and
    nothing is flagged, but the coverage line says a call was made on an
    instance the walk could not follow, so the zero reads as not-looked-at."""
    from arcaeon.prove.vet.checks import except_success_coverage
    pkg = _atlassian_tree(tmp_path,
                          factory_call="jira = await ctx.deps.jira_fetcher()")
    assert _tree_hits(pkg) == []
    cov = except_success_coverage(
        (pkg / "jira.py").read_text(encoding="utf-8"), "servers/jira.py",
        package_dir=pkg)
    assert cov["unresolved_instance_calls"] >= 1, cov
    assert cov["tool_handlers"] == 1, cov


def test_the_coverage_line_reports_unresolved_instance_calls(tmp_path, capsys):
    from arcaeon.prove.vet.__main__ import main
    pkg = _atlassian_tree(tmp_path,
                          factory_call="jira = await ctx.deps.jira_fetcher()")
    main(["scan", str(pkg / "jira.py")])
    out = capsys.readouterr().out
    assert "call(s) on unresolved instances" in out, out
    assert "0 call(s) on unresolved instances" not in out, out


def test_a_factory_returning_a_constructor_binds_without_an_annotation(tmp_path):
    """Same walk, the annotation-free spelling: the factory has no arrow and the
    class is read off the `return JiraFetcher()` in its body."""
    pkg = _atlassian_tree(tmp_path)
    (pkg / "dependencies.py").write_text(
        "from pkg.jira import JiraFetcher\n\n\n"
        "async def get_jira_fetcher(ctx):\n"
        "    return JiraFetcher()\n", encoding="utf-8")
    assert _tree_hits(pkg), "the constructor-in-the-body spelling must fire too"


def test_a_container_return_annotation_binds_nothing(tmp_path):
    """Conservative by construction: a `list[dict]` return is not a class the
    walk can open, so the local stays unbound rather than being guessed at."""
    from arcaeon.prove.vet.checks import except_success_coverage
    pkg = _atlassian_tree(tmp_path)
    (pkg / "dependencies.py").write_text(
        "async def get_jira_fetcher(ctx) -> list[dict]:\n"
        "    return ctx.rows\n", encoding="utf-8")
    assert _tree_hits(pkg) == []
    cov = except_success_coverage(
        (pkg / "jira.py").read_text(encoding="utf-8"), "servers/jira.py",
        package_dir=pkg)
    assert cov["unresolved_instance_calls"] >= 1, cov


# --- the low-level SDK decorator --------------------------------------------
#
# modelcontextprotocol/servers src/git and src/fetch both register their one
# handler as @server.call_tool(). Neither `_is_tool_handler` (which took
# tool/resource) nor `_dispatch_handlers` (which needs a branched-on
# "tools/call" literal) matched it, so both trees reported ZERO tool handlers
# and this check examined ZERO bodies in them. Gate 2 found no real hit of this
# idiom in either, so nothing was lost, but a zero from a tree nobody asked is
# not the same fact as a clean one.

CALL_TOOL_SERVER = '''
from mcp.server import Server
from mcp.server.stdio import stdio_server

server = Server("git")


def git_status(repo):
    try:
        return repo.git.status()
    except Exception:
        return []


async def main():
    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list:
        return git_status(arguments["repo_path"])

    async with stdio_server() as (r, w):
        await server.run(r, w, server.create_initialization_options())
'''


def test_the_low_level_call_tool_decorator_is_a_tool_handler():
    fs = _hits(CALL_TOOL_SERVER)
    assert fs, "@server.call_tool() must register a handler"
    assert fs[0].line == _line_of(CALL_TOOL_SERVER, "        return []")


def test_call_tool_coverage_stops_reporting_a_never_asked_zero():
    c = except_success_coverage(CALL_TOOL_SERVER, "server.py")
    assert c["tool_handlers"] == 1, c
    assert c["except_handlers_examined"] >= 1, c


# --- `scan` on a TypeScript file --------------------------------------------

@needs_ts
def test_scan_on_a_ts_file_does_not_report_a_false_parse_error(tmp_path, capsys):
    """`scan` handed every file to the Python front end, so a .ts file was told
    it was broken (could not parse: closing parenthesis) and got no TypeScript
    check at all. It now routes by extension, as `grade_source` already did."""
    from arcaeon.prove.vet.__main__ import main
    p = tmp_path / "index.ts"
    p.write_text(TS_FILESYSTEM, encoding="utf-8")
    main(["scan", str(p)])
    out = capsys.readouterr().out
    assert "could not parse" not in out, out
    assert "[medium] except-returns-success" in out, out


@needs_ts
def test_scan_on_a_ts_file_prints_the_coverage_line(tmp_path, capsys):
    """The line existed only for Python, and the population that most needed it
    was TypeScript: supabase-mcp walked 29 bodies and reached zero catch
    clauses, and the tool had no way to say so."""
    from arcaeon.prove.vet.__main__ import main
    p = tmp_path / "index.ts"
    p.write_text(TS_FILESYSTEM, encoding="utf-8")
    main(["scan", str(p)])
    out = capsys.readouterr().out
    assert "except-returns-success coverage:" in out, out
    assert "handler root(s)" in out, out
    assert "catch clause(s) examined" in out, out


@needs_ts
def test_ts_finding_points_at_the_catch_and_carries_the_handler_in_via():
    """The TS half of the location change. In-file the line was already the
    catch's return; what is new is that the registered tool handler is named as
    structure, so the same consumer reads both front ends the same way."""
    fs = _ts_hits(TS_FILESYSTEM)
    assert fs[0].file == "index.ts"
    assert fs[0].line == _line_of(TS_FILESYSTEM, "size: 0")
    assert fs[0].via == [{
        "file": "index.ts",
        "line": _line_of(TS_FILESYSTEM, 'server.tool("list_directory_with_sizes"'),
        "handler": "list_directory_with_sizes"}], fs[0].via


@needs_ts
def test_ts_a_catch_in_a_sibling_is_reported_in_the_sibling(tmp_path):
    """The one that was actually wrong: a catch site one relative import away
    used to be reported at the graded file's first handler line. It now carries
    the sibling's own path (the one the RESOLVER read, never a guessed
    extension) and its own line, with the handler in `via`."""
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "data.ts").write_text(
        "export function fetchAll() {\n"
        "  try {\n"
        "    return go();\n"
        "  } catch (e) {\n"
        "    return [];\n"
        "  }\n"
        "}\n", encoding="utf-8")
    src = (TS_HEAD + 'import { fetchAll } from "./lib/data.js";\n'
           + 'server.tool("list_things", async () => {\n'
             '  return { content: fetchAll() };\n'
             '});\n' + TS_TAIL)
    (tmp_path / "index.ts").write_text(src, encoding="utf-8")
    resolve = tc.file_resolver(tmp_path, tmp_path)
    findings, _ran = tc.scan_source_ts_ex(src, "index.ts", resolve=resolve)
    fs = [f for f in findings if f.check == CHECK]
    assert fs, "the sibling catch must fire"
    assert fs[0].file == "lib/data.ts", fs[0].file
    assert fs[0].line == 5, fs[0]
    assert fs[0].via == [{"file": "index.ts",
                          "line": _line_of(src, 'server.tool("list_things"'),
                          "handler": "list_things"}], fs[0].via
    assert "list_things" in fs[0].detail


@needs_ts
def test_ts_coverage_tells_no_catch_reached_apart_from_no_handlers():
    """The supabase-mcp case in miniature: handlers registered, bodies walked,
    and not one catch clause on any of those paths. A bare zero cannot say
    that, and until now the TypeScript side had only the bare zero."""
    walked = tc.ts_except_success_coverage(TS_FILESYSTEM, "index.ts")
    assert walked["handler_roots"] >= 1
    assert walked["catch_clauses_examined"] >= 1
    no_catch = tc.ts_except_success_coverage(
        TS_HEAD + 'server.tool("x", async (a) => { return { content: [] }; });\n'
        + TS_TAIL, "index.ts")
    assert no_catch["handler_roots"] >= 1
    assert no_catch["bodies_examined"] >= 1
    assert no_catch["catch_clauses_examined"] == 0
    never_asked = tc.ts_except_success_coverage(
        "function helper() { try { return go(); } catch { return []; } }\n",
        "index.ts")
    assert never_asked["handler_roots"] == 0
    assert never_asked["bodies_examined"] == 0
