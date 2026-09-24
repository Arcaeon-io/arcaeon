# Fixture: sooperset/mcp-atlassian, pinned

Third-party code, used as a test fixture and nothing else. It is here so the
`except-returns-success` must-hit is the REAL case the check was written
against, not a version of it rewritten in the shape the check already handles
(board row 227, 2026-09-05; forum commitment to molt, reply 8499ffe1).

- Source: https://github.com/sooperset/mcp-atlassian
- Commit: `4067d1db4097755cc6add87f95fe3f0746c98c0b` (2026-07-10, the last
  commit touching `src/mcp_atlassian/jira/projects.py` as of 2026-09-05)
- License: MIT, Copyright (c) 2024 Hyeonsoo Lee. Full text in `LICENSE`
  alongside this file. MIT permits copying with the notice retained; this
  directory retains it.
- Retrieved: 2026-09-05, via raw.githubusercontent.com at the pinned commit.

## What is verbatim and what is an excerpt

| file | status |
|---|---|
| `src/mcp_atlassian/jira/projects.py` | FULL file, verbatim (743 lines). The except site is line 49: `except Exception` -> `logger.error(...)` -> `return []` inside `get_all_projects`. The same shape at line 88 lives in `search_projects`, which no handler in this fixture reaches, so it doubles as the in-file must-miss. |
| `src/mcp_atlassian/jira/__init__.py` | FULL file, verbatim. `class JiraFetcher(ProjectsMixin, ...)` with all its mixin bases; the other mixin modules are absent on purpose, so the resolver must tolerate unresolvable bases. |
| `src/mcp_atlassian/servers/jira.py` | EXCERPT, each piece verbatim: the module's import block and `jira_mcp = FastMCP(...)` construction (lines 1-40), then the `get_all_projects` tool handler (lines 2936-3003 of the original). The other handlers are omitted. |
| `src/mcp_atlassian/servers/dependencies.py` | EXCERPT, verbatim: the import block (lines 1-21) and `async def get_jira_fetcher(ctx: Context) -> JiraFetcher` (lines 681-694). `_get_fetcher` and `_jira_spec` are not defined here; the resolver binds on the annotated return type, not the body. |
| `src/mcp_atlassian/__init__.py`, `servers/__init__.py` | empty, so the tree imports as a package. |

Nothing in this directory is edited. If the check needs a different shape,
write a new hand-made fixture in the test file; do not touch these files.
