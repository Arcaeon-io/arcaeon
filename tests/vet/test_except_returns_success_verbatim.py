"""except-returns-success against the REAL mcp-atlassian code, pinned.

Board row 227 (2026-09-05). Until now the must-hit for this check was a
four-file miniature of mcp-atlassian written by hand, in the shape the check
already handled -- which proves the check handles the shape I wrote, not the
server it was measured on. This file runs the check on the verbatim files from
sooperset/mcp-atlassian at commit 4067d1db (MIT; see
fixtures/mcp_atlassian_4067d1d/NOTICE.md for exactly what is verbatim and what
is an excerpt). The hand-made tree in test_except_returns_success.py stays as a
regression guard for the resolver's individual steps; THIS is the must-hit.

Run:  py -m pytest -q projects/mcp_vet/test_except_returns_success_verbatim.py
"""
from __future__ import annotations

from pathlib import Path

import pytest

from arcaeon.prove.vet.checks import scan_source_ex

CHECK = "except-returns-success"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "mcp_atlassian_4067d1d"
PKG = FIXTURE / "src" / "mcp_atlassian"
SERVERS = PKG / "servers"


def _line_of(text: str, needle: str, nth: int = 1) -> int:
    seen = 0
    for i, line in enumerate(text.splitlines(), 1):
        if line == needle:
            seen += 1
            if seen == nth:
                return i
    raise AssertionError(f"{needle!r} (#{nth}) not in fixture text")


@pytest.fixture(scope="module")
def findings():
    src = (SERVERS / "jira.py").read_text(encoding="utf-8")
    fs, ran = scan_source_ex(src, "servers/jira.py", package_dir=SERVERS)
    assert CHECK in ran, ran
    return fs


def test_fixture_is_the_pinned_file_not_a_rewrite():
    """The claim on the forum was `jira/projects.py:49`. Line 49 of the pinned
    file must be that `return []`, inside `get_all_projects`, under a bare
    `except Exception`."""
    site = (PKG / "jira" / "projects.py").read_text(encoding="utf-8")
    lines = site.splitlines()
    assert lines[48] == "            return []", lines[48]
    assert lines[46] == "        except Exception as e:", lines[46]
    assert "def get_all_projects(self, include_archived: bool = False)" in site
    assert (FIXTURE / "LICENSE").read_text(encoding="utf-8").startswith("MIT License")


def test_the_real_get_all_projects_except_site_fires(findings):
    """THE must-hit. The verbatim tool handler binds `jira` from
    `await get_jira_fetcher(ctx)` (annotated `-> JiraFetcher`), `JiraFetcher`
    inherits `ProjectsMixin` among eighteen bases, and the method's `except
    Exception: ... return []` is reached. The finding sits at the except site."""
    fs = [f for f in findings if f.check == CHECK]
    assert fs, "the verbatim mcp-atlassian shape must fire"
    site = (PKG / "jira" / "projects.py").read_text(encoding="utf-8")
    handler = (SERVERS / "jira.py").read_text(encoding="utf-8")
    hit = fs[0]
    assert hit.severity == "medium"
    assert hit.file == "jira/projects.py", hit.file
    assert hit.line == 49 == _line_of(site, "            return []"), hit
    assert hit.via == [{"file": "servers/jira.py",
                        "handler": "get_all_projects",
                        "line": _line_of(handler, "async def get_all_projects(")}], hit.via
    assert "get_all_projects()" in hit.detail
    assert "projects.py" in hit.detail


def test_the_unreached_search_projects_site_in_the_same_file_stays_quiet(findings):
    """Same shape, line 88, in `search_projects`, which no handler in the
    fixture calls. A `return []` nobody reaches is a contract, not a lie."""
    lines = [f.line for f in findings if f.check == CHECK]
    assert 88 not in lines, lines
    assert len(lines) == 1, lines


def test_no_other_check_reddens_the_verbatim_handler(findings):
    """Noise on a stranger's file is the one cost this project cannot pay.
    Before 2026-09-05 the ssrf check reported `project.get("key")` in this
    handler as an outbound network call; the mapping-lookup rule closed it.
    Any new red here is a regression on real code, not on a fixture."""
    others = [f for f in findings if f.check != CHECK]
    assert not others, [(f.check, f.line, f.detail[:80]) for f in others]
