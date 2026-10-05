# SPDX-License-Identifier: MIT
"""The two-sided rule, said the same way on every quickstart surface: a seal
shows one side's record; an exchange holds only when both parties' logs
reconcile (`arcaeon exchange pair`); and what a one-sided record cannot prove.

The surfaces: the README's first run, docs/FIRST_FIVE_MINUTES.md (in its
limits, which come before the steps) and the runnable example in examples/.
clients/curl/EXAMPLES.md is generated from docs/openapi.json and is not
edited by hand, so it is not one of them."""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: The paragraph, word for word. Every surface carries exactly this text
#: (line breaks and indentation aside).
TWO_SIDED = (
    "One side or both. A seal shows one side's record: what that party wrote down, and a "
    "way for anyone to check whether it changed since. An exchange holds only when both "
    "parties' logs reconcile: each party signs its own reaction in its own log, and "
    "`arcaeon exchange pair A.jsonl B.jsonl` reads the two logs and lines them up. A "
    "one-sided record cannot prove that the other party saw the same bytes, agreed with "
    "them, or answered at all."
)


def _flat(text: str) -> str:
    return " ".join(text.split())


def _section(text: str, heading: str) -> str:
    m = re.search(r"^## " + re.escape(heading) + r"\s*$(.*?)(?=^## |\Z)", text, re.M | re.S)
    assert m, f"no section '## {heading}'"
    return m.group(1)


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _example_doc(rel: str) -> str:
    return ast.get_docstring(ast.parse(_read(rel))) or ""


SURFACES = {
    "README.md": lambda: _section(_read("README.md").replace("\r\n", "\n"),
                                  "A 60-second first run"),
    "docs/FIRST_FIVE_MINUTES.md": lambda: _section(_read("docs/FIRST_FIVE_MINUTES.md"),
                                                   "What it cannot do"),
    "examples/escrow_two_agents_demo.py": lambda: _example_doc(
        "examples/escrow_two_agents_demo.py"),
}


@pytest.mark.parametrize("surface", sorted(SURFACES))
def test_every_quickstart_says_the_two_sided_rule(surface):
    assert _flat(TWO_SIDED) in _flat(SURFACES[surface]()), surface


def test_every_example_is_a_surface():
    for p in sorted((ROOT / "examples").glob("*.py")):
        assert f"examples/{p.name}" in SURFACES, p.name


def test_the_paragraph_makes_no_ranking_claim():
    low = TWO_SIDED.lower()
    for word in ("first", "unique", "only tool", "truth", "guarantee", "proves that",
                 "independent", "—", "–"):
        assert word not in low, word


def test_the_named_verb_exists():
    from arcaeon.prove import exchange_log as X
    assert "arcaeon exchange pair A.jsonl B.jsonl" in X.USAGE
