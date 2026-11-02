"""The package states no price, credit count, grant or plan name of its own.

Prices and plans live on the site's price list and change there; a copy in a
help string, an MCP tool description or a refusal outlives the day it was
changed. `arcaeon buy` is the one place that shows them, read live. This
test reads every string literal (help text, descriptions, printed messages,
docstrings) in the files that talk about the paid lane.
"""
import ast
import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "arcaeon"
FILES = [
    "cli.py",
    "mcp/server.py",
    "mcp/__init__.py",
    "mcp/__main__.py",
    "remote/sealed_scan.py",
    "prove/vet/__main__.py",
    "prove/vet/badge_cli.py",
    "status.py",
    "doctor.py",
]
STALE = re.compile(
    r"\$\d"                                  # a dollar amount
    r"|\b\d[\d,]*\s+credits?\b"              # a credit count
    r"|\bone credit\b"
    r"|registration grant|per verified email"
    r"|\b(?:mini|starter|bulk) (?:pack|rate|plan)\b|\bWitnessed plan\b"
    r"|\d+ free pins|pins/month",
    re.I)


def _strings(path: Path):
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.lineno, node.value


@pytest.mark.parametrize("rel", FILES)
def test_no_price_credit_count_grant_or_plan_name(rel):
    hits = [(line, m.group(0)) for line, s in _strings(SRC / rel)
            for m in STALE.finditer(s)]
    assert hits == [], f"{rel}: {hits}"


def test_the_paid_lane_points_at_the_pricing_page():
    from arcaeon.remote import sealed_scan
    text = (SRC / "remote" / "sealed_scan.py").read_text(encoding="utf-8")
    assert "https://arcaeon.io/pricing" in text
    assert sealed_scan  # importable
