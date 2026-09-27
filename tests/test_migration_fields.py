"""MIGRATION.md names every new JSON field the plug-in batch adds (K141).

A reader upgrading from 0.9.1 reads MIGRATION.md to learn which keys are new.
Each name below was added by a landed item; this test fails if MIGRATION.md
does not name it inside a code span (backticks), so a field cannot ship
without its line. A name counts when it is a whole token inside a code span,
so `evt: "mandate_loaded"` names both `evt` and `mandate_loaded`.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (ROOT / "MIGRATION.md").read_text(encoding="utf-8")

#: name -> the item that added it (for the failure message only).
NEW_FIELDS = {
    # every HTTP body (lane A, K002/K003)
    "exit": "K003 HTTP bodies",
    # reading rows (lane C, K030)
    "evt": "K030 reading row", "claim_id": "K030 reading row",
    "claim_sha256": "K030 reading row", "criterion_sha256": "K030 reading row",
    "reader": "K030 reading row", "reading": "K030 reading row",
    "near_match_id": "K030 reading row", "rationale_sha256": "K030 reading row",
    "rationale": "K030 reading row", "prompt_sha256": "K030 reading row",
    "prompt_template_sha256": "K036 reading row",
    # compare (lane C, K032 to K034)
    "COMPARED": "K034 verdict word", "disagreed": "K032 summary",
    "read": "K032 summary", "not_yet_informative": "K032 summary",
    "independence": "K033",
    # evidence-pack manifest (lane D, K053, K06xR1)
    "pack_schema": "K053 manifest", "files": "K053 manifest",
    "chain_head": "K053 manifest", "window": "K053 manifest", "pins": "K053 manifest",
    "witness": "K053 manifest", "operator_at_t": "K053 manifest",
    "checks": "K053 manifest", "counts": "K053 manifest",
    "audit_export": "K053 manifest", "manifest.sha256": "K06xR1",
    # mandate (lane E, K073, K076)
    "spend_cap.total": "K073", "mandate_cap_exceeded": "K073",
    "mandate_loaded": "K076", "mandate_changed": "K076", "mandate_changes": "K076",
    # AAT chain (lane D, K062, K063)
    "prev_hash": "K062 AAT chain", "aat_chain": "K063 AAT chain",
    "which_chain": "K063 AAT chain", "chain": "K040/K062 chain",
}


def _code_tokens(text: str) -> set[str]:
    tokens: set[str] = set()
    for span in re.findall(r"`([^`\n]+)`", text):
        tokens.update(re.findall(r"[A-Za-z_][A-Za-z0-9_.]*[A-Za-z0-9_]|[A-Za-z_]", span))
    return tokens


TOKENS = _code_tokens(MIGRATION)


@pytest.mark.parametrize("name", sorted(NEW_FIELDS))
def test_migration_names_the_new_field(name):
    assert name in TOKENS, (f"MIGRATION.md does not name `{name}` ({NEW_FIELDS[name]}) "
                            f"in a code span")


def test_http_bodies_carry_exit_line():
    """The route response rule is stated once: every HTTP body carries `exit`."""
    body = " ".join(MIGRATION.split())
    assert re.search(r"every (HTTP )?(answer|body|route)[^.]*`exit`", body, re.I), \
        "MIGRATION.md has no line saying every HTTP body carries `exit`"
