"""K055: the one-page README inside the pack."""
import hashlib
import json
import re

import pytest

from arcaeon import verdict as V
from arcaeon.prove.evidence_pack import DOES_NOT_SHOW, README_DOES_NOT_SHOW, build_pack

# the same negation rule tests/test_docs.py applies to the product README
_NEGATIONS = ("not ", "never ", "no ", "nor ", "isn't ", "is not ")
_OVERCLAIMS = ("compliant", "ai act ready", "independent witness", "tamper-proof")


def _readme(out):
    return (out / "README.md").read_text(encoding="utf-8")


@pytest.fixture
def pack(ledger, tmp_path):
    out = tmp_path / "pack"
    res = build_pack(ledger, out, agent="agent-a", since="2026-09-01",
                     until="2026-09-30", system_id="sys-a", provider="Acme")
    return out, res


def test_readme_is_written_and_hashed(pack):
    out, res = pack
    assert "README.md" in res["files"]
    m = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert m["files"]["README.md"] == hashlib.sha256((out / "README.md").read_bytes()).hexdigest()


def test_agent_and_window(pack):
    text = _readme(pack[0])
    assert "`agent-a`" in text and "`sys-a`" in text and "Acme" in text
    assert "2026-09-01" in text and "2026-09-30" in text
    assert "Rows: 2 (ledger lines 1 to 3)" in text


def test_verdict_in_words(pack, ledger, tmp_path):
    assert "## The verdict\n\nVERIFIED." in _readme(pack[0])
    out = tmp_path / "empty"
    build_pack(ledger, out, agent="nobody")
    assert "## The verdict\n\nCOULD NOT LOOK." in _readme(out)
    assert "Rows: 0 (no lines)" in _readme(out)


def test_verdict_broken_in_words(ledger, tmp_path):
    lines = ledger.read_bytes().split(b"\n")
    lines[2] = lines[2].replace(b"escalate", b"escalatf")
    ledger.write_bytes(b"\n".join(lines))
    out = tmp_path / "pack"
    res = build_pack(ledger, out)
    assert res["verdict"] == V.BROKEN
    assert "## The verdict\n\nBROKEN." in _readme(out)


def test_does_not_show_bullets_verbatim(pack):
    text = _readme(pack[0])
    section = text.split("## What this pack does not show", 1)[1].split("\n## ", 1)[0]
    tagged = [l[2:] for l in section.splitlines() if l.startswith("- ")]
    # each bullet ends in its bearer class, the bullet itself stays verbatim
    assert all(l.endswith(" [asserted]") for l in tagged)
    bullets = [l[:-len(" [asserted]")] for l in tagged]
    assert bullets == list(README_DOES_NOT_SHOW)
    # the customer page spells out the internal references, nothing else moves
    assert "(P7)" not in text and "by us" not in text
    assert "until the custody record is published and anchored" in text
    assert "Not six-month retention by the operator of the hosted witness." in text
    changed = [i for i, (a, b) in enumerate(zip(DOES_NOT_SHOW, README_DOES_NOT_SHOW))
               if a != b]
    assert changed == [3, 5]
    # spec section 6, verbatim: six bullets, the first names the overclaims
    assert len(DOES_NOT_SHOW) == 6
    assert DOES_NOT_SHOW[0].startswith('Not "Article 12 compliant", "AI Act ready"')
    assert DOES_NOT_SHOW[-1] == "Not six-month retention by us. Retention is the holder's."


def test_two_commands(pack):
    text = _readme(pack[0])
    assert "arcaeon evidence-pack verify ." in text
    assert "arcaeon verify records.jsonl" in text


def test_evidence_toward_once_on_page_one(pack):
    text = _readme(pack[0])
    low = text.lower()
    # the spec section 6 bullet quotes the phrase ('We say "evidence toward"');
    # a quotation is not a use, so the claim itself is counted once
    assert low.count("evidence toward") - low.count('"evidence toward"') == 1
    first_para = text.split("\n\n")[1]
    assert "evidence toward" in first_para
    assert len(text.splitlines()) <= 60  # one page


@pytest.mark.parametrize("agent", ["agent-a", "nobody", None])
def test_negation_rule(ledger, tmp_path, agent):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent=agent)
    low = _readme(out).lower()
    for phrase in _OVERCLAIMS:
        for m in re.finditer(re.escape(phrase), low):
            before = low[max(0, m.start() - 40):m.start()]
            assert any(n in before for n in _NEGATIONS), (phrase, low[m.start() - 40:m.end()])
    # "truth" only ever as a negation, never as a guarantee
    for m in re.finditer(r"\btruth\b", low):
        before = low[max(0, m.start() - 40):m.start()]
        assert any(n in before for n in _NEGATIONS)


def test_no_dashes(pack):
    text = _readme(pack[0])
    assert "–" not in text and "—" not in text


def test_readme_claims_only_what_a_pin_backs(ledger, tmp_path):
    """OA5: a ledger rewritten from row 1 with no pin verifies clean, so the
    README never says the rows were not changed after they were written."""
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a")
    text = (out / "README.md").read_text(encoding="utf-8")
    assert "changed after it was written" not in text
    assert "every row hashes to the next" in text
    assert "With a pin, it also shows the rows up to the pinned head" in text
    assert "Without a pin, a full rewrite by the holder still checks out." in text
