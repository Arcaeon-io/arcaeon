"""K059: the evidence-pack spec's section 7 test, as one file.

Build a pack from a four-row ledger with two agents; verify returns 0. Change
one byte in window.jsonl: returns 1 naming that file. Restore, change one word
in records.jsonl and regenerate its manifest hash to hide it: returns 1 naming
the chain break at that row. Delete could_not_look.json: returns 3,
reason_word "missing", never 0. Grep the README for "compliant" outside a
negation: the test fails if found.
"""
import hashlib
import json
import re
import shutil

import pytest

from arcaeon import verdict as V
from arcaeon.prove import evidence_pack_cli
from arcaeon.prove.evidence_pack import build_pack
from arcaeon.prove.evidence_pack_verify import verify_pack

_NEGATIONS = ("not ", "never ", "no ", "nor ", "isn't ", "is not ")


@pytest.fixture
def built(ledger, tmp_path):
    """A clean pack (agent-a, whole window) and a pristine copy to restore from."""
    out = tmp_path / "pack"
    res = build_pack(ledger, out, agent="agent-a")
    pristine = tmp_path / "pristine"
    shutil.copytree(out, pristine)
    return out, pristine, res


def _restore(out, pristine):
    shutil.rmtree(out)
    shutil.copytree(pristine, out)


def test_fixture_is_four_rows_two_agents(ledger):
    rows = [json.loads(l) for l in ledger.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 4
    assert {r["agent"] for r in rows} == {"agent-a", "agent-b"}


def test_1_built_pack_verifies_exit_0(built, capsys):
    out, _, res = built
    assert res["exit"] == 0
    assert evidence_pack_cli.main(["verify", str(out)]) == 0
    assert capsys.readouterr().out.startswith("VERIFIED")


def test_2_one_byte_in_window_is_broken_naming_the_file(built):
    out, _, _ = built
    win = out / "window.jsonl"
    raw = bytearray(win.read_bytes())
    i = raw.index(b"escalate")
    raw[i] = ord("E")
    win.write_bytes(bytes(raw))
    res = verify_pack(out)
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    assert "window.jsonl" in res["finding"]
    assert res["checks"][0]["changed"] == ["window.jsonl"]


def test_3_restore_then_hidden_word_change_is_broken_at_that_row(built):
    out, pristine, _ = built
    (out / "window.jsonl").write_bytes(b"damaged\n")
    _restore(out, pristine)
    assert verify_pack(out)["exit"] == 0  # restored: clean again
    rec = out / "records.jsonl"
    raw = rec.read_bytes()
    assert raw.count(b"lookup") == 1  # ledger row 2
    rec.write_bytes(raw.replace(b"lookup", b"looked"))
    m = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    m["files"]["records.jsonl"] = hashlib.sha256(rec.read_bytes()).hexdigest()
    (out / "manifest.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
    res = verify_pack(out)
    assert res["checks"][0]["verdict"] == V.VERIFIED  # the hash hides it
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    chain = next(c for c in res["checks"] if c["check"] == "records chain and head")
    assert chain["break_line"] == 2
    assert "line 2" in res["finding"]


def test_4_deleted_could_not_look_file_is_exit_3_missing_never_0(built, capsys):
    out, _, _ = built
    (out / "could_not_look.json").unlink()
    res = verify_pack(out)
    assert res["verdict"] == V.COULD_NOT_LOOK
    assert res["exit"] == 3 and res["exit"] != 0
    assert res["reason_word"] == "missing"
    assert "could_not_look.json" in res["looked_for"]
    rc = evidence_pack_cli.main(["verify", str(out)])
    assert rc == 3
    assert capsys.readouterr().out.startswith("COULD NOT LOOK")


def test_5_readme_never_says_compliant_outside_a_negation(built):
    out, _, _ = built
    low = (out / "README.md").read_text(encoding="utf-8").lower()
    hits = list(re.finditer("compliant", low))
    assert hits, "the section 6 bullet names the overclaim, inside a negation"
    for m in hits:
        before = low[max(0, m.start() - 40):m.start()]
        assert any(n in before for n in _NEGATIONS), low[m.start() - 40:m.end()]
