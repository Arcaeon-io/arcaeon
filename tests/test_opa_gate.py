"""The OPA/Rego gate (policies/opa/arcaeon_gate.rego, docs/OPA.md).

No OPA binary is needed: the policy text is held to its shape, and a small
Python evaluator that mirrors the rule table is run over real
`arcaeon envelope verify` reports (VERIFIED, COULD NOT LOOK, BROKEN) for every
action. When `opa` is on PATH the same 3x4 cells are also run through
`opa eval` and compared; otherwise that test skips and says why.
"""
from __future__ import annotations

import base64
import json
import re
import secrets
import shutil
import subprocess
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon import verdict as V

ROOT = Path(__file__).resolve().parents[1]
REGO = ROOT / "policies" / "opa" / "arcaeon_gate.rego"
OPA_MD = ROOT / "docs" / "OPA.md"
TEXT = REGO.read_text(encoding="utf-8")

ACTIONS = ("read", "act", "pay", "irreversible")
# The rule table, the same one `arcaeon gate decide` is to encode (parity later).
TABLE = {
    V.VERIFIED: {"read", "act", "pay", "irreversible"},
    V.COULD_NOT_LOOK: {"read"},
    V.BROKEN: set(),
}
_UNDEFINED = object()  # an absent key: undefined in Rego, not JSON null


def decide(inp: dict) -> dict:
    """A Python mirror of arcaeon_gate.rego: {"allow": bool, "reason": str}."""
    report = inp.get("report")
    verdict = report.get("verdict") if isinstance(report, dict) else None
    action = inp.get("action", _UNDEFINED)
    allowed = TABLE.get(verdict, set()) if isinstance(verdict, str) else set()
    if isinstance(action, str) and action in allowed:
        return {"allow": True, "reason": f"allowed: {verdict} permits {action}"}
    if action is not _UNDEFINED and not (isinstance(action, str) and action in TABLE[V.VERIFIED]):
        shown = action if isinstance(action, str) else json.dumps(action)
        return {"allow": False, "reason": f"refused: unknown action {shown}"}
    if verdict == V.BROKEN:
        return {"allow": False, "reason": "refused: BROKEN refuses every action"}
    if verdict == V.COULD_NOT_LOOK and isinstance(action, str):
        return {"allow": False,
                "reason": f"refused: COULD NOT LOOK allows read only, not {action}"}
    return {"allow": False,
            "reason": "refused: the report has no verdict this gate knows (missing or unknown)"}


# --- the policy text ----------------------------------------------------------------

def _rego_table() -> dict[str, set[str]]:
    block = re.search(r"^allowed := \{\n(.*?)\n\}", TEXT, re.S | re.M)
    assert block, "no `allowed := {...}` table in the policy"
    out = {}
    for line in block.group(1).splitlines():
        m = re.fullmatch(r'\s*"([^"]+)": (set\(\)|\{[^}]*\}),', line)
        assert m, f"table row not in the expected shape: {line!r}"
        out[m.group(1)] = set(re.findall(r'"([^"]+)"', m.group(2)))
    return out


def test_policy_shape():
    assert re.search(r"^package arcaeon\.gate$", TEXT, re.M)
    assert re.search(r"^default allow := false$", TEXT, re.M)
    assert re.search(r"^default reason := \"refused: ", TEXT, re.M)
    assert re.search(r"^allow if ", TEXT, re.M)
    assert re.search(r"^reason := .* if \{$", TEXT, re.M)
    # OPA v1 syntax: no rego.v1 / future.keywords import, no pre-1.0 bodies without `if`
    assert "import future.keywords" not in TEXT and "import rego.v1" not in TEXT
    for line in TEXT.splitlines():  # every rule body opens with `if {` (v1)
        if line.rstrip().endswith("{") and ":= {" not in line:
            assert line.rstrip().endswith("if {"), line
    for word in (V.VERIFIED, V.COULD_NOT_LOOK, V.BROKEN):
        assert f'"{word}"' in TEXT, word
    for action in ACTIONS:
        assert f'"{action}"' in TEXT, action
    code = [ln for ln in TEXT.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    assert len(code) <= 30, f"policy grew to {len(code)} code lines"


def test_policy_table_is_the_rule_table():
    assert _rego_table() == TABLE


def test_verdict_words_are_spelled_as_the_verifier_prints_them():
    assert (V.VERIFIED, V.COULD_NOT_LOOK, V.BROKEN) == ("VERIFIED", "COULD NOT LOOK", "BROKEN")


# --- real verify reports ------------------------------------------------------------

def _verify_json(capsys, argv) -> dict:
    capsys.readouterr()
    cli.main(["envelope", "verify", *argv])
    return json.loads(capsys.readouterr().out)


@pytest.fixture
def reports(tmp_path, capsys) -> dict[str, dict]:
    pytest.importorskip("cryptography", reason="signing needs the [sign] extra")
    key = tmp_path / "seal.key"
    key.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"), encoding="ascii")
    f = tmp_path / "grades.csv"
    f.write_bytes(b"name,grade\nunit-a,pass\n")
    capsys.readouterr()
    cli.main(["envelope", "seal", str(f), "--label", "week 3", "--audience", "instructor-1",
              "--deal", "d-7f3a", "--purpose", "grading", "--not-after", "7d", "--key", str(key)])
    did = json.loads(capsys.readouterr().out)["signer"]
    out = {
        V.VERIFIED: _verify_json(capsys, [str(f), "--audience", "instructor-1", "--signer", did]),
        # signed, but no --signer named: bounded, COULD NOT LOOK
        V.COULD_NOT_LOOK: _verify_json(capsys, [str(f), "--audience", "instructor-1"]),
    }
    f.write_bytes(b"name,grade\nunit-a,fail\n")  # the bytes changed: BROKEN
    out[V.BROKEN] = _verify_json(capsys, [str(f), "--audience", "instructor-1", "--signer", did])
    for word, r in out.items():
        assert r["verdict"] == word, r
    return out


CELLS = [(w, a) for w in (V.VERIFIED, V.COULD_NOT_LOOK, V.BROKEN) for a in ACTIONS]


def test_all_twelve_cells(reports):
    seen = {}
    for word, action in CELLS:
        d = decide({"report": reports[word], "action": action})
        assert d["allow"] is (action in TABLE[word]), (word, action, d)
        assert d["reason"].startswith("allowed: " if d["allow"] else "refused: ")
        seen[(word, action)] = d["allow"]
    assert sum(seen.values()) == 5  # 4 under VERIFIED, read under COULD NOT LOOK


def test_missing_or_unknown_verdict_refuses(reports):
    for report in ({}, {"verdict": None}, {"verdict": "verified"}, {"verdict": "MATCHED"},
                   {"verdict": ["VERIFIED"]}, None):
        for action in ACTIONS:
            assert decide({"report": report, "action": action})["allow"] is False
    assert decide({"action": "read"})["allow"] is False
    assert decide({"report": reports[V.VERIFIED], "action": "delete"}) == {
        "allow": False, "reason": "refused: unknown action delete"}
    assert decide({"report": reports[V.VERIFIED]})["allow"] is False


# --- opa eval, when there is one -----------------------------------------------------

def test_opa_eval_matches_the_mirror(reports, tmp_path):
    opa = shutil.which("opa")
    if not opa:
        pytest.skip("no `opa` binary on PATH; the policy text and the Python mirror were checked")
    for word, action in CELLS + [(None, "read")]:
        inp = {"report": reports[word] if word else {}, "action": action}
        p = tmp_path / "input.json"
        p.write_text(json.dumps(inp), encoding="utf-8")
        r = subprocess.run([opa, "eval", "--format", "json", "--data", str(REGO),
                            "--input", str(p), "data.arcaeon.gate"],
                           capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, r.stderr
        got = json.loads(r.stdout)["result"][0]["expressions"][0]["value"]
        want = decide(inp)
        assert (got["allow"], got["reason"]) == (want["allow"], want["reason"]), (word, action)


# --- docs/OPA.md ---------------------------------------------------------------------

def test_doc_names_the_policy_and_its_limits():
    doc = OPA_MD.read_text(encoding="utf-8")
    assert "policies/opa/arcaeon_gate.rego" in doc and "opa eval" in doc
    assert "openpolicyagent.org/docs/policy-language" in doc
    for word in (V.VERIFIED, V.COULD_NOT_LOOK, V.BROKEN):
        assert word in doc
    assert "never true" in doc
