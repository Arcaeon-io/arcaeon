"""D067: a checker that reads BROKEN for the same bytes vetoes act, pay and
irreversible (the D060 case: mcp-scan flagged a tool, the envelope's hash still
matches). The envelope verdict stays VERIFIED; the decision is refuse with
reason checker-broken naming the checker; read stays allowed. `gate packet`
renders a VERIFIED refusal (this one and D061's non-party refusal). Throwaway
keys in tmp_path, HOME pointed at tmp_path; nothing reaches the network."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import test_gate as TG                      # the gate tests' sealed-fixture helpers
from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import dispute_packet as P
from arcaeon.prove import gate as G
from arcaeon.record.ledger import Ledger

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

AUD = "instructor-1"
GUARDED = ("act", "pay", "irreversible")


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(tmp_path / "home"))


def _row(sha: str | None, verdict: str = V.BROKEN, *, vendor: str = "mcp-scan",
         name: str = "files/read_file", kind: str = G.CHECK_ROW_KIND) -> dict:
    """A check.verdict.relayed row with connector.core's field names."""
    return {"kind": kind, "relayed": True, "checked_by_us": False,
            "vendor": {"name": vendor, "adapter_version": "1"}, "vendor_id": None,
            "vendor_word": {V.BROKEN: "findings", V.VERIFIED: "no_findings"}.get(verdict, "error"),
            "relayed_verdict": verdict, "mapping": {"rule": "table"},
            "subject": {"name": name, "sha256": sha} if sha is not None else None,
            "attestation": {"status": "NONE", "checked_by_us": False, "claimed": None},
            "vendor_payload_digest": "sha256:raw-bytes:v1:" + "0" * 64,
            "vendor_payload_bytes": 42, "received_at": "2026-10-04T12:00:00Z"}


def _checks(tmp_path: Path, rows, name: str = "checks.jsonl") -> Path:
    p = tmp_path / name
    p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8", newline="\n")
    return p


def _verified(tmp_path):
    f, did = TG._make(tmp_path, V.VERIFIED)
    return f, did, hashlib.sha256(f.read_bytes()).hexdigest()


# --- the veto ---------------------------------------------------------------------------

@pytest.mark.parametrize("action", GUARDED)
def test_broken_check_on_same_digest_vetoes_guarded_actions(tmp_path, action):
    f, did, sha = _verified(tmp_path)
    c = _checks(tmp_path, [_row(sha)])
    d = G.decide(f, action=action, audience=AUD, signers=[did], check_files=[c])
    assert d.decision == "refuse" and d.verdict == V.VERIFIED
    assert d.reason.startswith(f"refuse {action}: {G.CHECKER_BROKEN}: ")
    assert "mcp-scan" in d.reason and "files/read_file" in d.reason
    assert d.checks["veto"] == G.CHECKER_BROKEN and d.checks["file_sha256"] == sha
    assert [b["checker"] for b in d.checks["broken"]] == ["mcp-scan"]
    assert d.checks["broken"][0]["reported_by"] == "sender"
    assert d.exit_code == V.EXIT_BAD
    assert d.to_dict()["checks"]["veto"] == G.CHECKER_BROKEN


def test_read_stays_allowed_and_names_the_checker(tmp_path):
    f, did, sha = _verified(tmp_path)
    c = _checks(tmp_path, [_row(sha)])
    d = G.decide(f, action="read", audience=AUD, signers=[did], check_files=[c])
    assert d.decision == "allow" and d.verdict == V.VERIFIED and d.exit_code == V.EXIT_GOOD
    assert d.checks["veto"] is None and d.checks["broken"]
    assert "mcp-scan" in d.reason and G.CHECKER_BROKEN in d.reason


def test_broken_row_for_another_digest_is_ignored(tmp_path):
    f, did, sha = _verified(tmp_path)
    other = hashlib.sha256(b"some other bytes").hexdigest()
    c = _checks(tmp_path, [_row(other), _row(None)])
    d = G.decide(f, action="pay", audience=AUD, signers=[did], check_files=[c])
    assert d.decision == "allow" and d.checks["broken"] == [] and d.checks["veto"] is None
    assert d.checks["rows"] == 2


@pytest.mark.parametrize("word", [V.VERIFIED, V.COULD_NOT_LOOK])
def test_non_broken_rows_do_not_veto(tmp_path, word):
    f, did, sha = _verified(tmp_path)
    c = _checks(tmp_path, [_row(sha, word)])
    d = G.decide(f, action="irreversible", audience=AUD, signers=[did], check_files=[c])
    assert d.decision == "allow" and d.checks["veto"] is None


def test_other_row_kinds_are_ignored(tmp_path):
    f, did, sha = _verified(tmp_path)
    bad = _row(sha, kind="check.verdict")
    bad["verdict"] = V.BROKEN
    c = _checks(tmp_path, [bad, {"kind": "gate.evidence", "verdict": V.BROKEN,
                                 "file_sha256": sha}])
    d = G.decide(f, action="pay", audience=AUD, signers=[did], check_files=[c])
    assert d.decision == "allow" and d.checks["rows"] == 0


def test_prefixed_and_uppercase_digest_still_matches(tmp_path):
    f, did, sha = _verified(tmp_path)
    c = _checks(tmp_path, [_row("sha256:" + sha.upper())])
    d = G.decide(f, action="pay", audience=AUD, signers=[did], check_files=[c])
    assert d.decision == "refuse" and d.checks["veto"] == G.CHECKER_BROKEN


def test_broken_envelope_stays_broken_with_checks(tmp_path):
    f, did = TG._make(tmp_path, V.BROKEN)
    sha = hashlib.sha256(f.read_bytes()).hexdigest()
    c = _checks(tmp_path, [_row(sha)])
    d = G.decide(f, action="pay", audience=AUD, signers=[did], check_files=[c])
    assert d.verdict == V.BROKEN and d.decision == "refuse"
    assert not d.reason.startswith(f"refuse pay: {G.CHECKER_BROKEN}")


def test_unreadable_checks_file_refuses_guarded_and_allows_read(tmp_path):
    f, did, _ = _verified(tmp_path)
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"kind": "check.verdict.relayed"\n', encoding="utf-8")
    for c in (bad, tmp_path / "missing.jsonl"):
        d = G.decide(f, action="pay", audience=AUD, signers=[did], check_files=[c])
        assert d.decision == "refuse" and d.verdict == V.VERIFIED
        assert d.checks["veto"] == G.CHECKS_UNREADABLE and d.exit_code == V.EXIT_COULD_NOT_LOOK
        assert d.could_not_check and d.could_not_check["looked_for"]
        r = G.decide(f, action="read", audience=AUD, signers=[did], check_files=[c])
        assert r.decision == "allow"


def test_no_checks_given_changes_nothing(tmp_path):
    f, did, _ = _verified(tmp_path)
    d = G.decide(f, action="pay", audience=AUD, signers=[did])
    assert d.decision == "allow" and d.checks is None and "checks" not in d.to_dict()


# --- evidence ----------------------------------------------------------------------------

def _vetoed_with_deal(tmp_path):
    f, did, sha = _verified(tmp_path)
    c = _checks(tmp_path, [_row(sha)])
    d = G.decide(f, action="pay", audience=AUD, signers=[did], deal="d-7f3a",
                 record_dir=tmp_path / "rec", ledger=tmp_path / "tape.jsonl", check_files=[c])
    assert d.decision == "refuse" and d.evidence and d.chain_row, d.reason
    return f, sha, d


def test_checker_broken_refusal_writes_evidence_pack_and_row(tmp_path):
    f, sha, d = _vetoed_with_deal(tmp_path)
    ev = json.loads((Path(d.evidence) / "evidence.json").read_text(encoding="utf-8"))
    assert ev["verdict"] == V.VERIFIED and ev["decision"] == "refuse"
    assert ev["checks"]["veto"] == G.CHECKER_BROKEN
    assert ev["checks"]["broken"][0]["row"]["relayed_verdict"] == V.BROKEN
    rows = [r for r in Ledger(tmp_path / "tape.jsonl") if r.get("kind") == G.CHAIN_KIND]
    assert len(rows) == 1
    row = rows[0]
    assert row["verdict"] == V.VERIFIED and row["veto"] == G.CHECKER_BROKEN
    assert row["reason"].startswith(f"refuse pay: {G.CHECKER_BROKEN}: ")
    assert row["file_sha256"] == sha
    assert G.verify_evidence_pack(d.evidence, row)["verdict"] == V.VERIFIED


def test_ordinary_refusal_row_has_no_veto_key(tmp_path):
    f, did = TG._make(tmp_path, V.BROKEN)
    d = G.decide(f, action="pay", audience=AUD, signers=[did], deal="d-7f3a",
                 record_dir=tmp_path / "rec", ledger=tmp_path / "tape.jsonl")
    assert "veto" not in d.chain_row


# --- CLI ---------------------------------------------------------------------------------

def test_cli_checks_flag_is_repeatable(tmp_path, capsys):
    f, did, sha = _verified(tmp_path)
    a = _checks(tmp_path, [_row(sha, V.VERIFIED)], "a.jsonl")
    b = _checks(tmp_path, [_row(sha, vendor="mockscan", name="grades.csv")], "b.jsonl")
    base = ["gate", "decide", "--envelope", str(f), "--audience", AUD, "--signer", did]
    rc = cli.main(base + ["--action", "pay", "--checks", str(a), "--checks", str(b), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == V.EXIT_BAD and out["decision"] == "refuse" and out["verdict"] == V.VERIFIED
    assert out["checks"]["veto"] == G.CHECKER_BROKEN and "mockscan" in out["reason"]
    assert cli.main(base + ["--action", "pay", "--checks", str(a)]) == V.EXIT_GOOD
    assert cli.main(base + ["--action", "read", "--checks", str(b)]) == V.EXIT_GOOD


# --- the dispute packet ------------------------------------------------------------------

def test_packet_renders_checker_broken_from_pack_and_decision(tmp_path):
    f, sha, d = _vetoed_with_deal(tmp_path)
    for p in (P.from_evidence(d.evidence), P.from_decision(d)):
        md = P.render_markdown(p)
        assert p["verdict"] == V.VERIFIED and p["decision"] == "refuse"
        assert p["refused_by"] == G.CHECKER_BROKEN
        assert p["failed"] and "mcp-scan" in p["failed"][0] and sha in p["failed"][0]
        for h in P.SECTIONS:
            assert f"\n## {h}\n" in md, h
        assert "**VERIFIED**" in md and "**refuse**" in md and G.CHECKER_BROKEN in md
        assert json.loads(P.render_json(p)) == p
        TG_paths = str(tmp_path)
        assert TG_paths not in md


NONPARTY_REASON = (
    "refuse pay: VERIFIED, but the non-party check rule refuses it: the amount 500 (from "
    "--amount) is over the cap 100 and no check counts (no --check was given). A check "
    "counts only when a key that is neither the envelope's signer nor the audience signed "
    "it, it names this file's sha256 and it says VERIFIED; a row nobody signed is the "
    "sender's report. Only read is allowed until one does.")
NONPARTY_CNC = {"looked_for": "a signed non-party check that says VERIFIED for this sha256",
                "where": "--check", "reason_word": "missing",
                "reason": "no check given counts toward the non-party check rule"}
NONPARTY_POLICY = {"rule": "require_nonparty_check_above", "cap": "100", "amount": "500",
                   "amount_source": "--amount", "amount_notes": [], "applies": True,
                   "satisfied": False, "checks": [], "limit": "raises the cost of collusion"}


def _nonparty_decision() -> dict:
    """D061's decision shape (branch d061-nonparty-check-rule), synthetic."""
    return {"decision": "refuse", "action": "pay", "verdict": V.VERIFIED,
            "reason": NONPARTY_REASON, "reasons": [NONPARTY_CNC["reason"]],
            "could_not_check": dict(NONPARTY_CNC), "file": "grades.csv",
            "envelope": "grades.csv.envelope.json", "audience": AUD, "deal": None,
            "purpose": None, "signers": ["did:key:z6Mkexample"], "at": "2026-10-04T12:00:00Z",
            "evidence": None, "evidence_error": None, "exit_code": 3, "limits": [],
            "report": {"verdict": V.VERIFIED, "steps": {s: V.VERIFIED for s in
                                                       ("envelope", "signature", "file",
                                                        "binding", "witness")}},
            "nonparty_check": dict(NONPARTY_POLICY)}


def test_packet_renders_nonparty_refusal_from_decision(tmp_path):
    p = P.from_decision(_nonparty_decision(), hash_file=False)
    md = P.render_markdown(p)
    assert p["verdict"] == V.VERIFIED and p["decision"] == "refuse"
    assert p["refused_by"] == P.NONPARTY
    assert p["failed"] == []
    assert any("signed non-party check" in x for x in p["not_checked"])
    assert "non-party check rule" in md and "**VERIFIED**" in md


def test_packet_renders_nonparty_refusal_from_evidence(tmp_path):
    dec = _nonparty_decision()
    pack = tmp_path / "pack"
    (pack / "bundle").mkdir(parents=True)
    ev = {"kind": G.EVIDENCE_KIND, **{k: dec[k] for k in (
        "deal", "action", "decision", "verdict", "reason", "reasons", "could_not_check",
        "at", "audience", "purpose", "signers", "limits", "report", "nonparty_check")},
        "file": {"path": "grades.csv", "copy": None, "sha256": None, "bytes": None},
        "envelope": {"path": "grades.csv.envelope.json", "copy": None, "sha256": None,
                     "bytes": None}}
    (pack / "evidence.json").write_text(json.dumps(ev), encoding="utf-8")
    p = P.from_evidence(pack)
    assert p["refused_by"] == P.NONPARTY and p["verdict"] == V.VERIFIED
    assert "non-party check rule" in P.render_markdown(p)


def test_nonparty_detected_by_reason_alone(tmp_path):
    dec = _nonparty_decision()
    del dec["nonparty_check"]
    assert P.from_decision(dec, hash_file=False)["refused_by"] == P.NONPARTY


def test_verified_allow_with_checks_is_still_nothing_to_dispute(tmp_path):
    f, did, sha = _verified(tmp_path)
    c = _checks(tmp_path, [_row(sha, V.VERIFIED)])
    d = G.decide(f, action="pay", audience=AUD, signers=[did], check_files=[c])
    assert d.decision == "allow"
    with pytest.raises(P.NothingToDispute, match="VERIFIED: nothing to dispute"):
        P.from_decision(d.to_dict())
    r = G.decide(f, action="read", audience=AUD, signers=[did],
                 check_files=[_checks(tmp_path, [_row(sha)], "b.jsonl")])
    with pytest.raises(P.NothingToDispute, match="VERIFIED: nothing to dispute"):
        P.from_decision(r)
