"""OCSF export keys off the gate DECISION, not only the envelope verdict.

F-R1: a refusal whose envelope reads VERIFIED (checker-broken, checks-unreadable,
nonparty-check) is never skipped and never titled "passed"; checker-broken is
High and an alert, with the broken check rows named in unmapped.
F-R6: COULD NOT LOOK on a refused action is Medium and an alert; COULD NOT LOOK
that allowed (read) or a bare verify report stays Low. Throwaway keys in
tmp_path, HOME pointed at tmp_path; nothing reaches the network."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import test_gate as TG
from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import gate as G
from arcaeon.prove import ocsf as O

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

AUD = "instructor-1"


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(tmp_path / "home"))


def _ex(tmp_path) -> dict:
    return {"deal": "d-7f3a", "purpose": "grading", "ledger": tmp_path / "tape.jsonl",
            "record_dir": tmp_path / "rec"}


def _broken_row(sha: str) -> dict:
    return {"kind": G.CHECK_ROW_KIND, "relayed": True, "checked_by_us": False,
            "vendor": {"name": "sentinelone", "adapter_version": "1"}, "vendor_id": "t-1",
            "vendor_word": "true_positive", "relayed_verdict": V.BROKEN,
            "subject": {"name": "grades.csv", "sha256": sha},
            "attestation": {"status": "NONE", "checked_by_us": False, "claimed": None}}


def _checker_broken(tmp_path, action="pay"):
    f, did = TG._make(tmp_path, V.VERIFIED)
    sha = hashlib.sha256(f.read_bytes()).hexdigest()
    c = tmp_path / "s1.jsonl"
    c.write_text(json.dumps(_broken_row(sha)) + "\n", encoding="utf-8")
    return G.decide(f, action=action, audience=AUD, signers=[did], check_files=[c],
                    **_ex(tmp_path))


def _checks_unreadable(tmp_path):
    f, did = TG._make(tmp_path, V.VERIFIED)
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"kind": "check.verdict.relayed"\n', encoding="utf-8")
    return G.decide(f, action="pay", audience=AUD, signers=[did], check_files=[bad],
                    **_ex(tmp_path))


def _nonparty(tmp_path):
    f, did = TG._make(tmp_path, V.VERIFIED)
    return G.decide(f, action="pay", audience=AUD, signers=[did],
                    require_nonparty_check_above="10", amount="11", **_ex(tmp_path))


def _no_pass(ev):
    assert "passed" not in ev["finding_info"]["title"]
    assert "passed" not in ev["message"]


# --- F-R1 ---------------------------------------------------------------------------

def test_checker_broken_refusal_is_exported_high_alert(tmp_path):
    d = _checker_broken(tmp_path)
    assert d.decision == "refuse" and d.verdict == V.VERIFIED
    assert d.veto == G.CHECKER_BROKEN
    for src in (d.to_dict(),
                json.loads((Path(d.evidence) / "evidence.json").read_text(encoding="utf-8"))):
        ev = O.to_ocsf(src)                          # no include_verified
        assert ev is not None
        assert ev["severity_id"] == 4 and ev["severity"] == "High"
        assert ev["is_alert"] is True
        _no_pass(ev)
        a = ev["unmapped"]["arcaeon"]
        assert a["decision"] == "refuse" and a["veto"] == G.CHECKER_BROKEN
        assert a["verdict"] == V.VERIFIED            # the envelope's own word is kept
        assert a["checks"]["broken_count"] == 1
        assert a["checks"]["broken"][0]["checker"] == "sentinelone"
        assert a["checks"]["broken"][0]["vendor_id"] == "t-1"
        assert str(tmp_path) not in O.dumps(ev)


def test_checker_broken_refusal_cli_exports(tmp_path, capsys):
    d = _checker_broken(tmp_path)
    p = tmp_path / "d.json"
    p.write_text(json.dumps(d.to_dict()), encoding="utf-8")
    assert cli.main(["envelope", "export-ocsf", str(p)]) == 0
    cap = capsys.readouterr()
    assert "nothing exported" not in cap.err
    ev = json.loads(cap.out)
    assert ev["severity_id"] == 4 and ev["is_alert"] is True


@pytest.mark.parametrize("make,veto", [(_checks_unreadable, G.CHECKS_UNREADABLE),
                                       (_nonparty, G.NONPARTY_VETO)])
def test_other_vetoed_refusals_are_never_skipped(tmp_path, make, veto):
    d = make(tmp_path)
    assert d.decision == "refuse" and d.verdict == V.VERIFIED and d.veto == veto
    ev = O.to_ocsf(d.to_dict())
    assert ev is not None
    assert ev["severity_id"] > 1
    assert ev["status_code"] == V.COULD_NOT_LOOK
    _no_pass(ev)
    assert ev["unmapped"]["arcaeon"]["veto"] == veto


def test_read_allowed_with_broken_note_still_skipped_by_default(tmp_path):
    d = _checker_broken(tmp_path, action="read")
    assert d.decision == "allow" and d.verdict == V.VERIFIED
    assert O.to_ocsf(d.to_dict()) is None
