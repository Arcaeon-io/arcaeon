"""OCSF export (D054 / TE-34): one arcaeon verdict out as one OCSF 1.9.0
Detection Finding. Real seals and gate decisions are made in tmp_path with a
throwaway key; nothing reaches the network."""
from __future__ import annotations

import base64
import json
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

import pytest

from arcaeon import verdict as V
from arcaeon.prove import envelope as E
from arcaeon.prove import gate as G
from arcaeon.prove import ocsf as O

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 4, 12, 0, 0, 123000, tzinfo=timezone.utc)
NOW_MS = 1791115200123
BIND = {"label": "week 3 grades", "audience": "instructor-1", "deal": "d-7f3a",
        "purpose": "grading", "not_after": "7d"}
BODY = b"name,grade\nunit-a,pass\n"
#: required by the Detection Finding class with no profile (OCSF 1.9.0)
REQUIRED = ("activity_id", "category_uid", "class_uid", "finding_info", "metadata",
            "severity_id", "time", "type_uid")
#: every top-level attribute the class lists with no profile (OCSF 1.9.0)
CLASS_ATTRS = {
    "activity_id", "activity_name", "anomaly_analyses", "category_name", "category_uid",
    "class_name", "class_uid", "comment", "confidence", "confidence_id", "confidence_score",
    "count", "device", "duration", "end_time", "enrichments", "evidences", "finding_info",
    "impact", "impact_id", "impact_score", "is_alert", "malware", "malware_scan_info",
    "message", "metadata", "notes", "observables", "raw_data", "raw_data_hash",
    "raw_data_size", "remediation", "resources", "risk_details", "risk_level",
    "risk_level_id", "risk_score", "severity", "severity_id", "start_time", "status",
    "status_code", "status_detail", "status_id", "time", "timezone_offset", "type_name",
    "type_uid", "unmapped", "vendor_attributes", "vulnerabilities"}
FINDING_INFO_ATTRS = {
    "title", "product", "desc", "uid", "types", "tags", "attacks", "analytic", "attack_graph",
    "created_time", "data_sources", "first_seen_time", "kill_chain", "last_seen_time",
    "modified_time", "product_uid", "related_analytics", "related_events",
    "related_events_count", "src_url", "traits", "uid_alt"}
METADATA_ATTRS = {"product", "version", "profiles", "uid", "log_name", "tenant_uid"}
PRODUCT_ATTRS = {"name", "vendor_name", "version"}
FILE_ATTRS = {"name", "type_id", "type", "size", "hashes"}

# Synthetic reports in the exact shape envelope.verify writes, with absolute
# directories in both slash forms to prove they never leave.
WIN_DIR = "D:" + "\\" + "work" + "\\" + "deal-7f3a" + "\\" + "in"
POSIX_DIR = "/srv/deals/d-7f3a/in"


def _report(verdict: str, d: str = WIN_DIR, sep: str = "\\") -> dict:
    r = {"verdict": verdict, "file": f"{d}{sep}grades.csv",
         "envelope": f"{d}{sep}grades.csv.envelope.json",
         "steps": {"envelope": "VERIFIED", "signature": "VERIFIED", "file": "VERIFIED",
                   "binding": "VERIFIED", "witness": "NOT CLAIMED"},
         "sealed": {"label": "week 3 grades", "bytes": len(BODY),
                    "sealed_by": {"name": None, "key": "did:key:z6MkTEST"},
                    "sealed_at": "2026-10-04T11:00:00Z",
                    "binding": {"audience": "instructor-1", "deal": "d-7f3a",
                                "purpose": "grading", "not_after": "2026-10-11T11:00:00Z"}},
         "signers": ["did:key:z6MkTEST"], "findings": [], "not_checked": [],
         "proves": E.PROVES, "does_not_prove": E.DOES_NOT_PROVE}
    if verdict == V.VERIFIED:
        r["reason"] = E.PROVES
    elif verdict == V.BROKEN:
        r["steps"]["file"] = "BROKEN"
        r["findings"] = ["the file's sha256 is " + "a" * 64 + ", the envelope sealed "
                         + "b" * 64 + ": the bytes changed after sealing"]
        r["reason"] = r["findings"][0]
    else:
        r["steps"]["signature"] = "COULD NOT LOOK"
        r.update(V.could_not_look("a signature on the envelope", r["envelope"], "missing",
                                  "the envelope is UNSIGNED"))
        r["not_checked"] = ["deal (recorded as 'd-7f3a'; pass --deal to hold the envelope to it)"]
    return r


# --- the mapping table -------------------------------------------------------------

@pytest.mark.parametrize("verdict,sev,alert", [(V.BROKEN, 4, True), (V.COULD_NOT_LOOK, 2, False),
                                               (V.VERIFIED, 1, False)])
def test_each_verdict_maps_to_class_type_and_severity(verdict, sev, alert):
    ev = O.to_ocsf(_report(verdict), now=NOW, include_verified=True)
    assert ev["class_uid"] == 2004 and ev["class_name"] == "Detection Finding"
    assert ev["category_uid"] == 2 and ev["category_name"] == "Findings"
    assert ev["activity_id"] == 1 and ev["activity_name"] == "Create"
    assert ev["type_uid"] == ev["class_uid"] * 100 + ev["activity_id"] == 200401
    assert ev["type_name"] == "Detection Finding: Create"
    assert ev["severity_id"] == sev
    assert ev["severity"] == {4: "High", 2: "Low", 1: "Informational"}[sev]
    assert ev["status_id"] == 1 and ev["status"] == "New"
    assert ev["is_alert"] is alert
    assert ev["status_code"] == verdict
    assert ev["unmapped"]["arcaeon"]["verdict"] == verdict
    assert ev["message"].startswith(verdict + ": grades.csv")


def test_verified_is_not_emitted_by_default():
    assert O.to_ocsf(_report(V.VERIFIED), now=NOW) is None
    assert O.to_ocsf(_report(V.VERIFIED), now=NOW, include_verified=True) is not None


@pytest.mark.parametrize("verdict", [V.BROKEN, V.COULD_NOT_LOOK, V.VERIFIED])
def test_required_attributes_present_and_no_invented_names(verdict):
    ev = O.to_ocsf(_report(verdict), now=NOW, include_verified=True)
    for k in REQUIRED:
        assert k in ev, k
    assert set(ev) <= CLASS_ATTRS, set(ev) - CLASS_ATTRS
    assert set(ev["finding_info"]) <= FINDING_INFO_ATTRS
    assert ev["finding_info"]["uid"] and ev["finding_info"]["title"]
    assert set(ev["metadata"]) <= METADATA_ATTRS
    assert ev["metadata"]["version"] == O.OCSF_VERSION == "1.9.0"
    assert set(ev["metadata"]["product"]) <= PRODUCT_ATTRS
    assert ev["metadata"]["product"]["name"] == "arcaeon"
    for e in ev["evidences"]:
        assert set(e) == {"file"} and set(e["file"]) <= FILE_ATTRS
        assert e["file"]["type_id"] == 1


@pytest.mark.parametrize("verdict", [V.BROKEN, V.COULD_NOT_LOOK, V.VERIFIED])
def test_time_is_integer_milliseconds(verdict):
    ev = O.to_ocsf(_report(verdict), now=NOW, include_verified=True)
    assert type(ev["time"]) is int and ev["time"] == NOW_MS
    assert ev["finding_info"]["created_time"] == NOW_MS
    assert ev["timezone_offset"] == 0


def test_limits_line_in_desc_for_every_verdict():
    for verdict in (V.BROKEN, V.COULD_NOT_LOOK, V.VERIFIED):
        desc = O.to_ocsf(_report(verdict), now=NOW, include_verified=True)["finding_info"]["desc"]
        assert O.LIMITS_LINE in desc
        assert "never means the content is true or safe" in desc


def test_could_not_look_lists_what_was_not_checked():
    ev = O.to_ocsf(_report(V.COULD_NOT_LOOK), now=NOW)
    a = ev["unmapped"]["arcaeon"]
    assert a["could_not_check"] == {"looked_for": "a signature on the envelope",
                                    "where": "grades.csv.envelope.json", "reason_word": "missing"}
    assert a["not_checked"] and a["not_checked"][0].startswith("deal")
    assert "could not check a signature on the envelope (missing)" in ev["finding_info"]["desc"]
    assert "Not checked: deal" in ev["finding_info"]["desc"]


def test_broken_carries_reasons_signer_and_binding():
    ev = O.to_ocsf(_report(V.BROKEN), now=NOW)
    a = ev["unmapped"]["arcaeon"]
    assert a["reasons"][0].endswith("the bytes changed after sealing")
    assert ev["status_detail"] == a["reasons"][0]
    assert a["signers_valid"] == ["did:key:z6MkTEST"]
    assert a["sealed_by"]["key"] == "did:key:z6MkTEST"
    assert a["sealed_for"]["audience"] == "instructor-1"
    f = ev["evidences"][0]["file"]
    assert f == {"name": "grades.csv", "type_id": 1, "type": "Regular File", "size": len(BODY)}
    assert ev["evidences"][1]["file"]["name"] == "grades.csv.envelope.json"


# --- determinism, JSON, paths ------------------------------------------------------

@pytest.mark.parametrize("verdict", [V.BROKEN, V.COULD_NOT_LOOK, V.VERIFIED])
def test_output_is_valid_json_and_deterministic(verdict):
    a = O.dumps(O.to_ocsf(_report(verdict), now=NOW, include_verified=True))
    b = O.dumps(O.to_ocsf(_report(verdict), now=NOW, include_verified=True))
    assert a == b
    assert json.loads(a)["time"] == NOW_MS
    later = O.to_ocsf(_report(verdict), now=NOW.replace(year=2027), include_verified=True)
    assert later["finding_info"]["uid"] == json.loads(a)["finding_info"]["uid"]


def _no_dirs(text: str):
    for bad in ("\\work","/srv/", "deal-7f3a" + "\\", "deals/d-7f3a"):
        assert bad not in text, bad
    assert not re.search(r"(?<![A-Za-z])[A-Za-z]:[\\/]", text)


@pytest.mark.parametrize("d,sep", [(WIN_DIR, "\\"), (WIN_DIR.replace("\\", "/"), "/"),
                                   (POSIX_DIR, "/")])
@pytest.mark.parametrize("verdict", [V.BROKEN, V.COULD_NOT_LOOK, V.VERIFIED])
def test_no_absolute_paths_leak(verdict, d, sep):
    r = _report(verdict, d, sep)
    r["findings"] = r["findings"] + [f"the file cannot be read (no such file: {d}{sep}x.csv)"]
    text = O.dumps(O.to_ocsf(r, now=NOW, include_verified=True))
    _no_dirs(text)
    assert "grades.csv" in text


def test_scrub_leaves_urls_and_plain_slashes():
    s = "pin_ref / witness_ref: see https://example.org/a/b and urn:x:y"
    assert O._scrub(s, []) == s


def test_not_an_arcaeon_verdict_is_refused():
    for bad in ([], {"x": 1}, {"verdict": "MATCHED"}, {"verdict": None}):
        with pytest.raises(O.ExportError):
            O.to_ocsf(bad, now=NOW)


# --- real seals, gate decisions and evidence packs ------------------------------------

def _key(tmp_path: Path) -> Path:
    k = tmp_path / "seal.key"
    k.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"), encoding="ascii")
    return k


def _sealed(tmp_path: Path, verdict: str):
    pytest.importorskip("cryptography", reason="signing needs the [sign] extra")
    f = tmp_path / "in" / "grades.csv"
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(BODY)
    env = E.seal(f, key_file=None if verdict == V.COULD_NOT_LOOK else _key(tmp_path), **BIND)
    sigs = env["dsseEnvelope"]["signatures"]
    if verdict == V.BROKEN:
        f.write_bytes(BODY + b"unit-b,pass\n")
    return f, (sigs[0]["keyid"] if sigs else "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")


@pytest.mark.parametrize("verdict,sev", [(V.BROKEN, 4), (V.COULD_NOT_LOOK, 2), (V.VERIFIED, 1)])
def test_real_verify_report_and_gate_decision(tmp_path, verdict, sev):
    f, did = _sealed(tmp_path, verdict)
    r = E.verify(f, audience="instructor-1", signers=[did], deal="d-7f3a", now=NOW)
    assert r["verdict"] == verdict
    ev = O.to_ocsf(r, now=NOW, include_verified=True)
    assert ev["severity_id"] == sev and ev["status_code"] == verdict
    d = G.decide(f, action="pay", audience="instructor-1", signers=[did], deal="d-7f3a",
                 record_dir=tmp_path / "rec", now=NOW).to_dict()
    ev2 = O.to_ocsf(d, now=NOW, include_verified=True)
    a = ev2["unmapped"]["arcaeon"]
    assert ev2["severity_id"] == sev
    assert a["source"] == "gate decision" and a["action"] == "pay"
    assert a["decision"] == ("allow" if verdict == V.VERIFIED else "refuse")
    assert a["audience_checked"] == "instructor-1"
    for text in (O.dumps(ev), O.dumps(ev2)):
        assert str(tmp_path) not in text
        assert str(tmp_path).replace("\\", "/") not in text
        _no_dirs(text)
    if verdict == V.BROKEN:
        assert a["evidence"] and "/" not in a["evidence"] and "\\" not in a["evidence"]
        assert "Evidence pack written to " + a["evidence"] in a["gate_reason"]


def test_evidence_pack_carries_the_file_sha256(tmp_path):
    f, did = _sealed(tmp_path, V.BROKEN)
    d = G.decide(f, action="act", audience="instructor-1", signers=[did], deal="d-7f3a",
                 record_dir=tmp_path / "rec", now=NOW)
    ev_json = json.loads((Path(d.evidence) / "evidence.json").read_text(encoding="utf-8"))
    ev = O.to_ocsf(ev_json, now=NOW)
    f0 = ev["evidences"][0]["file"]
    assert f0["name"] == "grades.csv"
    assert f0["hashes"] == [{"algorithm_id": 3, "algorithm": "SHA-256",
                             "value": ev_json["file"]["sha256"]}]
    assert ev["unmapped"]["arcaeon"]["file_sha256"] == ev_json["file"]["sha256"]
    assert ev["unmapped"]["arcaeon"]["source"] == "gate evidence pack"
    _no_dirs(O.dumps(ev))
    assert str(tmp_path) not in O.dumps(ev)


# --- CLI -------------------------------------------------------------------------

def test_cli_export_ocsf(tmp_path, capsys):
    from arcaeon import cli
    p = tmp_path / "r.json"
    p.write_text(json.dumps(_report(V.BROKEN)), encoding="utf-8")
    argv = ["envelope", "export-ocsf", str(p), "--now", "2026-10-04T12:00:00.123Z"]
    assert cli.main(argv) == 0
    first = capsys.readouterr().out
    assert json.loads(first)["time"] == NOW_MS
    assert cli.main(argv) == 0
    assert capsys.readouterr().out == first                 # deterministic with --now
    out = tmp_path / "ev.json"
    assert cli.main(argv + ["--out", str(out)]) == 0
    assert out.read_text(encoding="utf-8") == first


def test_cli_verified_skipped_unless_asked(tmp_path, capsys):
    from arcaeon import cli
    p = tmp_path / "r.json"
    p.write_text(json.dumps(_report(V.VERIFIED)), encoding="utf-8")
    assert cli.main(["envelope", "export-ocsf", str(p)]) == 0
    cap = capsys.readouterr()
    assert cap.out == "" and "nothing exported" in cap.err
    assert cli.main(["envelope", "export-ocsf", str(p), "--include-verified"]) == 0
    assert json.loads(capsys.readouterr().out)["severity_id"] == 1


def test_cli_bad_input_and_usage(tmp_path, capsys):
    from arcaeon import cli
    bad = tmp_path / "bad.json"
    bad.write_text('{"verdict": "BROKEN", "verdict": "VERIFIED"}', encoding="utf-8")
    assert cli.main(["envelope", "export-ocsf", str(bad)]) == 3
    assert cli.main(["envelope", "export-ocsf", str(tmp_path / "missing.json")]) == 3
    err = capsys.readouterr().err
    assert str(tmp_path) not in err
    assert cli.main(["envelope", "export-ocsf"]) == 2
    assert cli.main(["envelope", "export-ocsf", str(bad), "--now", "noon"]) == 2


def test_doc_cites_the_fetched_pages_and_the_version():
    doc = (ROOT / "docs" / "OCSF.md").read_text(encoding="utf-8")
    for url in O.OCSF_SOURCES:
        assert url in doc, url
    assert O.OCSF_VERSION in doc
    assert O.LIMITS_LINE in doc
    for word in ("200401", "class_uid", "severity_id", "unmapped"):
        assert word in doc
    assert "—" not in doc and "–" not in doc
