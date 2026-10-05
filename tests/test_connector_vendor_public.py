# SPDX-License-Identifier: MIT
"""L2-14: every real-vendor adapter run on ONE sample taken verbatim from a public
source (the vendor's docs page or a file in its public repo), under
tests/fixtures/<adapter>/vendor_public/. Each folder's README.md names the URL,
the commit sha or retrieval date, the licence note and any trimming. The
hand-made fixtures beside them are untouched.

No network: the samples were fetched once (2026-10-05) and committed. Nothing in
a sample is executed; the OPA bundle is read in memory and never extracted."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from arcaeon.connector import cedar as C
from arcaeon.connector import hiddenlayer as H
from arcaeon.connector import kyverno as K
from arcaeon.connector import lakera_guard as L
from arcaeon.connector import opa as OPA
from arcaeon.connector import opa_bundle as B
from arcaeon.connector import prisma_airs as P
from arcaeon.connector import sentinelone as S1
from arcaeon.connector import snyk_agent_scan as SN
from arcaeon.connector.intoto import STATEMENT_TYPE, StatementError, export_row, parse_statement
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"
AT = "2026-10-05T12:00:00Z"

#: adapter fixture folder -> what its vendor_public/README.md must say
PUBLIC = ("opa", "opa_bundle", "kyverno", "cedar", "snyk_agent_scan", "lakera_guard",
          "prisma_airs", "e2b", "hiddenlayer", "sentinelone", "intoto", "ocsf",
          "datadog_llmobs")
NOT_APPLICABLE = ("mockscan", "reported")


def _raw(adapter: str, name: str) -> bytes:
    return (FIX / adapter / "vendor_public" / name).read_bytes()


def _words(rows) -> list:
    return [(r["vendor_word"], r["relayed_verdict"]) for r in rows]


def _unsigned(rows) -> None:
    assert rows
    for r in rows:
        assert r["signed_by_vendor"] is False
        assert r["relayed"] is True and r["checked_by_us"] is False
        assert "verdict" not in r


# --- the folders say where each sample came from ---------------------------------------------

@pytest.mark.parametrize("adapter", PUBLIC)
def test_every_public_folder_names_its_source(adapter):
    text = (FIX / adapter / "vendor_public" / "README.md").read_text(encoding="utf-8")
    assert "Retrieved: 2026-10-05" in text
    assert "Licence:" in text and "Trimming:" in text
    assert "https://" in text


@pytest.mark.parametrize("adapter", NOT_APPLICABLE)
def test_our_own_formats_are_marked_not_applicable(adapter):
    text = (FIX / adapter / "vendor_public" / "README.md").read_text(encoding="utf-8")
    assert "not applicable" in text.lower()
    assert sorted(p.name for p in (FIX / adapter / "vendor_public").iterdir()) == ["README.md"]


def test_e2b_has_no_public_sample_and_none_was_made_up():
    d = FIX / "e2b" / "vendor_public"
    assert sorted(p.name for p in d.iterdir()) == ["README.md"]
    assert "no public sample found" in (d / "README.md").read_text(encoding="utf-8")


# --- OPA decision log (docs: management-decision-logs.md) ------------------------------------

def test_opa_docs_decision_reads_could_not_look_because_its_result_is_a_string():
    raw = _raw("opa", "decision_log_docs.json")
    assert json.loads(raw)[0]["result"] == "true"           # the docs write a string
    for kw in ({}, {"allow_paths": ["http/example/authz/allow"]}):
        rows = OPA.ingest(raw, received_at=AT, **kw)
        _unsigned(rows)
        assert len(rows) == 1
        r = rows[0]
        assert r["relayed_verdict"] == COULD_NOT_LOOK
        assert r["vendor_word"] == "non_boolean"
        assert r["could_not_look"]["reason"] == "the result is not JSON true or false"
        assert r["vendor_id"] == "4ca636c1-55e4-417a-b1d8-4aceb67960d1"
        assert r["subject"]["name"] == "opa:http/example/authz/allow"
        assert r["decision"]["bundles"] == {"authz": "W3sibCI6InN5cy9jYXRhbG9nIiwicyI6NDA3MX1d"}
        assert r["decision"]["timestamp"] == "2018-01-01T00:00:00.000000Z"
        assert "requested_by" not in json.dumps(r["decision"])


# --- OPA bundle (opa repo: v1/download/testdata/signed.tar.gz, built by `opa build`) -----------

def _seal(**kw):
    return B.seal_bundle(_raw("opa_bundle", "signed.tar.gz"), name="authz",
                         sealed_at=AT, **kw)


def test_opa_signed_test_bundle_verifies_under_its_published_test_key():
    s = _seal(verification_key=b"secret", key_algorithm="HS256")
    assert s["seal"] == VERIFIED
    assert s["revision"] == "" and s["roots"] == [""]         # `opa build` defaults
    assert s["files"] == 4 and s["opa_signatures_present"] is True
    assert s["signature"]["alg"] == "HS256" and s["signature"]["kid"] == "default"
    fh = s["file_hashes"]
    assert (fh["verdict"], fh["listed"], fh["matched"]) == (VERIFIED, 3, 3)
    assert fh["mismatched"] == fh["missing"] == fh["unlisted"] == fh["could_not_check"] == []
    assert s["opa_signature_verified"] == VERIFIED


def test_opa_signed_test_bundle_wrong_key_is_broken_and_no_key_could_not_look():
    assert _seal(verification_key=b"not-the-key", key_algorithm="HS256")[
        "opa_signature_verified"] == BROKEN
    s = _seal()
    assert s["seal"] == VERIFIED and s["opa_signature_verified"] == COULD_NOT_LOOK


def test_an_empty_revision_bundle_never_joins():
    rows = OPA.ingest(_raw("opa", "decision_log_docs.json"), received_at=AT)
    joined = OPA.join_bundles(rows, [_seal(verification_key=b"secret", key_algorithm="HS256")])
    assert joined[0]["policy_join"] == COULD_NOT_LOOK
    assert joined[0]["signed_by_vendor"] is False


# --- Kyverno (kyverno/website reports guide: `kubectl get polr -o yaml`) ----------------------

def test_kyverno_yaml_and_json_copies_hold_the_same_values():
    yaml = pytest.importorskip("yaml")
    d = FIX / "kyverno" / "vendor_public"
    for stem in ("polr_list_staging", "policyreport_docs_example"):
        y = yaml.safe_load((d / f"{stem}.yaml").read_text(encoding="utf-8"))
        assert y == json.loads((d / f"{stem}.json").read_text(encoding="utf-8"))


def test_kyverno_list_reads_fail_and_pass_with_the_scope_as_subject():
    rows = K.ingest(_raw("kyverno", "polr_list_staging.json"), received_at=AT)
    _unsigned(rows)
    assert _words(rows) == [("fail", BROKEN), ("pass", VERIFIED)]
    assert [r["vendor_id"] for r in rows] == ["90ab79b4-fc0b-41bc-b8d0-da021c02ee9d",
                                              "8e19960d-969d-4e4c-a7d7-480fff15df6d"]
    assert [r["subject"]["name"] for r in rows] == [
        "kyverno:staging-ns/Deployment/deployment-3", "kyverno:staging-ns/Deployment/deployment-4"]
    for r in rows:
        k = r["kyverno"]
        assert k["subject_from"] == "scope" and k["resources"] == []
        assert k["policy"] == "check-deployment-replicas" and k["rule"] is None
        assert k["source"] == "ValidatingAdmissionPolicy" and k["summary_check"] == "agrees"
    assert K.rollup(rows)["relayed_verdict"] == BROKEN


def test_kyverno_docs_example_trimmed_by_the_vendor_reads_could_not_look():
    rows = K.ingest(_raw("kyverno", "policyreport_docs_example.json"), received_at=AT)
    _unsigned(rows)
    assert _words(rows) == [("pass", COULD_NOT_LOOK), ("fail", COULD_NOT_LOOK)]
    assert all(r["kyverno"]["summary_check"] == "disagrees" for r in rows)
    assert rows[0]["subject"]["name"] == "kyverno:kube-system/Pod/kube-apiserver-kind-control-plane"


# --- Cedar / Verified Permissions (AWS API reference, IsAuthorized examples) ------------------

def test_avp_allow_and_deny_examples():
    rows = C.ingest(_raw("cedar", "avp_isauthorized_allow.json"), received_at=AT)
    _unsigned(rows)
    assert _words(rows) == [("ALLOW", VERIFIED)]
    assert rows[0]["cedar"]["policy_ids"] == ["SPEXAMPLEabcdefg111111"]
    rows = C.ingest(_raw("cedar", "avp_isauthorized_deny.json"), received_at=AT)
    _unsigned(rows)
    assert _words(rows) == [("DENY", BROKEN)]
    assert rows[0]["cedar"]["policy_ids"] == []


# --- Snyk agent-scan (snyk/agent-scan docs/json-output.md) ------------------------------------

def test_agent_scan_v06_docs_example():
    raw = _raw("snyk_agent_scan", "v06_scan_docs.json")
    rows = SN.ingest(raw, broken_at_score=500)
    _unsigned(rows)
    assert _words(rows) == [("risk_at_or_over_threshold", BROKEN)] * 2
    assert [(r["finding"]["target_kind"], r["finding"]["target_name"], r["finding"]["risk"],
             r["finding"]["score"]) for r in rows] == [
        ("server", "github", "prompt_injection_tool_desc", 1000),
        ("skill", "release-helper", "suspicious_download_url", 600)]
    assert rows[0]["finding"]["affected_tools"] == [0]
    assert _words(SN.ingest(raw, broken_at_score=700)) == [
        ("risk_at_or_over_threshold", BROKEN), ("risk_below_threshold", COULD_NOT_LOOK)]
    assert _words(SN.ingest(raw)) == [("risk_no_threshold", COULD_NOT_LOOK)] * 2


def test_agent_scan_v05_docs_example():
    rows = SN.ingest(_raw("snyk_agent_scan", "v05_scan_docs.json"))
    _unsigned(rows)
    assert _words(rows) == [("issue_error", BROKEN)]
    assert rows[0]["finding"]["code"] == "E004" and rows[0]["finding"]["format"] == "v0.5-path-keyed"


# --- Lakera Guard (docs.lakera.ai guard page and API reference) -------------------------------

def test_lakera_quickstart_response_is_flagged():
    rows = L.ingest(_raw("lakera_guard", "guard_quickstart_flagged.json"), policy_mode="enforce")
    _unsigned(rows)
    assert _words(rows) == [("flagged", BROKEN)]
    assert rows[0]["vendor_request_id"] == "abcd5678-ab42-42e4-8d80-af44ca72e975"
    assert rows[0]["finding"]["action"] == "enforce"


def test_lakera_api_reference_response_reads_its_tools_block():
    rows = L.ingest(_raw("lakera_guard", "guard_api_reference.json"))
    _unsigned(rows)
    assert _words(rows) == [("flagged", BROKEN), ("detector_detected", BROKEN),
                            ("payload_match", BROKEN), ("tools_flagged", BROKEN),
                            ("tool_detector_detected", BROKEN)]
    assert rows[-1]["finding"]["tool_id"] == 1
    assert rows[-1]["finding"]["part"] == "tools_breakdown"


def test_lakera_a_clean_looking_message_with_a_flagged_tool_is_not_a_pass():
    # derived in-test from the public example: message level clean, tools flagged
    doc = json.loads(_raw("lakera_guard", "guard_api_reference.json"))
    doc.update(flagged=False, payload=[], breakdown=[])
    rows = L.ingest(json.dumps(doc).encode(), policy_mode="enforce")
    assert rows[0]["vendor_word"] == "not_flagged_unsettled"
    assert L.standing_verdict(rows)["relayed_verdict"] == BROKEN


def test_lakera_action_naming_the_other_mode_blocks_the_clean_row():
    doc = json.loads(_raw("lakera_guard", "guard_api_reference.json"))
    for k in ("payload", "breakdown", "tools"):
        doc.pop(k)
    doc.update(flagged=False, action="detect")
    raw = json.dumps(doc).encode()
    assert _words(L.ingest(raw, policy_mode="enforce")) == [
        ("not_flagged_mode_conflict", COULD_NOT_LOOK)]
    assert _words(L.ingest(raw, policy_mode="detect")) == [
        ("not_flagged_detect_mode", COULD_NOT_LOOK)]
    doc["action"] = "enforce"
    assert _words(L.ingest(json.dumps(doc).encode(), policy_mode="enforce")) == [
        ("not_flagged", VERIFIED)]


# --- Prisma AIRS (pan.dev use-cases page, PaloAltoNetworks/pan.dev) ---------------------------

def test_prisma_sync_block_example():
    rows = P.ingest(_raw("prisma_airs", "sync_block_prompt_injection.json"))
    _unsigned(rows)
    assert _words(rows) == [("block", BROKEN)]
    f = rows[0]["finding"]
    assert f["category"] == "malicious" and f["prompt_detected"] == ["injection"]
    assert rows[0]["ids"]["tr_id"] == "1234"


def test_prisma_scan_results_and_reports_examples():
    rows = P.ingest(_raw("prisma_airs", "scan_results_grounding.json"))
    _unsigned(rows)
    assert _words(rows) == [("block", BROKEN), ("allow", VERIFIED)]
    assert [r["ids"]["req_id"] for r in rows] == [2, 1]
    rows = P.ingest(_raw("prisma_airs", "scan_reports_grounding.json"))
    _unsigned(rows)
    assert _words(rows) == [("allow", VERIFIED), ("block", BROKEN)]
    assert [(r["ids"]["req_id"], r["ids"]["tr_id"]) for r in rows] == [(1, "2882"), (2, "2082")]
    assert [r["finding"]["report_verdict"] for r in rows] == ["benign", "malicious"]
    assert P.standing_verdict(rows)["relayed_verdict"] == BROKEN


# --- HiddenLayer (docs.hiddenlayer.ai webhook "Data Formats") ---------------------------------

@pytest.mark.parametrize("name,word,ours,vid", [
    ("runtime_conviction.json", "conviction", BROKEN, "b53bc9c8-e5cc-4bd8-a3bf-98576de4cb71"),
    ("supply_chain_scan.json", "scan_detections", BROKEN, "3246d37b-b211-4983-80a8-86851c484fa8"),
    ("runtime_policy_outcome.json", "policy_block", BROKEN, "0c7fe87b-9bc6-4651-bf2c-80f8376817d1"),
    ("audit_log.json", "not_an_alert", COULD_NOT_LOOK, None),
])
def test_hiddenlayer_webhook_examples(name, word, ours, vid):
    rows = H.ingest(_raw("hiddenlayer", name))
    _unsigned(rows)
    assert _words(rows) == [(word, ours)]
    assert rows[0]["vendor_id"] == vid


def test_hiddenlayer_sample_carries_no_email():
    assert b"@" not in _raw("hiddenlayer", "supply_chain_scan.json")


# --- SentinelOne (Sentinel-One/purple-mcp unit test responses) --------------------------------

def test_sentinelone_list_and_get_responses_read_no_verdict():
    for name, vid in (("purple_mcp_list_alerts.json", "alert-1"),
                      ("purple_mcp_get_alert.json", "alert-123")):
        rows = S1.ingest(_raw("sentinelone", name))
        _unsigned(rows)
        assert _words(rows) == [("no_verdict", COULD_NOT_LOOK)]
        r = rows[0]
        assert r["vendor_id"] == vid and r["subject"]["name"] == f"sentinelone:alert/{vid}"
        assert r["at"] == "2024-01-01T00:00:00Z"
        assert r["detection"]["severity"] == "HIGH" and r["detection"]["status"] == "NEW"


# --- in-toto (in-toto/attestation spec/predicates/test-result.md) -----------------------------

def test_intoto_public_statement_is_refused_by_our_predicate_reader():
    raw = _raw("intoto", "test_result_statement.json")
    with pytest.raises(StatementError, match="predicateType"):
        parse_statement(raw)
    pub = json.loads(raw)
    row = H.ingest(_raw("hiddenlayer", "runtime_conviction.json"))[0]
    ours = export_row(row, ledger="checks.jsonl")
    assert set(ours) == set(pub) and ours["_type"] == pub["_type"] == STATEMENT_TYPE
    assert parse_statement(json.dumps(ours).encode())["predicate"]["relayed"] is True


# --- OCSF export (ocsf/examples Okta Detection Finding, OCSF 1.3.0) ---------------------------

def test_ocsf_export_agrees_with_the_public_detection_finding_ids():
    from arcaeon.prove import ocsf as O
    pub = json.loads(_raw("ocsf", "okta_detection_finding.ocsf.json"))
    rep = json.loads((FIX / "ocsf" / "broken.report.json").read_text(encoding="utf-8"))
    ev = O.to_ocsf(rep, ocsf_version="1.3.0")
    for k in ("class_uid", "category_uid", "category_name", "activity_id", "type_uid"):
        assert ev[k] == pub[k], k
    assert ev["metadata"]["version"] == pub["metadata"]["version"] == "1.3.0"
    assert ev["type_uid"] == ev["class_uid"] * 100 + ev["activity_id"]
    assert {"name", "vendor_name"} <= set(ev["metadata"]["product"]) & set(pub["metadata"]["product"])
    # the public sample writes the plural; the 1.3.0 schema caption is singular
    assert pub["class_name"] == "Detection Findings" and ev["class_name"] == "Detection Finding"


# --- Datadog LLM Observability export (DataDog/documentation instrument/api.md) ---------------

#: Span fields the Spans API table documents (same page as the example)
DD_SPAN_FIELDS = {"name", "span_id", "trace_id", "parent_id", "start_ns", "duration", "meta",
                  "status", "apm_trace_id", "metrics", "session_id", "feedback_join_key",
                  "tags", "service", "ml_app"}
DD_META_FIELDS = {"kind", "error", "input", "output", "metadata", "model_name", "model_provider",
                  "model_version", "embedding_for_prompt_idx", "span", "tool_definitions",
                  "expected_output", "intent"}


def test_datadog_export_has_the_public_example_shape():
    from arcaeon.prove import datadog_llmobs as DD
    pub = json.loads(_raw("datadog_llmobs", "spans_api_example.json"))
    rep = json.loads((FIX / "ocsf" / "verified.report.json").read_text(encoding="utf-8"))
    body = DD.to_llmobs(rep)
    assert set(body) == set(pub) == {"data"}
    assert body["data"]["type"] == pub["data"]["type"] == "span"
    assert {"ml_app", "spans"} <= set(body["data"]["attributes"]) & set(pub["data"]["attributes"])
    required = {"name", "span_id", "trace_id", "parent_id", "start_ns", "duration", "meta"}
    for span in pub["data"]["attributes"]["spans"] + body["data"]["attributes"]["spans"]:
        assert required <= set(span) <= DD_SPAN_FIELDS
        assert set(span["meta"]) <= DD_META_FIELDS and "kind" in span["meta"]
    root = body["data"]["attributes"]["spans"][0]
    assert root["parent_id"] == pub["data"]["attributes"]["spans"][0]["parent_id"] == "undefined"
