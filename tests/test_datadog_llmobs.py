"""L2-13: arcaeon verdicts out as a Datadog LLM Observability span payload
(the JSON body of POST /api/intake/llm-obs/v1/trace/spans). An EXPORT only:
nothing is sent, no key is read, no test touches the network. Digests and
verdict words leave; payload text, file names and directories never do."""
from __future__ import annotations

import base64
import json
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

import pytest

from arcaeon import verdict as V
from arcaeon.prove import datadog_llmobs as DD
from arcaeon.prove import envelope as E
from arcaeon.prove import gate as G

ROOT = Path(__file__).resolve().parents[1]
OCSF_FIX = ROOT / "tests" / "fixtures" / "ocsf"
FIX = ROOT / "tests" / "fixtures" / "datadog_llmobs"
NOW = datetime(2026, 10, 5, 12, 0, 0, 123456, tzinfo=timezone.utc)
NOW_NS = 1791201600123456000
SLUG = {V.VERIFIED: "verified", V.BROKEN: "broken", V.COULD_NOT_LOOK: "could_not_look"}
TOKEN = {V.VERIFIED: "VERIFIED", V.BROKEN: "BROKEN", V.COULD_NOT_LOOK: "COULD_NOT_LOOK"}
SECRET = "zz-SECRET-payload-7731-do-not-leak"
SHA = "c" * 64

# Written here from Datadog's HTTP API page (docs.datadoghq.com/llm_observability/
# setup/api/, read 2026-10-05), independently of the module's own constants.
SPANS_PAYLOAD_KEYS = {"ml_app", "spans", "tags", "session_id", "feedback_join_key"}
SPAN_REQUIRED = {"name", "span_id", "trace_id", "parent_id", "start_ns", "duration", "meta"}
SPAN_KEYS = SPAN_REQUIRED | {"status", "apm_trace_id", "metrics", "session_id",
                             "feedback_join_key", "tags", "service", "ml_app"}
META_KEYS = {"kind", "error", "input", "output", "metadata", "model_name", "model_provider",
             "model_version", "embedding_for_prompt_idx", "span", "tool_definitions",
             "expected_output", "intent"}
KINDS = {"agent", "workflow", "llm", "tool", "task", "embedding", "retrieval"}
ERROR_KEYS = {"message", "stack", "type"}


def _report(verdict: str) -> dict:
    """A verify report in the shape envelope.verify writes, with SECRET in
    every free-text field a report can hold."""
    d = "/srv/" + SECRET + "/in"
    r = {"verdict": verdict, "file": f"{d}/{SECRET}.csv", "envelope": f"{d}/{SECRET}.csv.envelope.json",
         "steps": {"envelope": "VERIFIED", "signature": "VERIFIED", "file": "VERIFIED",
                   "binding": "VERIFIED", "witness": "NOT CLAIMED"},
         "sealed": {"label": SECRET, "bytes": 23,
                    "sealed_by": {"name": SECRET, "key": "did:key:z6Mk" + SECRET},
                    "sealed_at": "2026-10-04T11:00:00Z",
                    "binding": {"audience": SECRET, "deal": SECRET, "purpose": SECRET,
                                "not_after": "2026-10-11T11:00:00Z"}},
         "signers": ["did:key:z6Mk" + SECRET], "findings": [], "not_checked": [],
         "note": SECRET, "file_sha256": SHA}
    if verdict == V.VERIFIED:
        r["reason"] = "fine " + SECRET
    elif verdict == V.BROKEN:
        r["steps"]["file"] = "BROKEN"
        r["findings"] = [f"the bytes of {SECRET} changed after sealing"]
        r["reason"] = r["findings"][0]
    else:
        r["steps"]["signature"] = "COULD NOT LOOK"
        r.update(V.could_not_look("a signature " + SECRET, r["envelope"], "missing",
                                  "the envelope is UNSIGNED " + SECRET))
        r["not_checked"] = [f"deal (recorded as {SECRET!r})"]
    return r


def _span(body: dict) -> dict:
    spans = body["data"]["attributes"]["spans"]
    assert len(spans) == 1
    return spans[0]


def _tags(span: dict) -> dict:
    out = {}
    for t in span["tags"]:
        k, _, v = t.partition(":")
        out[k] = v
    return out


# --- the verdict mapping -----------------------------------------------------------

@pytest.mark.parametrize("verdict,status", [(V.VERIFIED, "ok"), (V.BROKEN, "error"),
                                            (V.COULD_NOT_LOOK, "ok")])
def test_each_verdict_maps_to_status_and_tag(verdict, status):
    s = _span(DD.to_llmobs(_report(verdict), now=NOW))
    assert s["status"] == status
    assert _tags(s)["arcaeon.verdict"] == TOKEN[verdict]
    assert s["meta"]["metadata"]["arcaeon.verdict"] == verdict
    assert s["meta"]["kind"] == "task"
    assert s["metrics"]["arcaeon.verified"] == (1.0 if verdict == V.VERIFIED else 0.0)
    assert s["metrics"]["arcaeon.broken"] == (1.0 if verdict == V.BROKEN else 0.0)
    assert s["metrics"]["arcaeon.could_not_look"] == (1.0 if verdict == V.COULD_NOT_LOOK
                                                      else 0.0)
    if verdict == V.BROKEN:
        assert s["meta"]["error"]["type"] == "arcaeon.BROKEN"
    else:
        assert "error" not in s["meta"]


def test_verified_is_emitted_by_default():
    """Unlike the SIEM export, every check is a span: VERIFIED is not skipped."""
    assert DD.to_llmobs(_report(V.VERIFIED), now=NOW)["data"]["attributes"]["spans"]


def test_could_not_look_names_its_reason_word_only():
    s = _span(DD.to_llmobs(_report(V.COULD_NOT_LOOK), now=NOW))
    assert _tags(s)["arcaeon.could_not_look"] == "missing"
    assert s["metrics"]["arcaeon.not_checked"] == 1.0


def test_gate_refusal_of_a_verified_envelope_is_never_verified():
    d = {"verdict": V.VERIFIED, "action": "pay", "decision": "refuse", "reason": SECRET,
         "report": _report(V.VERIFIED),
         "checks": {"veto": "checker-broken", "rows": 1, "broken": [{"checker": SECRET}]}}
    s = _span(DD.to_llmobs(d, now=NOW))
    t = _tags(s)
    assert t["arcaeon.verdict"] == "BROKEN" and s["status"] == "error"
    assert t["arcaeon.envelope_verdict"] == "VERIFIED"
    assert t["arcaeon.veto"] == "checker-broken" and t["arcaeon.decision"] == "refuse"
    assert t["arcaeon.action"] == "pay" and t["arcaeon.source"] == "gate_decision"
    assert s["metrics"]["arcaeon.checks_broken"] == 1.0
    assert s["name"] == "arcaeon.gate.decide"
    d["checks"]["veto"] = "checks-unreadable"
    s = _span(DD.to_llmobs(d, now=NOW))
    assert _tags(s)["arcaeon.verdict"] == "COULD_NOT_LOOK" and s["status"] == "error"


def _gate(verdict: str, decision: str, veto: str | None = None, action: str = "pay") -> dict:
    d = {"verdict": verdict, "action": action, "decision": decision, "reason": SECRET,
         "report": _report(verdict)}
    if veto:
        d["checks"] = {"veto": veto, "rows": 1, "broken": []}
    return d


def _evidence(verdict: str, decision: str) -> dict:
    return {"kind": "arcaeon.gate.evidence/v1", "verdict": verdict, "action": "act",
            "decision": decision, "reason": SECRET, "reasons": [SECRET],
            "report": _report(verdict), "file": {"path": "/srv/x/" + SECRET, "sha256": SHA}}


@pytest.mark.parametrize("obj", [
    _gate(V.COULD_NOT_LOOK, "refuse"),
    _gate(V.VERIFIED, "refuse", veto="checks-unreadable"),
    _gate(V.VERIFIED, "refuse", veto="nonparty-check"),
    _evidence(V.COULD_NOT_LOOK, "refuse"),
], ids=["cnl-refuse", "veto-checks-unreadable", "veto-nonparty-check", "evidence-cnl-refuse"])
def test_could_not_look_on_a_refused_gate_is_an_error_span(obj):
    """The gate stopped the action: the span is an error, like OCSF's alert."""
    s = _span(DD.to_llmobs(obj, now=NOW))
    t = _tags(s)
    assert t["arcaeon.verdict"] == "COULD_NOT_LOOK" and t["arcaeon.decision"] == "refuse"
    assert s["status"] == "error"


@pytest.mark.parametrize("obj", [
    _report(V.COULD_NOT_LOOK),
    _gate(V.COULD_NOT_LOOK, "allow", action="read"),
    _evidence(V.COULD_NOT_LOOK, "allow"),
], ids=["verify-report", "gate-allow", "evidence-allow"])
def test_could_not_look_without_a_refusal_is_ok_and_tagged(obj):
    s = _span(DD.to_llmobs(obj, now=NOW))
    assert s["status"] == "ok"
    assert [t for t in s["tags"] if t.startswith("arcaeon.verdict:")] == [
        "arcaeon.verdict:COULD_NOT_LOOK"]


_EVERY_INPUT = [(v, o) for v in (V.VERIFIED, V.BROKEN, V.COULD_NOT_LOOK)
                for o in (_report(v), _gate(v, "allow", action="read"), _gate(v, "refuse"),
                          _evidence(v, "allow"), _evidence(v, "refuse"))]


@pytest.mark.parametrize("verdict,obj", _EVERY_INPUT)
def test_every_span_carries_exactly_one_verdict_tag_matching_its_word(verdict, obj):
    s = _span(DD.to_llmobs(obj, now=NOW))
    vt = [t for t in s["tags"] if t.startswith("arcaeon.verdict:")]
    word = s["meta"]["metadata"]["arcaeon.verdict"]
    assert vt == ["arcaeon.verdict:" + TOKEN[word]]
    assert " " not in vt[0]
    # status follows the word, and a refusal never reads ok unless VERIFIED survived it
    want = "error" if word == V.BROKEN or (word == V.COULD_NOT_LOOK
                                           and obj.get("decision") == "refuse") else "ok"
    assert s["status"] == want


def test_not_an_arcaeon_verdict_is_refused():
    for bad in ({"x": 1}, {"verdict": "MATCHED"}, {"verdict": None}, [], [{"x": 1}], 5,
                [_report(V.BROKEN)] * (DD.MAX_SPANS + 1)):
        with pytest.raises(DD.ExportError):
            DD.to_llmobs(bad, now=NOW)


# --- content never leaves ----------------------------------------------------------

@pytest.mark.parametrize("verdict", [V.VERIFIED, V.BROKEN, V.COULD_NOT_LOOK])
def test_no_content_leaves(verdict):
    text = DD.dumps(DD.to_llmobs(_report(verdict), now=NOW))
    assert SECRET not in text
    assert SECRET.lower() not in text.lower()
    assert "/srv/" not in text and ".csv" not in text and "did:key" not in text


def test_no_content_leaves_from_a_gate_decision_or_evidence_pack():
    rep = _report(V.BROKEN)
    gate = {"verdict": V.BROKEN, "action": SECRET, "decision": "refuse", "reason": SECRET,
            "audience": SECRET, "deal": SECRET, "purpose": SECRET, "signers": [SECRET],
            "at": "2026-10-05T11:00:00Z", "file": rep["file"], "envelope": rep["envelope"],
            "evidence": "/srv/" + SECRET, "report": rep, "reasons": [SECRET]}
    ev = {"kind": "arcaeon.gate.evidence/v1", "verdict": V.BROKEN, "action": "act",
          "decision": "refuse", "reason": SECRET, "reasons": [SECRET], "report": rep,
          "file": {"path": rep["file"], "sha256": SHA},
          "envelope": {"path": rep["envelope"], "sha256": "d" * 64}}
    for obj in (gate, ev):
        text = DD.dumps(DD.to_llmobs(obj, now=NOW))
        assert SECRET not in text, obj.get("kind")
    t = _tags(_span(DD.to_llmobs(gate, now=NOW)))
    assert "arcaeon.action" not in t             # not one of the gate's four actions
    t = _tags(_span(DD.to_llmobs(ev, now=NOW)))
    assert t["arcaeon.file_sha256"] == SHA and t["arcaeon.envelope_sha256"] == "d" * 64


def test_io_carries_digests_only():
    s = _span(DD.to_llmobs(_report(V.BROKEN), now=NOW))
    assert set(s["meta"]["input"]) == {"value"} and set(s["meta"]["output"]) == {"value"}
    assert s["meta"]["input"]["value"] == "sha256:" + SHA
    assert s["meta"]["metadata"]["arcaeon.input_digest_of"] == "the checked file"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", s["meta"]["output"]["value"])
    r = _report(V.BROKEN)
    del r["file_sha256"]
    s = _span(DD.to_llmobs(r, now=NOW))
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", s["meta"]["input"]["value"])
    assert s["meta"]["metadata"]["arcaeon.input_digest_of"] == "the arcaeon input document"


# --- stable ids from digests -------------------------------------------------------

def test_ids_are_stable_digests_and_ignore_export_time():
    a = _span(DD.to_llmobs(_report(V.BROKEN), now=NOW))
    b = _span(DD.to_llmobs(_report(V.BROKEN), now=datetime(2026, 10, 5, 13, tzinfo=timezone.utc)))
    assert (a["span_id"], a["trace_id"]) == (b["span_id"], b["trace_id"])
    assert a["start_ns"] != b["start_ns"]
    assert re.fullmatch(r"[0-9a-f]{32}", a["trace_id"]) and a["trace_id"] != "0" * 32
    assert re.fullmatch(r"[1-9][0-9]*", a["span_id"]) and 0 < int(a["span_id"]) < 2 ** 63
    assert a["parent_id"] == "undefined"
    rec = _tags(a)["arcaeon.record_sha256"]
    assert a["meta"]["output"]["value"] == "sha256:" + rec
    c = _span(DD.to_llmobs(_report(V.COULD_NOT_LOOK), now=NOW))
    assert c["span_id"] != a["span_id"] and c["trace_id"] != a["trace_id"]


def test_a_list_gives_one_span_and_one_trace_each():
    body = DD.to_llmobs([_report(V.BROKEN), _report(V.VERIFIED)], now=NOW)
    spans = body["data"]["attributes"]["spans"]
    assert [_tags(s)["arcaeon.verdict"] for s in spans] == ["BROKEN", "VERIFIED"]
    assert len({s["trace_id"] for s in spans}) == 2


# --- the documented shape ----------------------------------------------------------

def _check_shape(body: dict) -> None:
    assert set(body) == {"data"}
    assert body["data"]["type"] == "span" and set(body["data"]) == {"type", "attributes"}
    at = body["data"]["attributes"]
    assert set(at) <= SPANS_PAYLOAD_KEYS and {"ml_app", "spans"} <= set(at)
    assert all(isinstance(t, str) for t in at.get("tags", []))
    for s in at["spans"]:
        assert SPAN_REQUIRED <= set(s) <= SPAN_KEYS, set(s) ^ SPAN_KEYS
        assert isinstance(s["name"], str) and isinstance(s["span_id"], str)
        assert isinstance(s["trace_id"], str) and isinstance(s["parent_id"], str)
        assert type(s["start_ns"]) is int and s["start_ns"] > 0
        assert isinstance(s["duration"], (int, float)) and s["duration"] >= 0
        assert s.get("status", "ok") in ("ok", "error")
        assert set(s["meta"]) <= META_KEYS and s["meta"]["kind"] in KINDS
        assert set(s["meta"].get("error", {})) <= ERROR_KEYS
        for k, v in s["meta"].get("metadata", {}).items():
            assert isinstance(k, str) and isinstance(v, (str, bool, float)), k
        for k, v in s.get("metrics", {}).items():
            assert isinstance(k, str) and type(v) is float, k
        assert all(isinstance(t, str) and ":" in t for t in s.get("tags", []))


@pytest.mark.parametrize("verdict", [V.VERIFIED, V.BROKEN, V.COULD_NOT_LOOK])
def test_documented_required_fields_and_no_invented_names(verdict):
    body = DD.to_llmobs(_report(verdict), now=NOW, service="checks-svc")
    _check_shape(body)
    s = _span(body)
    assert body["data"]["attributes"]["ml_app"] == "arcaeon"
    assert s["start_ns"] == NOW_NS and s["service"] == "checks-svc"


@pytest.mark.parametrize("name", ["arcaeon", "my-app/checks:v1.2", "a_b"])
def test_ml_app_names_that_follow_the_guidelines(name):
    assert DD.to_llmobs(_report(V.BROKEN), now=NOW, ml_app=name)["data"]["attributes"][
        "ml_app"] == name


@pytest.mark.parametrize("name", ["", "Arcaeon", "a__b", "a_", "has space", "x" * 194, "é!"])
def test_ml_app_names_against_the_guidelines_are_refused(name):
    with pytest.raises(ValueError):
        DD.to_llmobs(_report(V.BROKEN), now=NOW, ml_app=name)


@pytest.mark.parametrize("verdict", [V.VERIFIED, V.BROKEN, V.COULD_NOT_LOOK])
def test_fixture_per_verdict(verdict):
    """tests/fixtures/datadog_llmobs/<word>.llmobs.json is the body for
    tests/fixtures/ocsf/<word>.report.json at NOW: byte for byte."""
    src = json.loads((OCSF_FIX / f"{SLUG[verdict]}.report.json").read_text(encoding="utf-8"))
    want = (FIX / f"{SLUG[verdict]}.llmobs.json").read_text(encoding="utf-8")
    got = DD.dumps(DD.to_llmobs(src, now=NOW))
    assert got == want
    _check_shape(json.loads(want))
    assert "grades.csv" not in want and "/srv/" not in want


def test_module_cites_the_doc_and_sends_nothing():
    src = (ROOT / "src" / "arcaeon" / "prove" / "datadog_llmobs.py").read_text(encoding="utf-8")
    assert DD.DOC_URL in src and DD.DOC_URL.startswith("https://docs.datadoghq.com/")
    assert DD.INTAKE_PATH == "/api/intake/llm-obs/v1/trace/spans"
    for banned in ("urllib", "http.client", "requests", "socket", "httpx", "DD_API_KEY\"]",
                   "os.environ"):
        assert banned not in src, banned


# --- real seals and gate decisions --------------------------------------------------

def _sealed(tmp_path: Path, verdict: str):
    pytest.importorskip("cryptography", reason="signing needs the [sign] extra")
    f = tmp_path / "in" / "grades.csv"
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(b"name,grade\n" + SECRET.encode() + b",pass\n")
    key = None
    if verdict != V.COULD_NOT_LOOK:
        key = tmp_path / "test-only.seal.key"
        key.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
                       encoding="ascii")
    env = E.seal(f, key_file=key, label="week 3", audience="instructor-1", deal="d-7f3a",
                 purpose="grading", not_after="7d")
    sigs = env["dsseEnvelope"]["signatures"]
    if verdict == V.BROKEN:
        f.write_bytes(f.read_bytes() + b"x\n")
    return f, (sigs[0]["keyid"] if sigs else "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")


@pytest.mark.parametrize("verdict", [V.VERIFIED, V.BROKEN, V.COULD_NOT_LOOK])
def test_real_verify_report_and_gate_decision(tmp_path, verdict):
    f, did = _sealed(tmp_path, verdict)
    r = E.verify(f, audience="instructor-1", signers=[did], deal="d-7f3a", now=NOW)
    assert r["verdict"] == verdict
    d = G.decide(f, action="pay", audience="instructor-1", signers=[did], deal="d-7f3a",
                 purpose="grading", ledger=tmp_path / "tape.jsonl",
                 record_dir=tmp_path / "rec", now=NOW).to_dict()
    for obj in (r, d):
        body = DD.to_llmobs(obj, now=NOW)
        _check_shape(body)
        assert _tags(_span(body))["arcaeon.verdict"] == TOKEN[verdict]
        text = DD.dumps(body)
        assert str(tmp_path) not in text and "grades.csv" not in text
        assert str(tmp_path).replace("\\", "/") not in text


# --- CLI -------------------------------------------------------------------------

def test_cli_export_datadog(tmp_path, capsys):
    from arcaeon import cli
    p = tmp_path / "r.json"
    p.write_text(json.dumps(_report(V.BROKEN)), encoding="utf-8")
    argv = ["envelope", "export-datadog", str(p), "--now", "2026-10-05T12:00:00.123456Z"]
    assert cli.main(argv) == 0
    first = capsys.readouterr().out
    assert _span(json.loads(first))["start_ns"] == NOW_NS
    assert SECRET not in first
    assert cli.main(argv) == 0
    assert capsys.readouterr().out == first
    out = tmp_path / "body.json"
    assert cli.main(argv + ["--out", str(out)]) == 0
    assert out.read_text(encoding="utf-8") == first
    assert capsys.readouterr().out.strip() == str(out)
    assert cli.main(argv + ["--ml-app", "checks", "--service", "svc"]) == 0
    b = json.loads(capsys.readouterr().out)
    assert b["data"]["attributes"]["ml_app"] == "checks" and _span(b)["service"] == "svc"


def test_cli_verified_is_exported(tmp_path, capsys):
    from arcaeon import cli
    p = tmp_path / "r.json"
    p.write_text(json.dumps(_report(V.VERIFIED)), encoding="utf-8")
    assert cli.main(["envelope", "export-datadog", str(p)]) == 0
    assert _tags(_span(json.loads(capsys.readouterr().out)))["arcaeon.verdict"] == "VERIFIED"


def test_cli_bad_input_and_usage(tmp_path, capsys):
    from arcaeon import cli
    bad = tmp_path / "bad.json"
    bad.write_text('{"verdict": "BROKEN", "verdict": "VERIFIED"}', encoding="utf-8")
    assert cli.main(["envelope", "export-datadog", str(bad)]) == 3
    assert cli.main(["envelope", "export-datadog", str(tmp_path / "missing.json")]) == 3
    assert str(tmp_path) not in capsys.readouterr().err
    good = tmp_path / "r.json"
    good.write_text(json.dumps(_report(V.BROKEN)), encoding="utf-8")
    assert cli.main(["envelope", "export-datadog"]) == 2
    assert cli.main(["envelope", "export-datadog", str(good), "--now", "noon"]) == 2
    assert cli.main(["envelope", "export-datadog", str(good), "--ml-app", "Bad App"]) == 2
    assert cli.main(["envelope", "export-datadog", str(good), "--api-key", "x"]) == 2


# --- the doc ---------------------------------------------------------------------

def test_doc_cites_the_page_and_has_limits():
    doc = (ROOT / "docs" / "DATADOG_LLM_OBS.md").read_text(encoding="utf-8")
    assert DD.DOC_URL in doc and DD.INTAKE_PATH in doc and DD.DOC_READ_ON in doc
    assert "DD-API-KEY" in doc
    for word in ("arcaeon.verdict:BROKEN", "arcaeon.verdict:COULD_NOT_LOOK", "status",
                 "span_id", "trace_id", "start_ns", "ml_app"):
        assert word in doc, word
    assert "## What it cannot prove" in doc
    assert "| COULD NOT LOOK, gate refused | `error` | `arcaeon.verdict:COULD_NOT_LOOK` |" in doc
    low = doc.lower()
    assert "nothing" in low and "sent" in low
    assert "—" not in doc and "–" not in doc
