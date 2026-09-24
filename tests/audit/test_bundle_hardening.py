"""0.1.8 — sell-code audit, 2026-09-01. Each test was RED against 0.1.7.

Five findings, all in the bundle a regulator reads or the API a customer
calls; none changes a verdict on a well-formed log:

  1. the `curl` re-verify command interpolated the namespace raw into a
     single-quoted shell string (command injection into a copy-paste line);
  2. a witness_descriptor() could write ANY string into `kind` and
     `independence` (the two fields a PASS is weighed on);
  3. `truncation_ok: false` shipped beside WITNESS_CHECK_FAILED — an
     accusation in a field, a non-accusation in the prose;
  4. integrity.json and manifest.json disagreed on the row count of one
     bundle (two decoders, two rules);
  5. `record(authority=..., chain=...)` silently dropped the caller's data,
     against the reserved-key rule's own stated reason.
"""
import json
import tempfile
from pathlib import Path

import pytest

from arcaeon.prove.audit import AuditLog, export_bundle, _read_rows
from arcaeon.record.ledger import Ledger
from arcaeon.record.ledger.witness import WitnessStore, publish_head


def _log(d, n=3):
    p = Path(d) / "audit.jsonl"
    log = AuditLog(p, system_id="triage-v3", provider="Acme AI")
    for i in range(n):
        log.record(event="decision", agent="triage-v3", decision=f"d{i}")
    return log, p


def _integrity(out):
    return json.loads((out / "integrity.json").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# 1. the re-verify command is safe to paste
# --------------------------------------------------------------------------

def test_namespace_cannot_break_out_of_the_curl_command():
    ns = "acme'; echo PWNED; echo '"
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d)
        store = WitnessStore(Path(d) / "w.jsonl")
        publish_head(store, ns, Ledger(p))
        out = export_bundle(p, Path(d) / "bundle", witness=store, witness_namespace=ns)
        run = _integrity(out)["how_to_reverify"]["step_2_completeness_INDEPENDENT"]["run"]
        summary = (out / "ARTICLE_12_SUMMARY.md").read_text(encoding="utf-8")
        curl_lines = [l for l in summary.splitlines() if "curl" in l]
        assert curl_lines, summary
        for cmd in [run, *curl_lines]:
            # exactly one single-quoted argument: the opening and closing quote
            assert cmd.count("'") == 2, cmd
            assert "; echo" not in cmd, cmd
            assert "ns=acme%27%3B%20echo%20PWNED%3B%20echo%20%27&rows=3&chain=" in cmd, cmd


def test_namespace_with_query_metacharacters_is_encoded_not_rewritten():
    ns = "acme/prod&rows=999#x"
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d)
        store = WitnessStore(Path(d) / "w.jsonl")
        publish_head(store, ns, Ledger(p))
        out = export_bundle(p, Path(d) / "bundle", witness=store, witness_namespace=ns)
        run = _integrity(out)["how_to_reverify"]["step_2_completeness_INDEPENDENT"]["run"]
        assert "ns=acme%2Fprod%26rows%3D999%23x&rows=3&chain=" in run, run


# --------------------------------------------------------------------------
# 2. a descriptor speaks only the documented vocabulary
# --------------------------------------------------------------------------

class _Declaring:
    def __init__(self, inner, descriptor):
        self._inner, self._d = inner, descriptor

    def latest(self, namespace):
        return self._inner.latest(namespace)

    def witness_descriptor(self):
        return self._d


@pytest.mark.parametrize("claimed", ["CERTIFIED_BY_REGULATOR", "none", "", 7, None])
def test_undocumented_independence_label_is_undeclared(claimed):
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d)
        inner = WitnessStore(Path(d) / "w.jsonl")
        publish_head(inner, "ns", Ledger(p))
        w = _Declaring(inner, {"kind": "remote_url", "identifier": "https://x.example/",
                               "independence": claimed})
        out = export_bundle(p, Path(d) / "bundle", witness=w, witness_namespace="ns")
        block = _integrity(out)["witness"]
        assert block["independence"] == "undeclared", block
        assert block["independence_source"] == "self_declared_by_witness"


@pytest.mark.parametrize("kind", ["none", "local_file", "notary", "", 3])
def test_undocumented_kind_falls_to_the_conservative_default(kind):
    """`kind: none` in particular made the summary drop its independence
    paragraph, because none means 'no witness'. A witness that IS consulted
    cannot describe itself as absent."""
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d)
        inner = WitnessStore(Path(d) / "w.jsonl")
        publish_head(inner, "ns", Ledger(p))
        w = _Declaring(inner, {"kind": kind, "identifier": "https://x.example/",
                               "independence": "externally_verifiable"})
        out = export_bundle(p, Path(d) / "bundle", witness=w, witness_namespace="ns")
        block = _integrity(out)["witness"]
        assert block["kind"] == "remote_url", block
        assert block["independence"] != "externally_verifiable", block
        assert block["independence_source"] == "conservative_default"
        summary = (out / "ARTICLE_12_SUMMARY.md").read_text(encoding="utf-8")
        assert "Witness independence — kind: remote_url" in summary


def test_documented_declarations_still_pass_through():
    """GREEN CONTROL: the allowlist must not eat the legitimate vocabulary."""
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d)
        inner = WitnessStore(Path(d) / "w.jsonl")
        publish_head(inner, "ns", Ledger(p))
        w = _Declaring(inner, {"kind": "opentimestamps", "identifier": "ots:abc",
                               "independence": "externally_verifiable"})
        out = export_bundle(p, Path(d) / "bundle", witness=w, witness_namespace="ns")
        block = _integrity(out)["witness"]
        assert block["kind"] == "opentimestamps"
        assert block["independence"] == "externally_verifiable"


# --------------------------------------------------------------------------
# 3. a comparison that never ran is None, not False
# --------------------------------------------------------------------------

def test_broken_witness_does_not_report_truncation_ok_false():
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d)
        store = WitnessStore(Path(d) / "w.jsonl")
        publish_head(store, "ns", Ledger(p))
        publish_head(store, "ns", Ledger(p))
        lines = store.path.read_text(encoding="utf-8").splitlines()
        lines[0] = lines[0].replace('"rows": 3', '"rows": 9')
        store.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        out = export_bundle(p, Path(d) / "bundle", witness=store, witness_namespace="ns")
        integ = _integrity(out)
        assert integ["witness"]["verdict"] == "witness_broken"
        assert integ["finding"] == "WITNESS_CHECK_FAILED"
        assert integ["truncation_checked"] is True
        assert integ["truncation_ok"] is None, integ


def test_unrecognized_witness_verdict_leaves_truncation_ok_unknown():
    class _Weird:
        def latest(self, ns):
            return None

    from arcaeon.record.ledger.witness import WitnessVerdict
    import arcaeon.prove.audit

    def fake(store, namespace, ledger):
        return WitnessVerdict("quantum_uncertain", "no idea", witness_rows=3,
                              witness_chain="ab", local_rows=3)

    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d)
        real = arcaeon.prove.audit.verify_against_witness
        arcaeon.prove.audit.verify_against_witness = fake
        try:
            out = export_bundle(p, Path(d) / "bundle", witness=_Weird(),
                                witness_namespace="ns")
        finally:
            arcaeon.prove.audit.verify_against_witness = real
        integ = _integrity(out)
        assert integ["finding"] == "UNRECOGNIZED_WITNESS_VERDICT:quantum_uncertain"
        assert integ["truncation_ok"] is None, integ


# --------------------------------------------------------------------------
# 6. the summary carries the witness's actual detail, not a stand-in
# --------------------------------------------------------------------------

def test_truncation_summary_carries_the_witness_row_arithmetic():
    """WitnessVerdict is truthy only on 'consistent', so `wv.detail if wv else
    ...` printed the fallback for every accusation. integrity.json had the
    numbers; the page a regulator reads said 'the witness reported truncation'."""
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d, n=4)
        store = WitnessStore(Path(d) / "w.jsonl")
        publish_head(store, "ns", Ledger(p))
        lines = p.read_text(encoding="utf-8").splitlines()
        p.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
        out = export_bundle(p, Path(d) / "bundle", witness=store, witness_namespace="ns")
        summary = (out / "ARTICLE_12_SUMMARY.md").read_text(encoding="utf-8")
        detail = _integrity(out)["witness"]["detail"]
        assert "log has 2 rows but the witness recorded 4" in detail
        assert detail in summary, summary
        assert "but the witness reported truncation." not in summary


def test_witness_check_failed_summary_names_the_actual_fault():
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d)
        store = WitnessStore(Path(d) / "w.jsonl")
        out = export_bundle(p, Path(d) / "bundle", witness=store, witness_namespace="typo")
        summary = (out / "ARTICLE_12_SUMMARY.md").read_text(encoding="utf-8")
        assert _integrity(out)["finding"] == "WITNESS_CHECK_FAILED"
        assert "witness holds no pin for namespace 'typo'" in summary, summary
        assert "witness unavailable" not in summary


# --------------------------------------------------------------------------
# 4. one bundle, one row count
# --------------------------------------------------------------------------

def test_integrity_and_manifest_agree_on_rows_when_a_byte_is_corrupted():
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d)
        p.write_bytes(p.read_bytes().replace(b'"d1"', b'"d\xff"', 1))
        out = export_bundle(p, Path(d) / "bundle")
        integ = _integrity(out)
        manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        assert integ["finding"] == "FAIL"           # the chain still catches it
        assert manifest["record_count"] == integ["rows"] == 3, (manifest, integ)
        assert manifest["unreadable_lines"] == 0


def test_read_rows_counts_a_pathologically_nested_line_instead_of_crashing():
    rows, unreadable = _read_rows(b'{"event":"x"}\n' + b"[" * 100000 + b"]" * 100000 + b"\n")
    assert len(rows) == 1 and unreadable == 1


# --------------------------------------------------------------------------
# 5. the ledger's stamps are reserved too
# --------------------------------------------------------------------------

@pytest.mark.parametrize("key", ["authority", "chain"])
def test_caller_cannot_supply_a_ledger_stamped_key(key):
    with tempfile.TemporaryDirectory() as d:
        log = AuditLog(Path(d) / "a.jsonl", system_id="s")
        with pytest.raises(ValueError) as e:
            log.record(event="decision", agent="a", **{key: "forged"})
        assert key in str(e.value)
        assert not (Path(d) / "a.jsonl").exists(), "refused rows must not land"
