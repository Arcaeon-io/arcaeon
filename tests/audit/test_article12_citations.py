"""K050: the Article 12 citations in the export say what the Act says.

Periods of use, reference database and input data are Art.12(3)(a), (b), (c).
Traceability stays Art.12(2). Through 0.9.1 the summary cited Art.12(2)(a).
"""
import inspect
import json

import arcaeon.prove.audit as audit
from arcaeon.prove.audit import AuditLog


def _summary(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl", system_id="sys-1", provider="Acme")
    log.record(event="system_start", agent="sys-1")
    log.record(event="reference_check", agent="sys-1", inputs={"db": "ref-v1"})
    log.record(event="system_stop", agent="sys-1")
    out = log.export_bundle(tmp_path / "out")
    return (out / "ARTICLE_12_SUMMARY.md").read_text(encoding="utf-8")


def test_summary_cites_12_3_not_12_2_a(tmp_path):
    s = _summary(tmp_path)
    assert "Art.12(3)(a)" in s
    assert "Art.12(3)(b)" in s
    assert "Art.12(3)(c)" in s
    assert "Art.12(2)(a)" not in s
    assert "Art.12(2)(b)" not in s
    assert "Art.12(2)(c)" not in s


def test_traceability_stays_12_2(tmp_path):
    assert "Traceability appropriate to the intended purpose (Art.12(2)):" in _summary(tmp_path)


def test_event_type_comments_cite_12_3():
    src = inspect.getsource(audit)
    assert "periods of use (Art.12(3)(a))" in src
    assert "reference DB (Art.12(3)(c),(b))" in src
    assert "Art.12(2)(a)" not in src
