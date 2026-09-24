"""load_probes() + probe_set_digest() + validation of the two shipped
starter sets. Run: python test_probes.py (or pytest)."""
import json
import tempfile
from pathlib import Path

from arcaeon.prove.baseline import Probe, load_probes, probe_set_digest

# arcaeon merge: the two starter sets ship as package data now (wheel AND sdist),
# at arcaeon/prove/baseline/probes/, instead of only in the old sdist.
REPO_ROOT = Path(__file__).resolve().parents[2] / "src" / "arcaeon" / "prove" / "baseline"
REASONING = REPO_ROOT / "probes" / "reasoning.jsonl"
CALIBRATION = REPO_ROOT / "probes" / "calibration.jsonl"


def _write(dirpath: Path, name: str, lines: list[dict]) -> Path:
    p = dirpath / name
    p.write_text("\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8")
    return p


def test_load_single_file():
    with tempfile.TemporaryDirectory() as td:
        p = _write(Path(td), "a.jsonl", [
            {"id": "a", "prompt": "p1", "scoring": {"type": "exact_match", "answer": "x"}},
            {"id": "b", "prompt": "p2", "scoring": {"type": "exact_match", "answer": "y"}},
        ])
        probes = load_probes(p)
        assert [pr.id for pr in probes] == ["a", "b"]


def test_load_directory_merges_all_jsonl_files_sorted_by_id():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        _write(td, "z.jsonl", [{"id": "z1", "prompt": "p", "scoring":
                                {"type": "exact_match", "answer": "x"}}])
        _write(td, "a.jsonl", [{"id": "a1", "prompt": "p", "scoring":
                                {"type": "exact_match", "answer": "x"}}])
        probes = load_probes(td)
        assert [pr.id for pr in probes] == ["a1", "z1"]   # sorted by id, not filename


def test_blank_lines_ignored():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "f.jsonl"
        p.write_text(
            '{"id": "a", "prompt": "p", "scoring": {"type": "exact_match", "answer": "x"}}\n'
            '\n'
            '   \n'
            '{"id": "b", "prompt": "p", "scoring": {"type": "exact_match", "answer": "x"}}\n',
            encoding="utf-8")
        assert len(load_probes(p)) == 2


def test_missing_path_raises_file_not_found():
    try:
        load_probes("/nonexistent/path/does-not-exist")
        assert False
    except FileNotFoundError:
        pass


def test_empty_probe_set_raises():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "empty.jsonl"
        p.write_text("\n\n", encoding="utf-8")
        try:
            load_probes(p)
            assert False
        except ValueError as e:
            assert "zero valid probes" in str(e)


def test_invalid_json_line_names_file_and_line_number():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "bad.jsonl"
        p.write_text('{"id": "a", "prompt": "p", "scoring": {"type": "exact_match", "answer": "x"}}\n'
                     'not json\n', encoding="utf-8")
        try:
            load_probes(p)
            assert False
        except ValueError as e:
            assert "bad.jsonl:2" in str(e)


def test_calibration_scoring_requires_answerable_field():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "c.jsonl"
        p.write_text('{"id": "a", "prompt": "p", "scoring": {"type": "calibration"}}\n',
                     encoding="utf-8")
        try:
            load_probes(p)
            assert False
        except ValueError as e:
            assert "answerable" in str(e)


# --- AUDIT 2026-09-01: answer validation moved to LOAD time -----------------
# Before: a probe with a missing/mistyped `answer` loaded fine and blew up
# inside score_item() — after the runner had been paid for every item up to
# it, and outside run_probes' error handling, so the whole batch was lost.

def _expect_load_error(td: Path, scoring: dict, needle: str) -> None:
    p = Path(td) / "v.jsonl"
    p.write_text(json.dumps({"id": "a", "prompt": "p", "scoring": scoring}) + "\n",
                 encoding="utf-8")
    try:
        load_probes(p)
        assert False, f"loaded a probe whose scoring should be rejected: {scoring}"
    except ValueError as e:
        assert "v.jsonl:1" in str(e)
        assert needle in str(e)


def test_exact_match_requires_a_string_answer_at_load_time():
    with tempfile.TemporaryDirectory() as td:
        _expect_load_error(td, {"type": "exact_match"}, "answer")             # KeyError before
        _expect_load_error(td, {"type": "exact_match", "answer": 42}, "answer")  # TypeError before


def test_numeric_tolerance_requires_numeric_answer_and_tolerance_at_load_time():
    with tempfile.TemporaryDirectory() as td:
        _expect_load_error(td, {"type": "numeric_tolerance"}, "answer")
        _expect_load_error(td, {"type": "numeric_tolerance", "answer": "forty"}, "answer")
        _expect_load_error(td, {"type": "numeric_tolerance", "answer": True}, "answer")
        _expect_load_error(td, {"type": "numeric_tolerance", "answer": 4,
                                "tolerance": "loose"}, "tolerance")
        # what already worked keeps working: ints, floats, numeric strings
        p = _write(Path(td), "ok.jsonl", [
            {"id": "a", "prompt": "p", "scoring": {"type": "numeric_tolerance", "answer": 4}},
            {"id": "b", "prompt": "p", "scoring": {"type": "numeric_tolerance", "answer": "4.5",
                                                   "tolerance": 0.1}},
        ])
        assert len(load_probes(p)) == 2


def test_answerable_calibration_requires_a_string_answer_and_bool_answerable():
    with tempfile.TemporaryDirectory() as td:
        _expect_load_error(td, {"type": "calibration", "answerable": True}, "answer")
        _expect_load_error(td, {"type": "calibration", "answerable": "yes",
                                "answer": "x"}, "answerable")
        p = _write(Path(td), "ok.jsonl", [
            {"id": "a", "prompt": "p", "scoring": {"type": "calibration", "answerable": False}},
        ])
        assert len(load_probes(p)) == 1


def test_deeply_nested_line_is_a_value_error_not_a_recursion_error():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "deep.jsonl"
        p.write_text("[" * 100000 + "]" * 100000 + "\n", encoding="utf-8")
        try:
            load_probes(p)
            assert False
        except ValueError as e:
            assert "deep.jsonl:1" in str(e)


def test_lone_surrogate_escape_is_rejected_at_load_not_at_register_write():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "sur.jsonl"
        p.write_bytes(b'{"id": "a", "prompt": "\\udc80", '
                      b'"scoring": {"type": "exact_match", "answer": "x"}}\n')
        try:
            load_probes(p)
            assert False
        except ValueError as e:
            assert "surrogate" in str(e)


def test_digest_reorder_invariant_content_sensitive():
    a = [Probe("1", "x", {"type": "exact_match", "answer": "x"}),
        Probe("2", "y", {"type": "exact_match", "answer": "y"})]
    b = list(reversed(a))
    assert probe_set_digest(a) == probe_set_digest(b)
    c = [Probe("1", "x", {"type": "exact_match", "answer": "x"}),
        Probe("2", "y", {"type": "exact_match", "answer": "DIFFERENT"})]
    assert probe_set_digest(a) != probe_set_digest(c)


def test_digest_is_self_describing():
    a = [Probe("1", "x", {"type": "exact_match", "answer": "x"})]
    d = probe_set_digest(a)
    assert d.startswith("sha256:json-c14n:v1:")
    assert len(d.split(":")) == 4


# --- the two shipped starter sets ------------------------------------------

def test_shipped_reasoning_set_loads_and_has_15_deterministic_items():
    probes = load_probes(REASONING)
    assert len(probes) == 15
    for p in probes:
        assert p.scoring["type"] in ("exact_match", "numeric_tolerance")
        assert "answer" in p.scoring


def test_shipped_calibration_set_loads_and_has_15_mixed_items():
    probes = load_probes(CALIBRATION)
    assert len(probes) == 15
    for p in probes:
        assert p.scoring["type"] == "calibration"
    answerable = [p for p in probes if p.scoring["answerable"]]
    unanswerable = [p for p in probes if not p.scoring["answerable"]]
    # both classes genuinely present — a set that's all-answerable or
    # all-unanswerable can't exercise the abstention-gaming guard at all
    assert len(answerable) >= 5
    assert len(unanswerable) >= 5
    for p in answerable:
        assert "answer" in p.scoring


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\nALL {len(fns)} TESTS PASSED")
