"""register()/compare() round-trip, digest-mismatch detection, and a real
end-to-end through CmdRunner + subprocess with a trivial echo command (no
ollama or network needed — just the current Python interpreter echoing
stdin to stdout). Run: python test_registration.py (or pytest)."""
import json
import sys
import tempfile
from pathlib import Path

from arcaeon.record.ledger import Ledger

from arcaeon.prove.baseline import (CallableRunner, CmdRunner, compare, load_probes,
                              register)

FIXTURE = [
    {"id": "a", "prompt": "capital of France?",
     "scoring": {"type": "exact_match", "answer": "Paris"}},
    {"id": "b", "prompt": "2 + 2?",
     "scoring": {"type": "numeric_tolerance", "answer": 4, "tolerance": 0}},
]

# A trivial echo command: this Python interpreter, reading stdin and writing
# it straight back to stdout. Portable across the platforms this ships on
# (no dependence on a shell builtin like `cat`/`type`).
ECHO_CMD = f'{json.dumps(sys.executable)} -c "import sys; sys.stdout.write(sys.stdin.read())"'


def _fixture_dir(td: Path) -> Path:
    p = td / "probes.jsonl"
    p.write_text("\n".join(json.dumps(x) for x in FIXTURE) + "\n", encoding="utf-8")
    return p


def test_register_writes_file_and_chains_to_ledger():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        probes_file = _fixture_dir(td)
        probes = load_probes(probes_file)
        ledger_path = td / "ledger.jsonl"

        row, path = register(
            probes, label="unit-test", runner=CallableRunner(lambda p: "Paris"),
            out_dir=td / "regs", ledger_path=ledger_path, probes_path=probes_file)

        assert path.exists()
        on_disk = json.loads(path.read_text(encoding="utf-8"))
        assert on_disk["schema"] == "arcaeon-baseline:registration:v1"
        assert on_disk["probe_count"] == 2
        assert on_disk["label"] == "unit-test"

        led = Ledger(ledger_path)
        assert led.verify().ok
        rows = list(led)
        assert len(rows) == 1
        assert rows[0]["kind"] == "arcaeon_baseline_registration"
        assert rows[0]["probe_set_digest"] == on_disk["probe_set_digest"]


def test_register_records_a_runner_error_without_aborting_the_whole_run():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        probes_file = _fixture_dir(td)
        probes = load_probes(probes_file)

        def flaky(prompt: str) -> str:
            if "France" in prompt:
                raise RuntimeError("boom")
            return "4"

        row, _ = register(probes, label="flaky", runner=CallableRunner(flaky),
                          out_dir=td / "regs", ledger_path=None,
                          probes_path=probes_file)
        assert row["aggregate"]["n"] == 2
        assert row["aggregate"]["n_errors"] == 1
        assert row["aggregate"]["n_scored"] == 1
        errored = [it for it in row["items"] if it["id"] == "a"][0]
        assert errored["score"] is None
        assert "error" in errored


def test_compare_identical_model_zero_flips_zero_delta():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        probes_file = _fixture_dir(td)
        probes = load_probes(probes_file)

        def model(p: str) -> str:
            return "Paris" if "France" in p else "4"

        _, reg_path = register(probes, label="stable", runner=CallableRunner(model),
                               out_dir=td / "regs", ledger_path=None,
                               probes_path=probes_file)
        report, _ = compare(reg_path, runner=CallableRunner(model),
                            probes_path=probes_file, out_dir=td / "cmp",
                            ledger_path=None)
        assert report["valid"] is True
        assert report["n_flips"] == 0
        assert report["aggregate_delta"]["mean"] == 0.0


def test_compare_detects_a_flip_and_reports_negative_delta():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        probes_file = _fixture_dir(td)
        probes = load_probes(probes_file)

        def good(p: str) -> str:
            return "Paris" if "France" in p else "4"

        def worse(p: str) -> str:
            return "Lyon" if "France" in p else "4"     # one item now wrong

        _, reg_path = register(probes, label="before", runner=CallableRunner(good),
                               out_dir=td / "regs", ledger_path=None,
                               probes_path=probes_file)
        report, path = compare(reg_path, runner=CallableRunner(worse),
                               probes_path=probes_file, out_dir=td / "cmp",
                               ledger_path=None)
        assert report["valid"] is True
        assert report["n_flips"] == 1
        assert report["flips"][0]["id"] == "a"
        assert report["flips"][0]["before_score"] == 1.0
        assert report["flips"][0]["after_score"] == 0.0
        assert report["aggregate_delta"]["mean"] < 0
        on_disk = json.loads(path.read_text(encoding="utf-8"))
        assert on_disk == report


# --- digest-mismatch detection ---------------------------------------------

def test_compare_after_probe_edit_is_flagged_invalid_not_silently_wrong():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        probes_file = _fixture_dir(td)
        probes = load_probes(probes_file)

        _, reg_path = register(probes, label="pinned",
                               runner=CallableRunner(lambda p: "Paris"),
                               out_dir=td / "regs", ledger_path=None,
                               probes_path=probes_file)

        # Edit the exam after registering — change the expected answer.
        edited = [dict(FIXTURE[0], scoring={"type": "exact_match", "answer": "Lyon"}),
                 FIXTURE[1]]
        probes_file.write_text(
            "\n".join(json.dumps(x) for x in edited) + "\n", encoding="utf-8")

        report, path = compare(reg_path, runner=CallableRunner(lambda p: "Paris"),
                               probes_path=probes_file, out_dir=td / "cmp",
                               ledger_path=None)
        assert report["valid"] is False
        assert "changed" in report["reason"]
        assert report["registered_probe_set_digest"] != report["current_probe_set_digest"]
        # no misleading diff fields on an invalid report
        assert "flips" not in report
        assert "aggregate_delta" not in report
        on_disk = json.loads(path.read_text(encoding="utf-8"))
        assert on_disk["valid"] is False


def test_compare_after_probe_addition_is_flagged_invalid():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        probes_file = _fixture_dir(td)
        probes = load_probes(probes_file)
        _, reg_path = register(probes, label="pinned",
                               runner=CallableRunner(lambda p: "Paris"),
                               out_dir=td / "regs", ledger_path=None,
                               probes_path=probes_file)

        extended = FIXTURE + [{"id": "c", "prompt": "extra?",
                               "scoring": {"type": "exact_match", "answer": "x"}}]
        probes_file.write_text(
            "\n".join(json.dumps(x) for x in extended) + "\n", encoding="utf-8")

        report, _ = compare(reg_path, runner=CallableRunner(lambda p: "Paris"),
                            probes_path=probes_file, out_dir=td / "cmp",
                            ledger_path=None)
        assert report["valid"] is False


def test_compare_default_probes_path_comes_from_registration():
    """Omitting --probes on compare should fall back to the path recorded
    at register time (a convenience most real usage will rely on)."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        probes_file = _fixture_dir(td)
        probes = load_probes(probes_file)
        _, reg_path = register(probes, label="default-path",
                               runner=CallableRunner(lambda p: "Paris"),
                               out_dir=td / "regs", ledger_path=None,
                               probes_path=probes_file)
        report, _ = compare(reg_path, runner=CallableRunner(lambda p: "Paris"),
                            out_dir=td / "cmp", ledger_path=None)  # no probes_path
        assert report["valid"] is True


def test_compare_missing_probes_path_raises_a_clear_error():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        probes_file = _fixture_dir(td)
        probes = load_probes(probes_file)
        _, reg_path = register(probes, label="no-path-recorded",
                               runner=CallableRunner(lambda p: "Paris"),
                               out_dir=td / "regs", ledger_path=None)  # no probes_path!
        try:
            compare(reg_path, runner=CallableRunner(lambda p: "Paris"),
                   out_dir=td / "cmp", ledger_path=None)
            assert False
        except ValueError as e:
            assert "probes_path" in str(e)


# --- real subprocess end-to-end with a trivial echo-cmd runner -------------

def test_end_to_end_with_trivial_echo_cmd_runner():
    """Full register() -> compare() through CmdRunner + a real subprocess,
    using a trivial stdin-echo command as the "model". Since the echo
    command returns the prompt itself, probes are crafted so the prompt
    text IS a correct/matchable answer for both scoring types."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        echo_probes = [
            {"id": "e1", "prompt": "Paris",
             "scoring": {"type": "exact_match", "answer": "Paris"}},
            {"id": "e2", "prompt": "4",
             "scoring": {"type": "numeric_tolerance", "answer": 4, "tolerance": 0}},
        ]
        probes_file = td / "echo_probes.jsonl"
        probes_file.write_text(
            "\n".join(json.dumps(x) for x in echo_probes) + "\n", encoding="utf-8")
        probes = load_probes(probes_file)

        runner = CmdRunner(ECHO_CMD, timeout=30)
        row, reg_path = register(probes, label="echo-e2e", runner=runner,
                                 out_dir=td / "regs", ledger_path=td / "ledger.jsonl",
                                 probes_path=probes_file)
        assert row["aggregate"]["mean"] == 1.0
        assert row["runner"]["type"] == "cmd"

        report, _ = compare(reg_path, runner=runner, probes_path=probes_file,
                            out_dir=td / "cmp", ledger_path=td / "ledger.jsonl")
        assert report["valid"] is True
        assert report["n_flips"] == 0

        # a real ledger with real chained rows, not a fixture
        led = Ledger(td / "ledger.jsonl")
        assert led.verify().ok
        assert led.verify().rows == 2


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\nALL {len(fns)} TESTS PASSED")


# ---------------------------------------------------------------------------
# AUDIT 2026-09-01. Crash paths a normal caller can reach.
# ---------------------------------------------------------------------------

def test_ledger_path_empty_string_is_the_documented_opt_out_not_a_crash():
    """compare()'s own invalid-reasons say "pass ledger_path='' to compare()
    explicitly to skip this check". The CLI mapped '' -> None; the library
    did not: Path('') is the cwd, .exists() is True, and Ledger('') raised
    PermissionError: '.' — from BOTH register() and compare()."""
    runner = CallableRunner(lambda p: "Paris" if "France" in p else "4")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        probes_file = _fixture_dir(td)
        probes = load_probes(probes_file)
        row, path = register(probes, label="unchained", runner=runner,
                             out_dir=td / "regs", ledger_path="",
                             probes_path=probes_file)
        assert "_ledger_chain" not in row
        report, _ = compare(path, runner=runner, probes_path=probes_file,
                            out_dir=td / "cmp", ledger_path="")
        assert report["valid"] is True
        assert report["chain_check"]["status"] == "skipped_no_ledger_path"
        assert "_ledger_chain" not in report


def test_compare_rejects_a_non_object_registration_with_a_clear_error():
    """A JSON list/scalar where a registration object was expected used to
    surface as AttributeError on `.get`, not the promised 'not a
    registration' ValueError."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        probes_file = _fixture_dir(td)
        for body in ("[1, 2]", '"just a string"', "42"):
            bad = td / "bad.json"
            bad.write_text(body, encoding="utf-8")
            try:
                compare(bad, runner=CallableRunner(lambda p: "x"),
                        probes_path=probes_file, out_dir=td / "cmp", ledger_path=None)
                assert False, body
            except ValueError as e:
                assert "not an arcaeon-baseline registration" in str(e)


def test_a_runner_returning_non_str_is_an_item_error_not_a_batch_crash():
    """A custom Runner / wrapped SDK call handing back None or an object used
    to raise TypeError inside the scorer's regexes, outside run_probes'
    handler — every item already answered was thrown away."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        probes_file = _fixture_dir(td)
        probes = load_probes(probes_file)
        row, _ = register(probes, label="objecty",
                          runner=CallableRunner(lambda p: 42 if "France" in p else "4"),
                          out_dir=td / "regs", ledger_path=None, probes_path=probes_file)
        assert row["aggregate"]["n_errors"] == 1
        assert row["aggregate"]["n_scored"] == 1
        bad = [it for it in row["items"] if it["id"] == "a"][0]
        assert bad["score"] is None and "not str" in bad["error"]


def test_a_runner_output_with_a_lone_surrogate_still_registers_and_chains():
    """Lone surrogates are not UTF-8; register() died at write_text() after
    every runner call had been made. Now normalized to U+FFFD, the same
    treatment CmdRunner already gives undecodable bytes."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        probes_file = _fixture_dir(td)
        probes = load_probes(probes_file)
        row, path = register(probes, label="surrogate",
                             runner=CallableRunner(lambda p: "Paris\udc80" if "France" in p else "4"),
                             out_dir=td / "regs", ledger_path=td / "ledger.jsonl",
                             probes_path=probes_file)
        assert path.exists() and "_ledger_chain" in row
        on_disk = json.loads(path.read_text(encoding="utf-8"))
        assert "�" in [it for it in on_disk["items"] if it["id"] == "a"][0]["output"]
        assert row["aggregate"]["n_errors"] == 0


# ---------------------------------------------------------------------------
# AUDIT 2026-08-28. The B-1 family, one level further out.
#
# B-1 fixed "the tamper check silently did not run because the path FORM
# differed". The B-1 RESIDUAL fixed "...because the cwd differed, so no row
# matched". Both left the outermost gate untouched: `if ledger_file.exists()`.
# Delete the ledger and the whole tamper check is skipped with no trace at all,
# and the compare that skipped it then RE-CREATES the ledger on its way out, so
# the artefact left behind looks freshly chained.
# ---------------------------------------------------------------------------

def _register_then_tamper(td: Path):
    """A chained registration whose file has been edited after the fact."""
    probes_file = _fixture_dir(td)
    probes = load_probes(probes_file)
    ledger_path = td / "ledger.jsonl"
    reg, path = register(probes, label="baseline", runner=CallableRunner(lambda p: "Paris" if "France" in p else "4"),
                         out_dir=td / "regs", ledger_path=ledger_path,
                         probes_path=probes_file)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["items"][0]["score"] = 0.0          # forge the "before" value
    raw["aggregate"]["mean"] = 0.5
    path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    return probes_file, ledger_path, path


def test_a_deleted_ledger_does_not_pass_a_skipped_tamper_check_off_as_run():
    """THE HOLE: with the ledger present this exact tamper is caught
    (`registration_tampered`). Delete the ledger and compare() returns an
    ordinary clean diff reporting a fabricated +0.5 improvement, with nothing
    anywhere in the report saying the tamper check never ran. One `rm` converts
    a detection into a green."""
    runner = CallableRunner(lambda p: "Paris" if "France" in p else "4")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        probes_file, ledger_path, path = _register_then_tamper(td)

        caught, _ = compare(path, runner=runner, probes_path=probes_file,
                            out_dir=td / "c1", ledger_path=ledger_path)
        assert caught["valid"] is False
        assert caught["invalid_kind"] == "registration_tampered"

        ledger_path.unlink()                       # the whole attack
        skipped, _ = compare(path, runner=runner, probes_path=probes_file,
                             out_dir=td / "c2", ledger_path=ledger_path)

        assert "chain_check" in skipped, (
            "the report does not record WHETHER the tamper check ran — a reader "
            "cannot tell this diff from one that was actually verified")
        assert skipped["chain_check"]["ran"] is False
        assert skipped["chain_check"]["status"] == "ledger_file_absent"

        # STRENGTHENED 2026-08-28. This test previously stopped at "the report
        # discloses that the check was skipped" and asserted nothing about the
        # verdict -- so it passed while compare() returned valid=True on a
        # registration tampered to fake a +0.5 gain. Disclosure without a verdict
        # is a footnote under a green light, and the fabricated improvement still
        # reported as real.
        #
        # Note what is being asserted now vs before: this is STRICTLY MORE than
        # the old assertions, not a relaxation to fit changed code. The two
        # original lines survive above; these are added beneath them.
        assert skipped["valid"] is False, (
            "an unverifiable registration reported valid=True -- the tamper check "
            "could not run, so this diff cannot be called clean")
        assert skipped["invalid_kind"] == "chain_ledger_absent"
        # and the fabricated improvement must not be presented as a finding
        assert "delta_mean" not in skipped or skipped.get("valid") is False


def test_a_genuinely_verified_comparison_says_so_in_the_same_field():
    """The other side: a clean chained comparison must be positively
    distinguishable from one whose check was skipped, not merely both `valid`."""
    runner = CallableRunner(lambda p: "Paris" if "France" in p else "4")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        probes_file = _fixture_dir(td)
        probes = load_probes(probes_file)
        ledger_path = td / "ledger.jsonl"
        reg, path = register(probes, label="clean", runner=runner,
                             out_dir=td / "regs", ledger_path=ledger_path,
                             probes_path=probes_file)
        report, _ = compare(path, runner=runner, probes_path=probes_file,
                            out_dir=td / "c", ledger_path=ledger_path)
        assert report["valid"] is True
        assert report["chain_check"]["ran"] is True
        assert report["chain_check"]["status"] == "verified"


def test_an_unverifiable_ledger_is_not_accused_of_being_a_broken_chain():
    """`Ledger.verify()` is TRI-STATE since arcaeon-ledger 0.5.7: ok=None means
    'no fault found, but the scan did not cover everything' (an empty file, or
    unchained/declared-break rows). `if not chain_verify.ok` collapses that into
    the accusation 'broken chain'. Same verdict either way (valid: False) — but
    the reason handed to the operator is a false charge against their file."""
    runner = CallableRunner(lambda p: "Paris" if "France" in p else "4")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        probes_file, ledger_path, path = _register_then_tamper(td)
        ledger_path.write_text("", encoding="utf-8")       # empty => ok is None

        from arcaeon.record.ledger import Ledger as _L
        vr = _L(ledger_path).verify()
        assert vr.ok is None and vr.verified_scope == "empty"

        report, _ = compare(path, runner=runner, probes_path=probes_file,
                            out_dir=td / "c", ledger_path=ledger_path)
        assert report["valid"] is False                     # unchanged
        assert report["invalid_kind"] != "ledger_broken", (
            "an unverifiable scope was reported as a BROKEN chain — the ledger's "
            "tri-state collapsed into an accusation")
        assert report["invalid_kind"] == "ledger_unverifiable"
