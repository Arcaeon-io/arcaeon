"""CLI argument-parsing tests — exercises arcaeon_baseline.cli.main() through
argparse directly (not just the library functions it calls), because a
dest-name collision between the subcommand and a subcommand's own flag can
silently misroute dispatch without either library-level tests or --help
catching it. (That collision happened here once: the top-level subparsers
used dest="cmd", and register/compare each define their own --cmd for the
runner's shell command — argparse writes both into args.cmd, so the second
write silently clobbered the subcommand name and every branch fell through
to the "unreached" return 2. Fixed by renaming the subparsers dest to
"subcommand"; this test pins it so it can't quietly come back.)
Run: python test_cli.py (or pytest)."""
import json
import sys
import tempfile
from pathlib import Path

from arcaeon.prove.baseline.cli import main

FIXTURE = [
    {"id": "a", "prompt": "Paris", "scoring": {"type": "exact_match", "answer": "Paris"}},
    {"id": "b", "prompt": "4", "scoring": {"type": "numeric_tolerance", "answer": 4, "tolerance": 0}},
]
ECHO_CMD = f'{json.dumps(sys.executable)} -c "import sys; sys.stdout.write(sys.stdin.read())"'


def test_selftest_subcommand_dispatches_and_returns_zero():
    assert main(["selftest"]) == 0


def test_register_subcommand_reaches_the_register_branch_not_the_fallback():
    """Regression pin for the --cmd/dest="cmd" collision: if dispatch is
    broken, this returns 2 (the unreached fallback) instead of running."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        probes_file = td / "probes.jsonl"
        probes_file.write_text("\n".join(json.dumps(x) for x in FIXTURE) + "\n",
                               encoding="utf-8")
        rc = main(["register", "--probes", str(probes_file), "--label", "cli-test",
                  "--cmd", ECHO_CMD, "--out", str(td / "regs"),
                  "--ledger", str(td / "ledger.jsonl")])
        assert rc == 0
        files = list((td / "regs").glob("*.json"))
        assert len(files) == 1
        reg = json.loads(files[0].read_text(encoding="utf-8"))
        assert reg["aggregate"]["mean"] == 1.0
        # the runner's shell command must have reached CmdRunner intact —
        # if args.cmd got clobbered by the subcommand string "register"
        # instead, the runner command would be "register", not ECHO_CMD.
        assert reg["runner"]["cmd"] == ECHO_CMD


def test_register_then_compare_subcommand_round_trip_via_cli():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        probes_file = td / "probes.jsonl"
        probes_file.write_text("\n".join(json.dumps(x) for x in FIXTURE) + "\n",
                               encoding="utf-8")
        rc = main(["register", "--probes", str(probes_file), "--label", "rt",
                  "--cmd", ECHO_CMD, "--out", str(td / "regs"),
                  "--ledger", str(td / "ledger.jsonl")])
        assert rc == 0
        (reg_file,) = (td / "regs").glob("*.json")

        rc = main(["compare", "--against", str(reg_file), "--probes", str(probes_file),
                  "--cmd", ECHO_CMD, "--out", str(td / "cmp"),
                  "--ledger", str(td / "ledger.jsonl")])
        assert rc == 0
        (cmp_file,) = (td / "cmp").glob("*.json")
        report = json.loads(cmp_file.read_text(encoding="utf-8"))
        assert report["valid"] is True
        assert report["n_flips"] == 0


def test_compare_invalid_digest_returns_nonzero_exit():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        probes_file = td / "probes.jsonl"
        probes_file.write_text("\n".join(json.dumps(x) for x in FIXTURE) + "\n",
                               encoding="utf-8")
        rc = main(["register", "--probes", str(probes_file), "--label", "inv",
                  "--cmd", ECHO_CMD, "--out", str(td / "regs"),
                  "--ledger", str(td / "ledger.jsonl")])
        assert rc == 0
        (reg_file,) = (td / "regs").glob("*.json")

        edited = FIXTURE[:1] + [{"id": "b", "prompt": "5",
                                 "scoring": {"type": "numeric_tolerance",
                                            "answer": 5, "tolerance": 0}}]
        probes_file.write_text("\n".join(json.dumps(x) for x in edited) + "\n",
                               encoding="utf-8")

        rc = main(["compare", "--against", str(reg_file), "--probes", str(probes_file),
                  "--cmd", ECHO_CMD, "--out", str(td / "cmp"),
                  "--ledger", str(td / "ledger.jsonl")])
        assert rc == 1


def test_compare_cli_prints_chain_check_status_and_coverage(capsys):
    """AUDIT 2026-09-01: the report carried chain_check (0.1.6) and
    coverage_note/verified_scope (0.1.5) but the CLI printed neither, so a
    diff whose tamper check was skipped printed the same lines as a verified
    one. A half-refusing runner (`--cmd` exits nonzero on one probe) must show
    up on the terminal, not only in the JSON."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        probes_file = td / "probes.jsonl"
        probes_file.write_text("\n".join(json.dumps(x) for x in FIXTURE) + "\n",
                               encoding="utf-8")
        rc = main(["register", "--probes", str(probes_file), "--label", "cov",
                  "--cmd", ECHO_CMD, "--out", str(td / "regs"), "--ledger", ""])
        assert rc == 0
        (reg_file,) = (td / "regs").glob("*.json")
        half_cmd = (f'{json.dumps(sys.executable)} -c "import sys; s=sys.stdin.read(); '
                    f'sys.exit(1) if s.strip()==\'4\' else sys.stdout.write(s)"')
        capsys.readouterr()
        rc = main(["compare", "--against", str(reg_file), "--probes", str(probes_file),
                  "--cmd", half_cmd, "--out", str(td / "cmp"), "--ledger", ""])
        assert rc == 0
        out = capsys.readouterr().out
        assert "chain_check: skipped_no_ledger_path" in out
        assert "verified_scope=bounded_after_unscored" in out
        assert "1 of 2 probe(s) could not be scored in this run" in out


def test_unknown_subcommand_rejected_by_argparse():
    try:
        main(["frobnicate"])
        assert False, "argparse should have rejected an unknown subcommand"
    except SystemExit as e:
        assert e.code == 2


def test_dunder_version_matches_pyproject():
    """Caught release-checking arcaeon-audit 0.1.5 the same night: a version
    bump that only touches pyproject.toml leaves __version__ claiming the
    OLD release inside a wheel whose own METADATA says otherwise. Pin them
    together here too."""
    import tomllib
    import arcaeon.prove.baseline
    declared = tomllib.loads(
        (Path(__file__).parent / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]["version"]
    assert arcaeon.prove.baseline.__version__ == declared, (
        f"arcaeon_baseline.__version__={arcaeon.prove.baseline.__version__!r} but "
        f"pyproject.toml declares {declared!r} -- a release bumped one "
        "and not the other")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\nALL {len(fns)} TESTS PASSED")
