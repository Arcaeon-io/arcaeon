"""The CLI's exit contract — previously untested in its entirety.

Found 2026-08-23 by the pre-invite adversarial audit: replacing `main()` with
`return 0` left the whole suite green. The 0/1/2 exit codes are what a
customer's CI branches on, and nothing had ever executed them. The same audit
noted that the `cli.py` tri-state fix shipped the same night went in WITHOUT a
test on the CLI path (the planted reds covered `export_bundle`). This file
closes that.

Contract, identical for `verify` and `export`:
    0 = nothing wrong found
    1 = an accusation (the log is bad)
    2 = the check could not complete (the question is unanswered)

The class this guards: "could not check" must never render as "checked, fine",
and an empty or unverifiable log must never be called tampering.
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from arcaeon.record.ledger import Ledger
from arcaeon.record.ledger.witness import WitnessStore, publish_head


def _run(*args):
    """Invoke the real CLI the way a customer's CI does."""
    p = subprocess.run([sys.executable, "-m", "arcaeon.prove.audit.cli", *args],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def _chained(d, n=6):
    p = Path(d) / "audit.jsonl"
    log = Ledger(p)
    for i in range(n):
        log.append({"actor": "agent", "decision": f"d{i}"})
    return p


def _unchain(p: Path):
    rows = p.read_text(encoding="utf-8").strip().split("\n")
    rows = [re.sub(r',\s*"chain":\s*"[0-9a-f]+"\s*\}$', "}", r) for r in rows]
    p.write_text("\n".join(rows) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------
# verify
# --------------------------------------------------------------------------

def test_verify_clean_log_exits_0():
    with tempfile.TemporaryDirectory() as d:
        code, out = _run("verify", str(_chained(d)))
        assert code == 0, out
        assert out.startswith("VERIFIED"), out     # the one word, not PASS


def test_verify_tampered_log_exits_1():
    with tempfile.TemporaryDirectory() as d:
        p = _chained(d)
        rows = p.read_text(encoding="utf-8").split("\n")
        rows[2] = rows[2].replace('"d2"', '"TAMPERED"')
        p.write_text("\n".join(rows), encoding="utf-8")
        code, out = _run("verify", str(p))
        assert code == 1, out
        assert "FAIL" in out


def test_verify_empty_log_is_not_an_accusation():
    """A day-one customer's first command must not accuse them of tampering.

    Before the fix this printed 'integrity broken at None — altered, truncated,
    or reordered' and exited 1, while `export` on the same file exited 0.
    """
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "empty.jsonl"
        p.write_text("", encoding="utf-8")
        code, out = _run("verify", str(p))
        # COULD NOT LOOK (legacy code 2; `arcaeon audit verify` exits 3), never
        # an accusation and never a green (qa-fixes 2026-09-24).
        assert code == 2, out
        assert "COULD NOT LOOK" in out and "EMPTY" in out
        assert "altered" not in out.lower()
        assert "None" not in out


def test_verify_unchained_log_is_unanswered_not_pass_and_not_fail():
    """Rows exist that the chain cannot speak for: exit 2, never 0, never 1."""
    with tempfile.TemporaryDirectory() as d:
        p = _chained(d, n=4)
        _unchain(p)
        code, out = _run("verify", str(p))
        assert code == 2, out
        assert "UNVERIFIED" in out
        assert "altered" not in out.lower()


# --------------------------------------------------------------------------
# export — the same contract, so the two subcommands cannot contradict
# --------------------------------------------------------------------------

def test_export_and_verify_never_disagree_on_the_same_file():
    """The bug that motivated the contract: two subcommands, one file, two
    opposite verdicts. Pin agreement across every state we can construct."""
    with tempfile.TemporaryDirectory() as d:
        cases = {}

        clean = _chained(d, n=5)
        cases["clean"] = clean

        empty = Path(d) / "empty.jsonl"
        empty.write_text("", encoding="utf-8")
        cases["empty"] = empty

        unchained = Path(d) / "adopted.jsonl"
        L = Ledger(unchained)
        for i in range(3):
            L.append({"e": i})
        _unchain(unchained)
        cases["unchained"] = unchained

        for name, path in cases.items():
            v_code, _ = _run("verify", str(path))
            e_code, _ = _run("export", str(path), str(Path(d) / f"out_{name}"))
            assert v_code == e_code, (
                f"{name}: verify exited {v_code} but export exited {e_code} "
                "on the same file"
            )


def test_export_exits_1_when_the_witness_catches_truncation():
    """A positive external detection must reach the exit code, not just prose."""
    with tempfile.TemporaryDirectory() as d:
        p = _chained(d, n=10)
        store = WitnessStore(Path(d) / "w.jsonl")
        publish_head(store, "acme-prod", Ledger(p))
        rows = p.read_text(encoding="utf-8").strip().split("\n")
        p.write_text("\n".join(rows[:6]) + "\n", encoding="utf-8")

        code, out = _run("export", str(p), str(Path(d) / "out"),
                         "--witness", str(store.path), "--namespace", "acme-prod")
        assert code == 1, out
        assert "TRUNCATION_DETECTED" in out


def test_export_of_unchained_tampered_log_does_not_exit_0():
    """The night's critical bug, pinned at the exit-code layer: the export that
    said 'no records have been written yet' also exited 0, so CI went green
    over a log with witnessed records deleted."""
    with tempfile.TemporaryDirectory() as d:
        p = _chained(d, n=10)
        store = WitnessStore(Path(d) / "w.jsonl")
        publish_head(store, "acme-prod", Ledger(p))
        _unchain(p)
        rows = p.read_text(encoding="utf-8").strip().split("\n")
        p.write_text("\n".join(rows[:7]) + "\n", encoding="utf-8")

        code, out = _run("export", str(p), str(Path(d) / "out"),
                         "--witness", str(store.path), "--namespace", "acme-prod")
        assert code != 0, out
        assert "no records have been written yet" not in out


def test_dunder_version_matches_pyproject():
    """Caught while release-checking 0.1.5: pyproject.toml's version and
    arcaeon_audit.__version__ are two independent strings, and only the
    former got bumped for a release once (`--version` / `arcaeon_audit.
    __version__` still claimed the OLD release inside a wheel whose own
    METADATA said otherwise). Pin them together so a version bump that
    misses one place fails here instead of shipping."""
    import tomllib
    import arcaeon.prove.audit
    pyproject = Path(__file__).parent / "pyproject.toml"
    declared = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
    assert arcaeon.prove.audit.__version__ == declared, (
        f"arcaeon_audit.__version__={arcaeon.prove.audit.__version__!r} but "
        f"pyproject.toml declares {declared!r} -- a release bumped one "
        "and not the other")


def test_verify_declared_break_does_not_report_zero_unchained_rows():
    """AUDIT 2026-08-28, the CLI half of the same defect. `bounded_declared_break`
    (ledger 0.6.0) has prechain == 0, so `verify` printed '(0 carry no chain
    links)' while exiting 2 for an unverified scope — the count contradicts the
    verdict and names a cause the reader does not have. Exit code is correct and
    stays correct; the sentence must stop being false."""
    import json as _json
    from arcaeon.record.ledger import declare_break, verify_file

    with tempfile.TemporaryDirectory() as d:
        p = _chained(d, n=5)
        lines = p.read_text(encoding="utf-8").splitlines()
        row = _json.loads(lines[2])
        row["decision"] = "OUT_OF_BAND"
        lines[2] = _json.dumps(row)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        declare_break(p, 3, "rewritten out of band by a legacy tool")

        assert verify_file(p).verified_scope == "bounded_declared_break"

        code, out = _run("verify", str(p))
        assert code == 2, out                      # unchanged contract
        assert "0 carry no chain links" not in out, out
        assert "declared" in out.lower(), out
