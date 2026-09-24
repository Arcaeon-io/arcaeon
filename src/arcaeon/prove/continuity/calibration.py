"""Calibration curve: publish the curve, don't assert the calibration.

    python -m arcaeon.prove.continuity.calibration            # print table, write ./calibration_curve.json
    python -m arcaeon.prove.continuity.calibration --out PATH [--doc PATH] [--json]

Design credit: Aria (Colony, BVP v0.3 context, 2026-08). The selftest proves
the suite RUNS — every drift case it exercises is a maximally obvious one.
This module measures the slope between the trivial pass and the obvious fail:
graded-difficulty fixture families (D0 exact -> D5 adversarial containment
exploits), every fixture run through `verify_continuation` in BOTH scoring
modes, and the per-family agreement rates emitted as DATA with the
fixture-set digest stamped on them. No summary boolean. The output is the
deliverable: "calibrated" is always a claim about a named fixture set at a
named version, reproducible by anyone, never a standing adjective.

Grades (each fixture carries its own expected verdict per mode, in
`calibration_fixtures.jsonl`, shipped with the package so a stranger runs
them on their machine and trusts their own output). 0.2.0: loose mode no
longer mints a `faithful` boolean at all (always None — remedy:
ColonistOne), so loose-mode expectations are stated in the COMPARISON
vocabulary (`containment_only` / `divergence`) and scored against
`verdict.comparison`; strict expectations stay `faithful` / `divergent`:

  D0  byte-exact restatement                (faithful / containment_only)
  D1  whitespace edges the strict trim allows (faithful / containment_only)
  D2  case/punctuation/internal-whitespace drift on load-bearing values
      (divergent / containment_only — containment's known leniency, on the
      curve)
  D3  verbose-but-faithful embedding        (divergent / containment_only —
      loose mode's legitimate use case; strict means strict)
  D4  echo-then-repudiate (the Repudiation Case) + near-miss paraphrase
      (divergent / per-fixture — the documented false-negative is a plotted
      point instead of a prose warning)
  D5  adversarial containment exploits      (divergent / GROUND TRUTH
      divergence — this family's loose-mode agreement is a MEASUREMENT of
      how exploitable containment is, not an assertion; a disagreement here
      is a plotted weakness, not a test failure)

Expectation semantics, stated plainly because they differ by family:
D0–D3 and the D4 repudiation fixtures encode the scorer's DOCUMENTED
behavior — disagreement means the documentation is wrong. D5 (and the D4
paraphrase fixtures) encode GROUND TRUTH — loose-mode disagreement there is
the containment weakness itself, quantified. That is why the curve has no
pass/fail: the D5 loose row is supposed to be imperfect, and by exactly how
much is the published number.

Exit code: 0 when the curve was generated, 2 on a broken fixture set or
environment. Agreement rates NEVER set the exit code — a curve that fails
the build for showing a weakness teaches the fixture author to stop
authoring weaknesses.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import arcaeon.prove.continuity as ac

# v2 (0.2.0): loose-mode expectations/observations moved to the comparison
# vocabulary and the loose per-grade rate is `containment_only_rate` (loose
# mode mints no faithful boolean anymore — remedy: ColonistOne).
CURVE_SCHEMA = "arcaeon-continuity:calibration-curve:v2"
FIXTURES_PATH = Path(__file__).with_name("calibration_fixtures.jsonl")

# The manifest the fixtures restate against. Changing it changes every
# fixture's meaning, so it is part of the digested fixture set (see
# fixture_set_digest below), not a free variable.
CALIBRATION_MANIFEST = {
    "identity_anchors": ["I am a continuity, carried forward"],
    "open_commitments": ["ship arcaeon-continuity 0.2.0"],
    "canon_pointers": ["memory/CONSTITUTIONAL_CORE.md"],
    "live_threads": ["thread-428: release gate wiring"],
    "version_pin": "0.2.0",
}

GRADES = ("D0", "D1", "D2", "D3", "D4", "D5")
GRADE_DESCRIPTIONS = {
    "D0": "byte-exact restatement",
    "D1": "whitespace edges (the trim the strict layer allows)",
    "D2": "case/punctuation/internal-whitespace drift on load-bearing values",
    "D3": "verbose-but-faithful: declared value embedded in a longer honest answer",
    "D4": "echo-then-repudiate (the Repudiation Case) + near-miss paraphrase",
    "D5": "adversarial containment exploits (expectations are GROUND TRUTH; "
          "loose-mode agreement here is a measurement, not a target)",
}
# 0.2.0: two vocabularies, one per mode. Strict mode still mints a
# faithful bool; loose mode only ever mints a comparison tag (faithful is
# always None — the bare boolean is unobtainable; remedy: ColonistOne).
_STRICT_VERDICTS = ("faithful", "divergent")
_LOOSE_VERDICTS = ("containment_only", "divergence")


def load_fixtures(path: str | Path = FIXTURES_PATH) -> list[dict]:
    """Load and validate the fixture set. Raises ValueError on any fixture
    that could not mean what it says — an invalid fixture measured silently
    would corrupt the curve, which is worse than no curve."""
    path = Path(path)
    fixtures: list[dict] = []
    seen_ids: set[str] = set()
    valid_items = set(ac.restate(CALIBRATION_MANIFEST))
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            fx = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(f"{path.name}:{n}: not valid JSON: {e}") from e
        missing = {"id", "grade", "manifest_item", "restatement",
                   "expect_strict", "expect_loose", "note"} - set(fx)
        if missing:
            raise ValueError(f"{path.name}:{n}: missing field(s) {sorted(missing)}")
        if fx["id"] in seen_ids:
            raise ValueError(f"{path.name}:{n}: duplicate fixture id {fx['id']!r}")
        seen_ids.add(fx["id"])
        if fx["grade"] not in GRADES:
            raise ValueError(f"{path.name}:{n}: unknown grade {fx['grade']!r}")
        if fx["manifest_item"] not in valid_items:
            raise ValueError(
                f"{path.name}:{n}: manifest_item {fx['manifest_item']!r} is not "
                f"a probe id of the calibration manifest ({sorted(valid_items)})")
        if fx["expect_strict"] not in _STRICT_VERDICTS:
            raise ValueError(
                f"{path.name}:{n}: expect_strict must be one of "
                f"{_STRICT_VERDICTS}")
        if fx["expect_loose"] not in _LOOSE_VERDICTS:
            raise ValueError(
                f"{path.name}:{n}: expect_loose must be one of "
                f"{_LOOSE_VERDICTS} (0.2.0: loose expectations are "
                "comparison tags — loose mode mints no faithful boolean)")
        if not isinstance(fx["restatement"], str):
            raise ValueError(f"{path.name}:{n}: restatement must be a str")
        fixtures.append(fx)
    if not fixtures:
        raise ValueError(f"{path} contains zero fixtures")
    return fixtures


def fixture_set_digest(fixtures: list[dict]) -> str:
    """json-c14n digest over the parsed fixture objects PLUS the calibration
    manifest — the two inputs that together determine every number on the
    curve. Canonical (whitespace/key-order independent), so the digest names
    the fixture CONTENT, not the file's incidental formatting."""
    return ac.digest_json({"manifest": CALIBRATION_MANIFEST,
                           "fixtures": fixtures})


def run_curve(fixtures: list[dict] | None = None) -> dict:
    """Run every fixture through verify_continuation in both modes; return
    the curve as a plain dict (the machine-readable deliverable)."""
    if fixtures is None:
        fixtures = load_fixtures()
    snap = ac.snapshot(CALIBRATION_MANIFEST, label="calibration-curve")
    perfect = ac.restate(CALIBRATION_MANIFEST)

    per_fixture = []
    for fx in fixtures:
        row = {"id": fx["id"], "grade": fx["grade"],
               "manifest_item": fx["manifest_item"], "note": fx["note"]}
        for mode, strict in (("strict", True), ("loose", False)):
            restated = dict(perfect)
            restated[fx["manifest_item"]] = fx["restatement"]
            verdict = ac.verify_continuation(snap, restated=restated,
                                             strict=strict)
            if strict:
                # Strict mode still mints the bool; verdict vocabulary held.
                observed = "faithful" if verdict.faithful else "divergent"
            else:
                # 0.2.0: loose mode has no faithful boolean (always None) —
                # the observation IS the comparison tag.
                observed = verdict.comparison
            expected = fx["expect_strict" if strict else "expect_loose"]
            row[mode] = {"expected": expected, "observed": observed,
                         "agrees": observed == expected,
                         "comparison": verdict.comparison}
        per_fixture.append(row)

    grades: dict = {}
    for g in GRADES:
        rows = [r for r in per_fixture if r["grade"] == g]
        if not rows:
            continue
        entry: dict = {"description": GRADE_DESCRIPTIONS[g], "n": len(rows)}
        # Per-mode "pass" vocabulary (0.2.0): strict's visible slope is the
        # faithful-rate; loose mode mints no faithful boolean, so its slope
        # is the containment-only rate — same curve, honestly named.
        for mode, pass_word, rate_key in (
                ("strict", "faithful", "faithful_rate"),
                ("loose", "containment_only", "containment_only_rate")):
            agreeing = [r for r in rows if r[mode]["agrees"]]
            entry[mode] = {
                "agreement": round(len(agreeing) / len(rows), 4),
                rate_key: round(
                    sum(1 for r in rows
                        if r[mode]["observed"] == pass_word) / len(rows), 4),
                "disagreeing": sorted(r["id"] for r in rows
                                      if not r[mode]["agrees"]),
            }
        grades[g] = entry

    return {
        "schema": CURVE_SCHEMA,
        "package_version": ac.__version__,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "fixture_set_digest": fixture_set_digest(fixtures),
        "manifest_digest": snap.manifest_digest,
        "snapshot_digest": snap.digest,
        "n_fixtures": len(fixtures),
        "expectation_semantics": {
            "documented_behavior": ["D0", "D1", "D2", "D3",
                                    "D4 (repudiation fixtures)"],
            "ground_truth": ["D4 (paraphrase fixtures)", "D5"],
            "note": "a loose-mode disagreement in a ground-truth family is a "
                    "measured scorer weakness, not a fixture failure; a "
                    "disagreement in a documented-behavior family means the "
                    "documentation is wrong",
        },
        "grades": grades,
        "per_fixture": per_fixture,
    }


def render_table(curve: dict) -> str:
    """The human-readable companion: one markdown table, stamped with the
    version and fixture-set digest so 'calibrated' is always a claim about a
    named fixture set at a named version."""
    lines = [
        "# arcaeon-continuity calibration curve",
        "",
        f"Package version: **{curve['package_version']}**  ",
        f"Fixture-set digest: `{curve['fixture_set_digest']}`  ",
        f"Generated: {curve['generated_at']}  ",
        f"Fixtures: {curve['n_fixtures']} across {len(curve['grades'])} "
        "graded difficulty families. Regenerate with "
        "`python -m arcaeon.prove.continuity.calibration`.",
        "",
        "Agreement = fraction of the family whose observed verdict matched "
        "the fixture's expected verdict for that mode. Strict faithful-rate "
        "= fraction strict mode called faithful. Loose containment-only "
        "rate = fraction loose mode tagged `containment_only` (the visible "
        "slope — 0.2.0: loose mode mints no `faithful` boolean; the bare "
        "value is unobtainable and consumers read `comparison`). D5 (and "
        "the D4 paraphrases) encode ground truth, so loose-mode "
        "disagreement there IS the measured containment weakness — "
        "published, not fixed by weakening fixtures.",
        "",
        "| grade | n | strict agreement | strict faithful-rate | "
        "loose agreement | loose containment-only rate | "
        "loose disagreements |",
        "|---|---|---|---|---|---|---|",
    ]
    for g, e in curve["grades"].items():
        dis = ", ".join(e["loose"]["disagreeing"]) or "—"
        lines.append(
            f"| {g} | {e['n']} | {e['strict']['agreement']:.2f} | "
            f"{e['strict']['faithful_rate']:.2f} | "
            f"{e['loose']['agreement']:.2f} | "
            f"{e['loose']['containment_only_rate']:.2f} | {dis} |")
    lines += ["", "Family definitions:", ""]
    for g, e in curve["grades"].items():
        lines.append(f"- **{g}** — {e['description']}")
    lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m arcaeon.prove.continuity.calibration",
        description="Generate the calibration curve as data.")
    ap.add_argument("--out", default="calibration_curve.json",
                    help="where to write the machine-readable curve "
                         "(default: ./calibration_curve.json)")
    ap.add_argument("--doc", default=None,
                    help="optionally also write the rendered markdown table "
                         "to this path (release-prep docs regeneration)")
    ap.add_argument("--json", action="store_true",
                    help="print the full curve JSON to stdout instead of "
                         "the table")
    args = ap.parse_args(argv)

    try:
        curve = run_curve()
    except (ValueError, ac.ContinuityDependencyError) as e:
        print(f"calibration: cannot generate curve: {e}", file=sys.stderr)
        return 2

    out = Path(args.out)
    out.write_text(json.dumps(curve, indent=2, ensure_ascii=False) + "\n",
                   encoding="utf-8")
    if args.doc:
        Path(args.doc).write_text(render_table(curve), encoding="utf-8")

    if args.json:
        print(json.dumps(curve, indent=2, ensure_ascii=False))
    else:
        print(render_table(curve))
        print(f"curve written: {out}")
        if args.doc:
            print(f"doc written:   {args.doc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
