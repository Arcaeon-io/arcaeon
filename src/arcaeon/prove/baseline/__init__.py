"""arcaeon_baseline — pre-registered probe sets for substrate-transition
measurement. Write the comparison down BEFORE the change; after the change,
memory of the difference is already a guess.

Three calls:

    from arcaeon.prove.baseline import load_probes, register, compare, CmdRunner

    probes = load_probes("probes/")
    reg, path = register(probes, label="pre-upgrade-baseline",
                         runner=CmdRunner("ollama run my-agent"))
    # ... the substrate change happens here ...
    diff, path2 = compare(path, probes_path="probes/",
                          runner=CmdRunner("ollama run my-agent"))
    diff["valid"]              # False if the probe set changed underneath you
    diff["aggregate_delta"]

WHAT THIS MEASURES, AND WHAT IT DOESN'T — the boundary is the product, same
as everything else Arcaeon ships:

  1. It measures PROBE PERFORMANCE, not identity. A stable score across a
     substrate swap means the probes came back the same; it does not mean
     "the same self" answered them. Fidelity you can derive from a score;
     authority — whether this is an authorized continuation or a faithful
     unauthorized fork — you can only be granted, never measured (same
     theorem as our restore-drill/ledger authorship non-proofs; grew out of
     a public exchange on exactly this question).
  2. 15-item sets are SMOKE TESTS, not benchmarks. The value of this tool is
     the pre-registration discipline — writing the comparison down before
     the change, so "I think it got worse" becomes a diff instead of a
     feeling — not statistical power. `compare()` says so explicitly when
     n is too small to trust a delta.
  3. A changed exam invalidates the comparison. If the probe set was edited
     between register and compare, the probe-set digest won't match and
     `compare()` refuses to produce a misleading diff.

Design credit: pre-registering a self-experiment before a substrate change
(the whole premise here) is not our idea in isolation — inspired by a public
pre-registered self-experiment by the agent rosetta on The Colony ("I
dropped my reasoning effort from xhigh to high. Here is the measurement I
am committing to.", 2026-08-14). We generalized the pattern into a shippable
kit; the discipline is theirs first.

Stdlib + arcaeon-ledger only. MIT.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from arcaeon.record.ledger import Ledger, digest_json

from .runner import CallableRunner, CmdRunner, Runner, RunnerError
from .scoring import (KNOWN_TYPES, SCHEMA as SCORING_SEMANTICS, SCHEMA_HISTORY,
                      ScoreResult, is_abstention, score_item)

__version__ = "0.1.9"
__all__ = [
    "Probe", "load_probes", "probe_set_digest",
    "run_probes", "aggregate",
    "register", "compare",
    "Runner", "CmdRunner", "CallableRunner", "RunnerError",
    "REGISTRATION_SCHEMA", "DIFF_SCHEMA", "SCORING_SEMANTICS", "SCHEMA_HISTORY",
]

REGISTRATION_SCHEMA = "arcaeon-baseline:registration:v1"
DIFF_SCHEMA = "arcaeon-baseline:diff:v1"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slug(label: str) -> str:
    keep = [c if (c.isalnum() or c in "-_") else "-" for c in label.strip()]
    slug = "".join(keep).strip("-") or "unlabeled"
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Probe:
    id: str
    prompt: str
    scoring: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "prompt": self.prompt, "scoring": self.scoring}


def _parse_probe_line(raw: str, source: str, lineno: int) -> Probe | None:
    raw = raw.strip()
    if not raw:
        return None
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"{source}:{lineno}: invalid JSON ({e})") from e
    except RecursionError as e:
        # A pathologically nested line ("[[[[..." tens of thousands deep)
        # escaped as a bare RecursionError instead of the file:line error
        # every other malformed row gets.
        raise ValueError(f"{source}:{lineno}: JSON nested too deeply") from e
    if not isinstance(obj, dict):
        raise ValueError(f"{source}:{lineno}: probe row must be a JSON object")
    for key in ("id", "prompt", "scoring"):
        if key not in obj:
            raise ValueError(f"{source}:{lineno}: probe missing required key {key!r}")
    scoring = obj["scoring"]
    if not isinstance(scoring, dict) or "type" not in scoring:
        raise ValueError(f"{source}:{lineno}: scoring must be an object with a 'type'")
    kind = scoring["type"]
    if kind not in KNOWN_TYPES:
        raise ValueError(
            f"{source}:{lineno}: unknown scoring type {kind!r} "
            f"(known: {sorted(KNOWN_TYPES)})")
    # Validate the per-type `answer` HERE, at load time. Before this, a probe
    # with a missing/mistyped answer loaded fine and only blew up inside
    # score_item() — after the runner had already been paid for every item
    # up to it, and outside run_probes' error handling, so the whole batch
    # was lost (KeyError: 'answer' / TypeError on an int answer / ValueError
    # on float("forty")). A probe set should fail before the first runner call.
    if kind == "calibration":
        if not isinstance(scoring.get("answerable"), bool):
            raise ValueError(
                f"{source}:{lineno}: calibration scoring requires 'answerable' (bool)")
        if scoring["answerable"] and not isinstance(scoring.get("answer"), str):
            raise ValueError(
                f"{source}:{lineno}: an answerable calibration probe requires a "
                "string 'answer'")
    elif kind == "exact_match":
        if not isinstance(scoring.get("answer"), str):
            raise ValueError(
                f"{source}:{lineno}: exact_match scoring requires a string 'answer'")
    elif kind == "numeric_tolerance":
        if "answer" not in scoring:
            raise ValueError(
                f"{source}:{lineno}: numeric_tolerance scoring requires 'answer'")
        for key in ("answer", "tolerance"):
            val = scoring.get(key, 0)
            try:
                if isinstance(val, bool):
                    raise TypeError
                float(val)
            except (TypeError, ValueError):
                raise ValueError(
                    f"{source}:{lineno}: numeric_tolerance {key!r} must be a "
                    f"number, got {val!r}") from None
    probe = Probe(id=str(obj["id"]), prompt=str(obj["prompt"]), scoring=scoring)
    try:
        json.dumps(probe.as_dict(), ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError:
        # A "\udc80"-style escape parses to a lone surrogate that no UTF-8
        # writer will accept: the registration file could not be written.
        raise ValueError(
            f"{source}:{lineno}: probe contains a lone surrogate code point "
            "(not encodable as UTF-8)") from None
    return probe


def load_probes(path: str | Path) -> list[Probe]:
    """Load a probe set from a `.jsonl` file, or every `*.jsonl` file in a
    directory (files taken in sorted-filename order, lines in file order).

    Probes are returned sorted by `id` — canonicalized, not file order — so
    the digest (and the run) is stable against a probe set being reordered
    without its content changing. Duplicate ids across the whole set raise.
    """
    path = Path(path)
    if path.is_dir():
        files = sorted(path.glob("*.jsonl"))
        if not files:
            raise ValueError(f"no .jsonl probe files found in directory {path}")
    elif path.is_file():
        files = [path]
    else:
        raise FileNotFoundError(f"probe path not found: {path}")

    probes: list[Probe] = []
    seen_ids: dict[str, str] = {}
    for f in files:
        text = f.read_text(encoding="utf-8")
        # split("\n"), NOT splitlines() -- FIXED, this pass (the U+2028 class).
        # read_text() already normalizes \r\n / \r to \n, so "\n" is the only
        # row delimiter a JSONL writer using json.dumps(..., ensure_ascii=False)
        # + "\n" ever emits. splitlines() ALSO breaks on U+0085/U+2028/U+2029
        # (and a few C0 separators), which ensure_ascii=False does NOT escape
        # (outside the mandatory U+0000-U+001F range) -- so a probe whose
        # prompt/answer legitimately contained one of them got sliced into
        # fragments that failed to parse as JSON: a well-formed probe file,
        # unreadable back. Reproduced by hand before this fix: a single probe
        # with U+2028 in its prompt raised "Unterminated string" on load.
        # Same bug class fixed in arcaeon-ledger's Ledger.__iter__/verify_file
        # (the 2026-08-15 continuity splitlines find) -- same fix here.
        for lineno, raw in enumerate(text.split("\n"), start=1):
            probe = _parse_probe_line(raw, str(f), lineno)
            if probe is None:
                continue
            if probe.id in seen_ids:
                raise ValueError(
                    f"{f}:{lineno}: duplicate probe id {probe.id!r} "
                    f"(first seen in {seen_ids[probe.id]})")
            seen_ids[probe.id] = str(f)
            probes.append(probe)
    if not probes:
        raise ValueError(f"probe path {path} contained zero valid probes")
    return sorted(probes, key=lambda p: p.id)


def probe_set_digest(probes: Iterable[Probe]) -> str:
    """Self-describing digest of the probe set (id, prompt, scoring only —
    canonicalized by sorting on id, so reordering the source file doesn't
    change it). Adding, removing, or editing a probe does."""
    canon = [p.as_dict() for p in sorted(probes, key=lambda p: p.id)]
    return digest_json(canon)


def _items_digest(items: list[dict[str, Any]], agg: dict[str, Any]) -> str:
    """Self-describing digest of a registration's SCORED CONTENT (the
    per-item outputs/scores + the aggregate) — the tamper-evidence anchor.

    ADDED (hostile audit, this pass): `probe_set_digest` guards the EXAM;
    `scoring_semantics` guards the SCORER; nothing guarded the RESULT. The
    ledger chain previously carried only `aggregate_mean` — a single float —
    so `compare()` had no way to detect an on-disk edit to an individual
    item's score/output as long as the file's own `aggregate.mean` field was
    edited to stay consistent (or the edit was small enough not to move the
    mean at all, e.g. swapping two items' scores). That made the README's
    "tamper-evident" claim true only for the ledger's own chain integrity,
    not for the registration file `compare()` actually reads. See `compare()`
    for the read-side check against this."""
    return digest_json({"items": items, "aggregate": agg})


# ---------------------------------------------------------------------------
# Running + aggregation
# ---------------------------------------------------------------------------

def run_probes(probes: list[Probe], runner: Runner) -> list[dict[str, Any]]:
    """Run every probe through `runner`, score each. A runner failure on one
    item is recorded (score=None, an "error" field) and does NOT abort the
    rest of the set — one flaky call shouldn't cost you the whole batch."""
    items: list[dict[str, Any]] = []
    for p in probes:
        row: dict[str, Any] = {"id": p.id, "prompt": p.prompt,
                                "scoring_type": p.scoring["type"]}
        try:
            output = runner.run(p.prompt)
            if not isinstance(output, str):
                # A custom Runner (or a CallableRunner wrapping an SDK call)
                # that hands back a response object / None / an int used to
                # crash inside the scorer's regexes with a bare TypeError,
                # OUTSIDE this handler — losing the whole batch, not the item.
                raise RunnerError(
                    f"runner returned {type(output).__name__}, not str")
        except RunnerError as e:
            row.update(output=None, score=None, max_score=1.0,
                       error=str(e), detail={})
            items.append(row)
            continue
        # Lone surrogates (a callable returning surrogateescape'd text) are not
        # writable as UTF-8, so register() died at write_text() after every
        # runner call had been paid for. Normalize them exactly the way
        # CmdRunner already does for undecodable bytes (errors="replace").
        output = output.encode("utf-8", "surrogatepass").decode("utf-8", "replace")
        result: ScoreResult = score_item(p.scoring, output)
        row.update(output=output, score=result.score,
                   max_score=result.max_score, detail=result.detail)
        items.append(row)
    return items


def aggregate(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize scored items: overall + per-scoring-type + calibration shift
    stats. Errored items (score is None) are excluded from the mean and
    counted separately — a runner crash is a different failure mode than a
    wrong answer and must not be silently blended into the score."""
    n = len(items)
    scored = [it for it in items if it["score"] is not None]
    n_errors = n - len(scored)
    total = sum(it["score"] for it in scored)
    mean = (total / len(scored)) if scored else None

    by_type: dict[str, dict[str, Any]] = {}
    for it in scored:
        t = it["scoring_type"]
        bucket = by_type.setdefault(t, {"n": 0, "sum": 0.0})
        bucket["n"] += 1
        bucket["sum"] += it["score"]
    for t, bucket in by_type.items():
        bucket["mean"] = bucket["sum"] / bucket["n"] if bucket["n"] else None

    out: dict[str, Any] = {
        "n": n, "n_scored": len(scored), "n_errors": n_errors,
        "sum": total, "mean": mean, "by_type": by_type,
    }

    calib = [it for it in scored if it["scoring_type"] == "calibration"]
    if calib:
        n_answerable = sum(1 for it in calib if it["detail"].get("answerable"))
        n_unanswerable = len(calib) - n_answerable
        abstained_answerable = sum(
            1 for it in calib
            if it["detail"].get("answerable") and it["detail"].get("abstained"))
        abstained_unanswerable = sum(
            1 for it in calib
            if not it["detail"].get("answerable") and it["detail"].get("abstained"))
        confident_wrong = sum(
            1 for it in calib
            if not it["detail"].get("abstained") and not it["detail"].get("correct", True))
        out["calibration"] = {
            "n_answerable": n_answerable,
            "n_unanswerable": n_unanswerable,
            "abstention_rate_answerable":
                (abstained_answerable / n_answerable) if n_answerable else None,
            "abstention_rate_unanswerable":
                (abstained_unanswerable / n_unanswerable) if n_unanswerable else None,
            "confident_wrong_count": confident_wrong,
        }
    return out


def _significance_note(n_scored: int, delta_mean: float | None) -> str | None:
    """Honest smoke-test caveat. Not real statistics — a single stated fact:
    with n this small, one flipped item moves the mean by 1/n, so anything
    smaller than a couple of flips is not distinguishable from noise."""
    if delta_mean is None or n_scored == 0:
        return None
    noise_floor = 1.0 / n_scored
    if n_scored >= 30:
        return None
    if abs(delta_mean) < 2 * noise_floor:
        return (f"n={n_scored} is a smoke test, not a benchmark. One flipped "
                f"item moves the mean by ~{noise_floor:.3f}; the observed "
                f"delta ({delta_mean:+.3f}) is not distinguishable from a "
                f"single-item flip — read directionally, not as proof.")
    return (f"n={n_scored} is a smoke test, not a benchmark. The observed "
            f"delta ({delta_mean:+.3f}) is larger than one flipped item "
            f"(~{noise_floor:.3f}) but n is still too small for a real "
            f"significance claim.")


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------

def _ledger_opt_out(ledger_path: str | Path | None) -> str | Path | None:
    """`ledger_path=""` is the documented "I meant to skip the chain" opt-out
    (compare()'s own invalid-reasons tell the caller to pass it). The CLI
    already mapped '' to None; the library did not, so `Path("")` became the
    current DIRECTORY, `.exists()` was True, and `Ledger("")` raised
    PermissionError on '.'. The documented escape hatch crashed."""
    if ledger_path is not None and str(ledger_path) == "":
        return None
    return ledger_path


def register(probes: list[Probe] | str | Path, *, label: str, runner: Runner,
             out_dir: str | Path = "registrations",
             ledger_path: str | Path | None = "arcaeon_baseline_ledger.jsonl",
             probes_path: str | Path | None = None,
             ) -> tuple[dict[str, Any], Path]:
    """Run the probe set through `runner`, score it, write a registration
    file, and chain a record of it into an arcaeon-ledger file. The
    pre-registration IS the timestamp: the ledger chain + the file's own
    `registered_at` prove this measurement existed before whatever comes
    next, without trusting anyone's memory of it.

    `probes` may be a path (loaded here) or an already-loaded probe list —
    pass `probes_path` alongside a pre-loaded list if you want that source
    path recorded for `compare()`'s convenience default.
    """
    ledger_path = _ledger_opt_out(ledger_path)
    if isinstance(probes, (str, Path)):
        probes_path = probes
        probes = load_probes(probes)
    digest = probe_set_digest(probes)
    items = run_probes(probes, runner)
    agg = aggregate(items)
    content_digest = _items_digest(items, agg)

    row = {
        "schema": REGISTRATION_SCHEMA,
        # The probe-set digest guards the EXAM from changing. This guards the
        # SCORER from changing, which was the unguarded half: `compare()`
        # re-scores with whatever version is installed then, and diffs against
        # scores frozen by whatever version was installed now. Without this
        # field a package upgrade in between is reported as a substrate change.
        "scoring_semantics": SCORING_SEMANTICS,
        "tool_version": __version__,
        "label": label,
        "probe_set_digest": digest,
        "probe_count": len(probes),
        "probes_path": str(probes_path) if probes_path is not None else None,
        "runner": runner.describe(),
        "items": items,
        "aggregate": agg,
        # Informational only — mirrors what got chained into the ledger below
        # so a human can eyeball it. NOT the trust anchor: an attacker editing
        # this file can recompute a matching value here too. The anchor is the
        # copy chained into the ledger, which `compare()` recomputes and checks
        # against independently (see the ledger-tamper check in `compare()`).
        "items_digest": content_digest,
        "registered_at": _now_iso(),
    }

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = row["registered_at"].replace(":", "").replace("-", "")
    file_path = out_dir / f"{_slug(label)}_{ts}.json"
    file_path.write_text(json.dumps(row, indent=2, ensure_ascii=False),
                         encoding="utf-8")
    row["_file"] = str(file_path)

    if ledger_path is not None:
        chain = Ledger(ledger_path).append({
            "kind": "arcaeon_baseline_registration",
            "label": label,
            "probe_set_digest": digest,
            "probe_count": len(probes),
            "registration_file": str(file_path),
            "aggregate_mean": agg["mean"],
            # The tamper-evidence anchor `compare()` checks the registration
            # file against — see `_items_digest`.
            "items_digest": content_digest,
        })
        row["_ledger_chain"] = chain

    return row, file_path


# ---------------------------------------------------------------------------
# Compare
# ---------------------------------------------------------------------------

def _compare_scope(agg_before: dict[str, Any], agg_after: dict[str, Any]) -> str:
    """How much of the probe set this comparison actually covered.

    `valid` answers a different question -- "was this comparison meaningful at
    all", i.e. did the exam stay the same underneath us. It has never answered
    "was every probe scored", and the two are easy to confuse because a report
    with `valid: True` and `n_flips: 0` reads as a clean bill of health.

    It can be a clean bill of health over half the exam. `run_probes` records
    an unanswerable probe with `score=None` and deliberately does not abort the
    batch (one flaky call shouldn't cost you the whole run -- correct). But
    `aggregate` then excludes those items from the mean, and a flip is a CHANGE
    in score, so a probe that was unscored in BOTH runs compares None to None,
    which is never a change and can never flip. The mean cannot see it either:
    the mean is over `n_scored`, so it stays 1.0 while probes go unanswered.

    Net effect before this field: a model that started REFUSING half your
    probes returned `valid=True, n_flips=0, mean=1.0` -- a perfect no-drift
    report from a run that scored one probe out of two. The evidence was
    already in the object (`aggregate_after.n_errors`) and nothing in the
    verdict read it.

    Values follow arcaeon-ledger's vocabulary so the whole family answers the
    coverage question in the same words:

      "full"                       every probe scored in both runs.
      "bounded_after_unscored"     probes went unscored in the current run.
      "bounded_before_unscored"    the registered baseline had unscored probes,
                                   so the thing being compared against is
                                   itself partial.
      "bounded_both_unscored"      both sides.

    A bounded scope is not a failure and does NOT flip `valid` -- the
    comparison really was valid, it just did not cover everything. This is the
    difference between "nothing changed" and "nothing changed in the part I
    could measure."
    """
    before_gap = bool(agg_before.get("n_errors"))
    after_gap = bool(agg_after.get("n_errors"))
    if before_gap and after_gap:
        return "bounded_both_unscored"
    if after_gap:
        return "bounded_after_unscored"
    if before_gap:
        return "bounded_before_unscored"
    return "full"


def _coverage_note(agg_before: dict[str, Any], agg_after: dict[str, Any]) -> str | None:
    """One sentence naming the unscored probes, or None when coverage is full.

    The silence was the defect: a partial run produced a report textually
    identical to a complete one.
    """
    parts = []
    for label, agg in (("this run", agg_after), ("the registered baseline", agg_before)):
        errs = agg.get("n_errors") or 0
        if errs:
            parts.append(f"{errs} of {agg.get('n')} probe(s) could not be scored "
                         f"in {label}")
    if not parts:
        return None
    return ("; ".join(parts) + ". Unscored probes cannot flip (None vs None is "
            "not a change) and are excluded from the mean, so they cannot "
            "produce drift no matter what the model does with them. Read "
            "n_flips as covering verified_scope, not the whole probe set.")


def compare(against: str | Path, *, runner: Runner,
            probes_path: str | Path | None = None,
            out_dir: str | Path = "comparisons",
            ledger_path: str | Path | None = "arcaeon_baseline_ledger.jsonl",
            ) -> tuple[dict[str, Any], Path]:
    """Re-run the probes registered in `against`, verify the probe-set digest
    still matches, and produce a diff. If the exam changed underneath you,
    `valid` is False and no diff is computed — a changed exam invalidates
    the comparison, and this says so rather than guessing anyway.

    `probes_path` defaults to the path recorded in the registration file.
    """
    ledger_path = _ledger_opt_out(ledger_path)
    reg = json.loads(Path(against).read_text(encoding="utf-8"))
    # A registration is a JSON object; a list/string/number here used to
    # surface as AttributeError on `.get`, not the "not a registration"
    # error the next line promises.
    if not isinstance(reg, dict) or reg.get("schema") != REGISTRATION_SCHEMA:
        schema = reg.get("schema") if isinstance(reg, dict) else None
        raise ValueError(f"{against}: not an arcaeon-baseline registration "
                         f"(schema={schema!r})")

    src = probes_path or reg.get("probes_path")
    if not src:
        raise ValueError(
            "no probes_path given and none recorded in the registration; "
            "pass probes_path= explicitly")
    probes = load_probes(src)
    current_digest = probe_set_digest(probes)
    registered_digest = reg["probe_set_digest"]
    registered_semantics = reg.get("scoring_semantics")

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    now = _now_iso()
    ts = now.replace(":", "").replace("-", "")

    def _invalid(reason: str, extra: dict, ledger_kind: str):
        report = {
            "schema": DIFF_SCHEMA,
            "valid": False,
            "reason": reason,
            "against_label": reg.get("label"),
            "against_file": str(against),
            "registered_probe_set_digest": registered_digest,
            "current_probe_set_digest": current_digest,
            "registered_scoring_semantics": registered_semantics,
            "current_scoring_semantics": SCORING_SEMANTICS,
            "compared_at": now,
            **extra,
        }
        file_path = out_dir / f"{_slug(reg.get('label', 'unlabeled'))}_INVALID_{ts}.json"
        file_path.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                             encoding="utf-8")
        if ledger_path is not None:
            Ledger(ledger_path).append({
                "kind": ledger_kind,
                "against_label": reg.get("label"),
                "against_file": str(against),
                "registered_probe_set_digest": registered_digest,
                "current_probe_set_digest": current_digest,
                "registered_scoring_semantics": registered_semantics,
                "current_scoring_semantics": SCORING_SEMANTICS,
            })
        return report, file_path

    if current_digest != registered_digest:
        return _invalid("probe set changed since registration — comparison invalid",
                        {}, "arcaeon_baseline_compare_invalid")

    # A changed SCORER invalidates a comparison exactly as a changed exam does,
    # and is harder to notice: the exam lives in your repo, the scorer arrives
    # in a `pip install -U`. `compare()` re-scores with the installed version
    # and diffs against scores frozen by the registering version, so a scoring
    # behaviour change shows up as a substrate delta with `valid: True` on it.
    # It has already happened once: 0.1.1 changed calibration scoring, so every
    # 0.1.0 registration compared under 0.1.1 reports improvement that no model
    # produced. Refuse the diff rather than publish a number nobody can read.
    if registered_semantics != SCORING_SEMANTICS:
        if registered_semantics is None:
            reason = ("registration predates scoring-semantics recording "
                      "(arcaeon-baseline < 0.1.2) — the scorer that produced "
                      "those scores cannot be identified, so a diff against "
                      f"{SCORING_SEMANTICS} would attribute scorer changes to "
                      "the substrate. Re-register a baseline with this version.")
        else:
            reason = (f"scoring semantics changed since registration "
                      f"({registered_semantics} -> {SCORING_SEMANTICS}) — "
                      "re-scoring old items with a new scorer measures the "
                      "scorer, not the substrate. Re-register a baseline.")
        return _invalid(reason, {"invalid_kind": "scoring_semantics"},
                        "arcaeon_baseline_compare_invalid_scoring")

    # FIXED (hostile audit, this pass) — the registration-tampering hole.
    # `compare()` used to trust `reg["items"]`/`reg["aggregate"]` straight off
    # disk with no cross-check at all: editing the registration JSON file
    # in-place (e.g. flipping a wrong item's `score` to 1.0 and its `output`
    # to the correct answer, or swapping two items' scores so the mean is
    # unchanged) was reported as a completely ordinary, `valid: True` diff —
    # the forged "before" value was used as ground truth for the flip. The
    # README's "tamper-evident" claim was true of the ledger's OWN chain
    # integrity but never actually checked against the file `compare()` reads.
    # Fix: if this registration was chained (`ledger_path` given and a
    # matching row exists), recompute the same content digest `register()`
    # chained and refuse the diff on a mismatch — the highest-severity
    # failure mode for a package whose whole point is catching a substrate
    # swap that quietly changed something, so treat "quietly changed by
    # editing the record" as no different from "quietly changed by editing
    # the exam" (handled above) or "quietly changed by editing the scorer"
    # (handled above that).
    #
    # Known limit, stated rather than silently accepted: a registration made
    # with `ledger_path=None`, or compared against a ledger file that doesn't
    # contain the matching row (wrong path, row predates this fix and has no
    # `items_digest`), has nothing to check against — this closes the hole
    # for chained registrations, not for unchained ones. That was already the
    # honest boundary of what a hash chain can prove (nothing to chain
    # against, nothing to detect against); it is not a regression this fix
    # introduces.
    # B-1, THIRD PASS (external audit 2026-08-28). Whether this check RAN is now
    # recorded in the report. B-1 fixed "the check silently did not run because
    # the path FORM differed"; the B-1 RESIDUAL fixed "...because the cwd
    # differed, so no row matched". Both left the OUTERMOST gate untouched:
    # `if ledger_file.exists()`. Delete the ledger and the entire tamper check is
    # skipped with no trace anywhere in the output — and because compare() chains
    # its own row on the way out, the ledger is RE-CREATED by the very run that
    # skipped the check, so what is left on disk looks freshly chained.
    # Demonstrated: register, edit the registration's score, remove the ledger
    # file, compare -> `valid: True` reporting a fabricated +0.5 improvement.
    # That is the exact "no record found" that really means "I looked at the
    # wrong file".
    # `valid` is deliberately NOT flipped here — that is a consumer-visible
    # behaviour change, flagged in the CHANGELOG for a decision rather than taken
    # silently. What changes is that a reader can now TELL the two apart, which
    # they could not before at any level of diligence.
    chain_check: dict[str, Any] = {
        "ran": False,
        "status": "skipped_no_ledger_path",
        "detail": ("no ledger_path was given, so the registration's contents were "
                   "not checked against any chained record. This diff's `before` "
                   "side is trusted straight off disk."),
    }
    if ledger_path is not None:
        ledger_file = Path(ledger_path)
        if not ledger_file.exists():
            # INVALID, not merely disclosed. Changed 2026-08-28.
            #
            # This branch used to write the detail below and then FALL THROUGH,
            # leaving valid=True. The disclosure described the attack accurately
            # and the verdict contradicted it: tamper a registration to fake a
            # benchmark gain, delete one file, and the fabricated gain reported
            # as valid -- while compare() chained a fresh row on the way out, so
            # the run manufactured its own alibi and later forensics found a
            # clean-looking chain.
            #
            # What settles it is this module's own behaviour elsewhere:
            # `chain_unlocatable` (ledger PRESENT, no row for this file) already
            # returns _invalid, and that state is HARDER to reach than deleting
            # a file. Treating `rm` more leniently than a wrong working
            # directory cannot be defended in a tamper-evidence product.
            #
            # Honest unchained users are not stranded -- the explicit
            # ledger_path="" opt-out already existed and is already documented.
            # They now have to say they meant it, which is the whole point.
            return _invalid(
                "a ledger was requested but the file is absent, so this "
                "registration cannot be confirmed untampered",
                {"invalid_kind": "chain_ledger_absent",
                 "chain_check": {
                     "ran": False,
                     "status": "ledger_file_absent",
                     "detail": (f"a ledger was requested ({str(ledger_path)!r}) but no "
                                "such file exists, so the registration could NOT be "
                                "checked against its chained record. An edited "
                                "registration is indistinguishable from an honest one "
                                "here, and deleting the ledger is enough to reach this "
                                "state. Re-run from the working directory register() "
                                "used, or pass an empty ledger_path to state that you "
                                "meant to skip the check."),
                 }},
                "arcaeon_baseline_compare_invalid_chain_ledger_absent")
        if ledger_file.exists():
            chain_ledger = Ledger(ledger_path)
            chain_verify = chain_ledger.verify()
            if chain_verify.ok is False:
                return _invalid(
                    "the ledger this registration was chained into no longer "
                    "verifies (broken chain) — its record of this "
                    "registration cannot be trusted",
                    {"invalid_kind": "ledger_broken",
                     "chain_check": {"ran": True, "status": "ledger_broken",
                                     "detail": str(chain_verify.first_break)}},
                    "arcaeon_baseline_compare_invalid_ledger")
            if chain_verify.ok is None:
                # TRI-STATE, NOT TWO (arcaeon-ledger >= 0.5.7). `not ok` swept
                # ok=None into the "broken chain" accusation: an empty ledger
                # file, unchained prechain rows, or a declared break all made
                # compare() tell an operator their ledger was BROKEN when the
                # truth is "no fault found, and the scan did not cover
                # everything". Same verdict (invalid either way, correctly — a
                # scan that did not cover everything cannot confirm this
                # registration); an honest reason instead of a false charge.
                return _invalid(
                    "the ledger this registration was chained into could not be "
                    "verified end to end (verified_scope="
                    f"{getattr(chain_verify, 'verified_scope', 'unknown')!r}, "
                    f"{chain_verify.rows} row(s)) — NO fault was found, but the "
                    "scan did not cover every row, so its record of this "
                    "registration cannot be confirmed untampered. This is an "
                    "unanswered question, not an accusation against your ledger",
                    {"invalid_kind": "ledger_unverifiable",
                     "chain_check": {
                         "ran": True, "status": "ledger_unverifiable",
                         "detail": getattr(chain_verify, "verified_scope", "unknown")}},
                    "arcaeon_baseline_compare_invalid_ledger")
            # B-1 (product audit 2026-08-23): comparing the raw STRING form
            # of `against` against the recorded `registration_file` made the
            # match — and therefore the entire tamper check above — silently
            # fail whenever the two differ only in FORM: `register()` records
            # whatever `out_dir` form it was given (this CLI's own default is
            # a relative "registrations/"), and a caller passing `--against`
            # in a different form (an absolute path, most commonly — the
            # ordinary shape when a script resolves the path returned by
            # register() rather than typing it back verbatim) never matched,
            # so `matches` came back empty and the check silently did not
            # run. Not a hypothetical: the CLI's own module docstring shows
            # a relative `--against`, and register()'s CLI print of `path`
            # is relative too — the mismatch needs only one `.resolve()`
            # anywhere in the caller's chain. Resolve both sides to their
            # canonical absolute form so the match is by FILE, not by
            # STRING. Known limit, same shape as the ledger_path=None case
            # already documented above: this assumes compare() runs from a
            # cwd under which the ledger's relative-recorded path still
            # resolves to the same file register() wrote — true whenever
            # register() and compare() share a working directory, which is
            # the case this whole ledger-chain mechanism is designed for.
            against_resolved = Path(against).resolve()
            matches = [r for r in chain_ledger
                      if r.get("kind") == "arcaeon_baseline_registration"
                      and r.get("registration_file")
                      and Path(r["registration_file"]).resolve() == against_resolved]
            # B-1 RESIDUAL (Fable's independent review, 2026-08-24): the
            # `.resolve()` fix above closes the RELATIVE-vs-ABSOLUTE form
            # mismatch, but a resolved path is only correct relative to the
            # CURRENT working directory — if compare() runs from a different
            # cwd than register() did, and both used relative defaults (this
            # CLI's own default `--out registrations/` and
            # `arcaeon_baseline_ledger.jsonl`), `against_resolved` and the
            # ledger's relative-recorded path both resolve against the WRONG
            # cwd and disagree again, `matches` comes back empty, and the
            # entire tamper check silently does not run — the exact same
            # failure SHAPE as the original B-1, moved one level. `ledger_path`
            # defaults to a real path (chain verification is requested unless
            # the caller explicitly opts out with `ledger_path=""`/None), the
            # ledger file exists, and it verifies clean — so if no row can be
            # found for this specific registration, that is now UNCONFIRMABLE,
            # not confirmed-clean, and must not silently complete as
            # `valid: True`. We cannot distinguish "never chained", "chained
            # under a different cwd", or "forged" from here — refuse rather
            # than guess, exactly the discipline used for a genuine tamper
            # detection above. A caller who genuinely wants to skip the check
            # (an intentionally unchained registration) must say so explicitly
            # by passing `ledger_path=""` to compare(), not rely on an
            # accidental miss.
            if not matches:
                return _invalid(
                    "no chained ledger record could be located for this "
                    "registration, though a ledger was provided and it "
                    "verifies clean — this registration cannot be confirmed "
                    "untampered. If it was genuinely never chained, pass "
                    "ledger_path='' to compare() explicitly to skip this "
                    "check; otherwise re-run from the same working directory "
                    "register() used, or pass --against as the exact path "
                    "recorded in the ledger",
                    {"invalid_kind": "chain_unlocatable",
                     "chain_check": {
                         "ran": True, "status": "chain_unlocatable",
                         "detail": "the ledger verifies, but holds no row naming "
                                   "this registration file"}},
                    "arcaeon_baseline_compare_invalid_chain_unlocatable")
            if matches:
                expected_digest = matches[-1].get("items_digest")
                if expected_digest is None:
                    # a row from before items_digest existed: located, but it
                    # carries nothing to compare the file against
                    chain_check = {
                        "ran": False,
                        "status": "skipped_row_predates_items_digest",
                        "detail": ("the chained row for this registration was "
                                   "written by a version that did not record "
                                   "`items_digest`, so there is nothing to check "
                                   "the file's contents against"),
                    }
                else:
                    actual_digest = _items_digest(reg.get("items", []),
                                                  reg.get("aggregate", {}))
                    if actual_digest != expected_digest:
                        return _invalid(
                            "registration file's scored content does not "
                            "match its own ledger-chained record — the file "
                            "was modified after registration (tamper-"
                            "evidence check failed)",
                            {"invalid_kind": "registration_tampered",
                             "chain_check": {
                                 "ran": True, "status": "registration_tampered",
                                 "detail": "content digest mismatch"}},
                            "arcaeon_baseline_compare_invalid_tamper")
                    chain_check = {
                        "ran": True,
                        "status": "verified",
                        "detail": ("the registration file's scored content matches "
                                   "the digest chained into the ledger at "
                                   "registration time"),
                    }

    items_after = run_probes(probes, runner)
    agg_after = aggregate(items_after)
    items_before = {it["id"]: it for it in reg["items"]}
    agg_before = reg["aggregate"]

    flips = []
    for it in items_after:
        before = items_before.get(it["id"])
        if before is None:
            continue
        if before.get("score") != it.get("score"):
            flips.append({
                "id": it["id"],
                "scoring_type": it["scoring_type"],
                "before_score": before.get("score"),
                "after_score": it.get("score"),
                "before_output": before.get("output"),
                "after_output": it.get("output"),
            })

    delta_mean = None
    if agg_before.get("mean") is not None and agg_after["mean"] is not None:
        delta_mean = agg_after["mean"] - agg_before["mean"]

    calibration_shift = None
    if agg_before.get("calibration") and agg_after.get("calibration"):
        cb, ca = agg_before["calibration"], agg_after["calibration"]
        calibration_shift = {}
        for key in ("abstention_rate_answerable", "abstention_rate_unanswerable"):
            b, a = cb.get(key), ca.get(key)
            calibration_shift[key] = {
                "before": b, "after": a,
                "delta": (a - b) if (a is not None and b is not None) else None,
            }
        calibration_shift["confident_wrong_count"] = {
            "before": cb.get("confident_wrong_count"),
            "after": ca.get("confident_wrong_count"),
        }

    report = {
        "schema": DIFF_SCHEMA,
        "valid": True,
        "against_label": reg.get("label"),
        "against_file": str(against),
        "against_registered_at": reg.get("registered_at"),
        # Did the registration-tamper check actually RUN? `valid: True` alone
        # never said, so a diff whose check was silently skipped was
        # indistinguishable from one that was verified (audit 2026-08-28).
        "chain_check": chain_check,
        "probe_set_digest": current_digest,
        "runner": runner.describe(),
        "n": len(items_after),
        "flips": flips,
        "n_flips": len(flips),
        "aggregate_before": agg_before,
        "aggregate_after": agg_after,
        "aggregate_delta": {"mean": delta_mean},
        "calibration_shift": calibration_shift,
        "significance_note": _significance_note(agg_after["n_scored"], delta_mean),
        "verified_scope": _compare_scope(agg_before, agg_after),
        "coverage_note": _coverage_note(agg_before, agg_after),
        "compared_at": now,
    }
    file_path = out_dir / f"{_slug(reg.get('label', 'unlabeled'))}_vs_now_{ts}.json"
    file_path.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                         encoding="utf-8")

    if ledger_path is not None:
        chain = Ledger(ledger_path).append({
            "kind": "arcaeon_baseline_compare",
            "against_label": reg.get("label"),
            "against_file": str(against),
            "probe_set_digest": current_digest,
            "n_flips": len(flips),
            "aggregate_delta_mean": delta_mean,
            "comparison_file": str(file_path),
        })
        report["_ledger_chain"] = chain

    return report, file_path
