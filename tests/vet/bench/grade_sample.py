"""Grade a registry sample per bench/PLAN.md. Read the plan first; this file is
its executable half and must not quietly drift from it.

    py projects/mcp_vet/bench/grade_sample.py --snapshot registry_<stamp>.jsonl
    py projects/mcp_vet/bench/grade_sample.py --snapshot ... --ours-only
    py projects/mcp_vet/bench/grade_sample.py --snapshot ... --n 10   # smoke

Output: bench/results/<stamp>_sample.jsonl (one row per server, every bucket)
plus <stamp>_summary.json (schema 1, see summary_schema.py). Re-runnable:
rows already present are skipped, so a crash mid-sample resumes instead of
re-cloning 40 repos. Append-only: a differing row for a name already on disk
raises instead of overwriting (M30). A no-handler-found row is only allowed
after every package.json / pyproject.toml directory the first walk missed has
been graded too (M19), and carries the fields that let the miss be classified
afterwards (M20).
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
from arcaeon.prove.vet import __version__  # noqa: E402
from arcaeon.prove.vet.grade import grade_source  # noqa: E402
from arcaeon.prove.vet import ts_checks, checks  # noqa: E402
from arcaeon.prove.vet.badge import battery_digest  # noqa: E402
from arcaeon.prove.vet.service import select_files, PRUNE_DIRS  # noqa: E402
from registry_scrape import gradability  # noqa: E402
from summary_schema import (  # noqa: E402
    SCHEMA_VERSION, NO_HANDLER_REASONS, NO_HANDLER_UNCLASSIFIED,
    exclusions_block, checks_run_by_lang, validate_summary)

SNAP_DIR = HERE / "snapshots"
RES_DIR = HERE / "results"
SAMPLE_N = 100
CLONE_TIMEOUT = 120
SUFFIXES = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs")
# item 146, 2026-09-05: PRUNE is now `mcp_vet.service.PRUNE_DIRS`, the SAME
# set `grade-target` prunes, so this harness and the published CLI select
# files identically (a superset of the old local PRUNE: adds fixtures/ and
# __snapshots__, plus the cache dirs grade-target already pruned).
PRUNE = PRUNE_DIRS
# Directories never worth reading for ANY purpose (markers, manifests). Smaller
# than PRUNE on purpose: a package.json in `examples/` is still a place we did
# not look, and M20 wants to know that.
NEVER = {"node_modules", ".git", "venv", ".venv", "site-packages", "__pycache__"}
# `tools/call` catches hand-rolled dispatchers (arcaeon-ledger speaks the
# protocol directly; the first --ours-only run called it "no-handler-found").
MARKER = re.compile(r"@mcp\.tool|\.tool\(|registerTool\(|setRequestHandler\(|addTool\(|call_tool|tools/call")

# M22: every server lands in exactly one of these. Anything else is a bug in
# the scrape, and the benchmark refuses to compute a denominator over it.
BUCKETS = ("ungradable:remote-only", "ungradable:no-source-no-remote",
           "gradable:package-only", "gradable:repo")

# M20: language markers for the SDKs the scanner does not read. A file name
# in the first set or a suffix in the second counts; see PLAN.md's dated
# addendum for the handler-registration functions of each SDK (not scanned).
LANG_MARKERS = {
    "go": ({"go.mod"}, {".go"}),
    "rust": ({"Cargo.toml"}, {".rs"}),
    "java": ({"pom.xml", "build.gradle", "build.gradle.kts"}, {".java", ".kt"}),
    "csharp": (set(), {".cs", ".csproj", ".sln", ".fsproj"}),
}
MANIFESTS = {"package.json", "pyproject.toml"}
MAX_MANIFEST_RETRIES = 20


class BucketError(ValueError):
    """A snapshot row that is in no bucket, or in a bucket its fields deny."""


class ResultConflict(RuntimeError):
    """A re-run produced a different row for a name already in the results."""

# Our own, graded with the same code, reported first (PLAN.md).
OURS = {
    "arcaeon-ledger": Path.home() / "arcaeon-ledger",
    "arcaeon-distill": Path.home() / "arcaeon-distill",
    "arcaeon-once": Path.home() / "arcaeon-once",
    "arcaeon-continuity": Path.home() / "arcaeon-continuity",
    "arcaeon_connector": HERE.parent.parent / "arcaeon_connector",
}


def load_snapshot(name: str):
    path = SNAP_DIR / name
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    summary = json.loads(path.with_suffix(".summary.json").read_text(encoding="utf-8"))
    return rows, summary


def population(rows):
    """Distinct servers = latest, active rows. One per name."""
    seen, out = set(), []
    for r in rows:
        if r["is_latest"] and r["status"] == "active" and r["name"] not in seen:
            seen.add(r["name"])
            out.append(r)
    return out


def bucket_counts(pop) -> dict:
    """M22: one bucket per server, buckets sum to the population. Raises on a
    row whose label is unknown or disagrees with its own fields, rather than
    letting the denominator quietly shrink or grow."""
    counts = Counter()
    for r in pop:
        b = r.get("gradability")
        if b not in BUCKETS:
            raise BucketError(f"{r.get('name')!r}: gradability {b!r} is not one of {BUCKETS}")
        recomputed = gradability(r)
        if recomputed != b:
            raise BucketError(f"{r.get('name')!r}: labelled {b!r} but fields say {recomputed!r}")
        counts[b] += 1
    if sum(counts.values()) != len(pop):
        raise BucketError("bucket counts do not sum to the population")
    return {b: counts.get(b, 0) for b in BUCKETS}


def sample(pop, sha256: str, n: int):
    frame = [r for r in pop if r["gradability"] == "gradable:repo"]
    rng = random.Random(int(sha256[:8], 16))
    return rng.sample(frame, min(n, len(frame))), len(frame)


def candidate_files(root: Path):
    # item 146, 2026-09-05: the walk+prune step is `select_files`, the SAME
    # function `grade-target` uses, so this harness and the published CLI
    # agree on what counts as this server's own code (including filename-
    # pattern pruning like `test_*.py` / `conftest.py` outside a tests/ dir,
    # which the old local PRUNE — directory names only — could not catch).
    # candidate_files then layers its OWN, stricter MARKER requirement on top
    # (a file must show a handler-registration call to count as a "candidate"
    # at all); that layer stays bench-specific, not part of file SELECTION.
    for p in select_files(root):
        try:
            head = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if MARKER.search(head):
            yield p, head


def _rel(path: Path, base: Path) -> str:
    r = str(path.relative_to(base)).replace("\\", "/")
    return "." if r in ("", ".") else r


def repo_markers(dest: Path) -> tuple[dict, list[str]]:
    """M20 fields for a checkout: per-language file counts (Go/Rust/Java/C#
    markers plus our own .py/.ts) and every directory holding a package.json
    or pyproject.toml, both over the WHOLE clone, so a later classifier can
    say which kind of miss a no-handler-found was."""
    counts = Counter()
    manifests: set[str] = set()
    for p in dest.rglob("*"):
        rel_parts = p.relative_to(dest).parts
        if any(part in NEVER for part in rel_parts):
            continue
        if not p.is_file():
            continue
        if p.name in MANIFESTS:
            manifests.add(_rel(p.parent, dest))
        for lang, (names, suffixes) in LANG_MARKERS.items():
            if p.name in names or p.suffix in suffixes:
                counts[lang] += 1
        if p.suffix == ".py":
            counts["py"] += 1
        elif p.suffix in SUFFIXES:
            counts["ts"] += 1
    markers = {k: counts.get(k, 0) for k in ("go", "rust", "java", "csharp", "py", "ts")}
    return markers, sorted(manifests)


def _covered(rel_dir: str, scanned_dirs: list[str]) -> bool:
    """Did a candidate_files() walk rooted at one of `scanned_dirs` actually
    read `rel_dir`? True only if it sits under a scanned root with no PRUNE
    name on the path between them."""
    parts = [x for x in rel_dir.split("/") if x and x != "."]
    for s in scanned_dirs:
        sp = [x for x in s.split("/") if x and x != "."]
        if parts[:len(sp)] != sp:
            continue
        if any(x in PRUNE for x in parts[len(sp):]):
            continue
        return True
    return False


def classify_no_handler(row: dict) -> str:
    """M20: split a no-handler-found row into one of three reasons using only
    what the row carries. Rows graded before the fields existed get
    NO_HANDLER_UNCLASSIFIED; they are never guessed into a reason."""
    m = row.get("repo_markers")
    if m is None or "manifest_dirs" not in row or "scanned_dirs" not in row:
        return NO_HANDLER_UNCLASSIFIED
    if any(m.get(k, 0) for k in ("go", "rust", "java", "csharp")):
        return "unsupported-language"
    if m.get("py", 0) == 0 and m.get("ts", 0) == 0:
        return "unsupported-language"
    if any(not _covered(d, row["scanned_dirs"]) for d in row["manifest_dirs"]):
        return "monorepo-miss"
    return "no-handler"


def no_handler_split(rows: list[dict]) -> dict:
    split = {**{r: 0 for r in NO_HANDLER_REASONS}, NO_HANDLER_UNCLASSIFIED: 0}
    for d in rows:
        if d["outcome"] == "no-handler-found":
            split[d.get("no_handler_reason") or classify_no_handler(d)] += 1
    return split


def gate_reached(grade, src: str, rel: str) -> int:
    """0..4 per PLAN.md, or -1 when the file was never asked. An empty finding
    list is "all gates met" ONLY when the check found handlers and an
    entrypoint; otherwise it is a fragment or a test file, and on the first
    --ours-only run a test file was the "best file" of arcaeon_connector."""
    if "audit-record" not in grade.checks_run:
        return -1
    applies = (ts_checks.audit_record_applies(src, rel) if ts_checks.is_ts_path(rel)
               else checks.audit_record_applies(src))
    if not applies:
        return -1
    ar = [f for f in grade.findings if f["check"] == "audit-record"]
    if not ar:
        return 4
    g = ar[0].get("gates") or {}
    order = ["presence", "completeness", "tamper_evidence", "reconstructability"]
    n = 0
    for k in order:
        if g.get(k):
            n += 1
        else:
            break
    return n


def grade_tree(root: Path, base: Path | None = None) -> dict:
    """Grade every candidate file under `root`. File paths are recorded
    relative to `base` (default: root) so a manifest-scan retry into a
    subfolder still reports paths from the clone root."""
    base = base or root
    files, best, langs = [], -1, Counter()
    for p, src in candidate_files(root):
        rel = str(p.relative_to(base)).replace("\\", "/")
        # M41: same condition service.scan_target uses. A Python file gets the
        # directory it sits in, so `audit-record` may open the sibling module an
        # import names; TS keeps None (its sibling walk is the `resolve` hook,
        # not this one). Without it the benchmark measured every multi-file
        # Python server through the confessed single-file blind spot and read
        # gate 0 off servers that record one relative import away.
        package_dir = p.parent if (root.is_dir() and not ts_checks.is_ts_path(rel)) else None
        g = grade_source(src, rel, package_dir=package_dir)
        gate = gate_reached(g, src, rel)
        lang = "ts" if ts_checks.is_ts_path(rel) else "py"
        langs[lang] += 1
        files.append({"file": rel, "lang": lang, "checks_run": g.checks_run,
                      "verdict": g.verdict, "gate": gate,
                      "audit_detail": next((f["detail"] for f in g.findings
                                            if f["check"] == "audit-record"), None)})
        best = max(best, gate)
    if not files:
        return {"outcome": "no-handler-found", "files": [], "gate": None, "langs": {}}
    if best < 0:
        return {"outcome": "no-handler-found", "files": files, "gate": None, "langs": dict(langs)}
    return {"outcome": "graded", "files": files, "gate": best, "langs": dict(langs)}


def clone(url: str, dest: Path) -> str | None:
    # A private or deleted repo makes git ask for credentials. GIT_TERMINAL_PROMPT=0
    # only silences the terminal; on Windows git-credential-manager still opens a
    # (hidden) window and waits forever, and a timeout that kills git.exe leaves
    # git-remote-https + the credential manager holding our stdout/stderr pipes,
    # so `communicate()` never returns: the 9/2 run sat at item 39 for an hour
    # on rooz21/x402. Three fences: no credential helper at all (an anonymous
    # clone is the only kind this benchmark should make), the GCM told not to
    # be interactive if it is invoked anyway, and a tree kill on timeout.
    cmd = ["git", "-c", "credential.helper=", "-c", "core.askPass=",
           "clone", "--depth", "1", "--quiet", url, str(dest)]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never",
           "GIT_ASKPASS": "", "SSH_ASKPASS": ""}
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                         text=True, env=env)
    try:
        _, err = p.communicate(timeout=CLONE_TIMEOUT)
    except subprocess.TimeoutExpired:
        _kill_tree(p.pid)
        try:
            p.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        return "timeout"
    if p.returncode != 0:
        return (err or "clone failed").strip().splitlines()[-1][:200]
    return None


def _kill_tree(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        os.kill(pid, 9)


def grade_checkout(dest: Path, subfolder: str | None) -> dict:
    """Grade a cloned tree. M19: the registry's `repo_subfolder` is where we
    look first; if that yields no handler, every directory in the clone that
    holds a package.json or pyproject.toml and was NOT covered by the first
    walk is graded too, before the row is allowed to say no-handler-found.
    Records the M20 fields (`repo_markers`, `manifest_dirs`, `scanned_dirs`)
    on every row so the miss can be classified afterwards."""
    out: dict = {}
    root = dest / subfolder.strip("/") if subfolder else dest
    if not root.exists():
        root = dest  # registry subfolder wrong; grade the whole tree and say so
        out["subfolder_missing"] = True
    markers, manifests = repo_markers(dest)
    out["repo_markers"], out["manifest_dirs"] = markers, manifests
    scanned = [_rel(root, dest)]
    result = grade_tree(root, base=dest)
    if result["outcome"] == "no-handler-found":
        parts = [result]
        for d in manifests:
            if _covered(d, scanned) or len(scanned) > MAX_MANIFEST_RETRIES:
                continue
            scanned.append(d)
            parts.append(grade_tree(dest / d, base=dest))
        if len(parts) > 1:
            result = _merge_grades(parts)
            if result["outcome"] == "graded":
                result["found_via"] = "manifest-scan"
    out["scanned_dirs"] = scanned
    out.update(result)
    if out["outcome"] == "no-handler-found":
        out["no_handler_reason"] = classify_no_handler(out)
    return out


def _merge_grades(parts: list[dict]) -> dict:
    files = [f for p in parts for f in p["files"]]
    langs = Counter()
    for p in parts:
        langs.update(p["langs"])
    gates = [p["gate"] for p in parts if p["outcome"] == "graded"]
    if gates:
        return {"outcome": "graded", "files": files, "gate": max(gates), "langs": dict(langs)}
    return {"outcome": "no-handler-found", "files": files, "gate": None, "langs": dict(langs)}


def grade_row(r: dict, work: Path) -> dict:
    out = {"name": r["name"], "repo_url": r["repo_url"], "subfolder": r.get("repo_subfolder"),
           "version": r["version"], "packages": r["package_registries"]}
    dest = work / re.sub(r"[^A-Za-z0-9_.-]", "_", r["name"])[:80]
    err = clone(r["repo_url"], dest)
    if err:
        out.update(outcome="clone-failed", reason=err, gate=None, files=[], langs={})
        return out
    out.update(grade_checkout(dest, r.get("repo_subfolder")))
    shutil.rmtree(dest, ignore_errors=True)
    return out


# --- M30: results are append-only -------------------------------------------
VOLATILE = ("seconds",)   # wall-clock; two honest runs never agree on it


def _stable(row: dict) -> dict:
    return {k: v for k, v in row.items() if k not in VOLATILE}


def load_results(path: Path) -> dict:
    """Rows already on disk, by name. Two rows for one name that differ in
    anything but wall-clock are a conflict, not a resume."""
    done: dict = {}
    if not path.exists():
        return done
    for l in path.read_text(encoding="utf-8").splitlines():
        if not l.strip():
            continue
        d = json.loads(l)
        prev = done.get(d["name"])
        if prev is not None and _stable(prev) != _stable(d):
            raise ResultConflict(f"{path.name}: two differing rows for {d['name']!r}")
        done[d["name"]] = d
    return done


def append_row(fh, done: dict, row: dict) -> dict:
    """Write `row` unless a row for its name exists. Identical (modulo
    wall-clock) is a no-op; different raises. A results file is a record of
    what was graded, and a record you can overwrite is not one."""
    prev = done.get(row["name"])
    if prev is not None:
        if _stable(prev) == _stable(row):
            return prev
        raise ResultConflict(
            f"refusing to overwrite {row['name']!r}: the new row differs from the one on disk "
            "(delete the results file deliberately if a regrade is intended)")
    fh.write(json.dumps(row, sort_keys=True) + "\n")
    fh.flush()
    done[row["name"]] = row
    return row


def build_summary(*, snapshot: str, snap_summary: dict, pop, frame_n: int, picked,
                  results: list[dict]) -> dict:
    theirs = [d for d in results if not d.get("ours")]
    graded = [d for d in theirs if d["outcome"] == "graded"]
    summ = {
        "snapshot": snapshot, "snapshot_sha256": snap_summary["sha256"],
        "mcp_vet_version": __version__, "plan": "bench/PLAN.md",
        "servers_distinct_active": len(pop),
        "buckets": bucket_counts(pop),
        "frame_gradable_repo": frame_n, "sample_n": len(picked),
        "seed": "int(sha256[:8], 16)",
        "outcomes": dict(Counter(d["outcome"] for d in theirs)),
        "gate_distribution_graded": dict(Counter(str(d["gate"]) for d in graded)),
        "gate_by_lang": {
            lang: dict(Counter(str(d["gate"]) for d in graded if lang in d["langs"]))
            for lang in ("py", "ts")},
        "ours": [{"name": d["name"], "outcome": d["outcome"], "gate": d["gate"],
                  "files": [(f["file"], f["gate"]) for f in d["files"]]}
                 for d in results if d.get("ours")],
        "no_handler_found": [d["name"] for d in theirs if d["outcome"] == "no-handler-found"],
        "clone_failed": [(d["name"], d.get("reason")) for d in theirs if d["outcome"] == "clone-failed"],
    }
    summ["schema"] = SCHEMA_VERSION
    summ["exclusions"] = exclusions_block(summ)
    summ["battery_digest"] = battery_digest()
    summ["checks_run_by_lang"] = checks_run_by_lang(results)
    summ["no_handler_found_split"] = no_handler_split(theirs)
    summ["no_handler_found_by_reason"] = {
        reason: [d["name"] for d in theirs if d["outcome"] == "no-handler-found"
                 and (d.get("no_handler_reason") or classify_no_handler(d)) == reason]
        for reason in (*NO_HANDLER_REASONS, NO_HANDLER_UNCLASSIFIED)}
    return validate_summary(summ)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", required=True)
    ap.add_argument("--n", type=int, default=SAMPLE_N)
    ap.add_argument("--ours-only", action="store_true")
    a = ap.parse_args()

    rows, summary = load_snapshot(a.snapshot)
    pop = population(rows)
    picked, frame_n = sample(pop, summary["sha256"], a.n)
    stamp = a.snapshot.replace("registry_", "").replace(".jsonl", "")
    RES_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RES_DIR / f"{stamp}_sample.jsonl"
    done = load_results(out_path)   # raises on a conflicting duplicate (M30)

    results = []
    with out_path.open("a", encoding="utf-8") as fh:
        for name, path in OURS.items():
            key = "ours:" + name
            if key in done:
                results.append(done[key]); continue
            d = {"name": key, "repo_url": str(path), "ours": True}
            d.update(grade_checkout(path, None) if path.exists() else
                     {"outcome": "clone-failed", "reason": "path missing", "gate": None, "files": [], "langs": {}})
            results.append(append_row(fh, done, d))
        if not a.ours_only:
            work = Path(tempfile.mkdtemp(prefix="mcpbench_"))
            try:
                for i, r in enumerate(picked, 1):
                    if r["name"] in done:
                        results.append(done[r["name"]]); continue
                    t0 = time.time()
                    d = grade_row(r, work)
                    d["seconds"] = round(time.time() - t0, 1)
                    results.append(append_row(fh, done, d))
                    sys.stderr.write(f"\r{i}/{len(picked)} {d['outcome']:<22} {r['name'][:50]:<50}")
            finally:
                shutil.rmtree(work, ignore_errors=True)
            sys.stderr.write("\n")

    summ = build_summary(snapshot=a.snapshot, snap_summary=summary, pop=pop,
                         frame_n=frame_n, picked=picked, results=results)
    (RES_DIR / f"{stamp}_summary.json").write_text(json.dumps(summ, indent=2), encoding="utf-8")
    print(json.dumps(summ, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
