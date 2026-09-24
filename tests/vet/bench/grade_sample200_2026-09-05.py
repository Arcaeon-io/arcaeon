"""Board item 81 (BATCH_100_2026-09-05_PROPOSED.md), source PLAN_90_DAYS_SMALL_CASE
Action 3. A SEPARATE draw from bench/PLAN.md's own 100-sample: this one is seeded
with the literal integer 20260905 (not derived from the snapshot sha256), n=200,
and grades each server through the `python -m arcaeon.prove.vet grade-target` CLI as a
subprocess (not by importing grade_source directly) so the artifact matches
exactly what a stranger running the published command gets.

    py projects/mcp_vet/bench/grade_sample200_2026-09-05.py --snapshot registry_2026-09-02T2142Z.jsonl
    py projects/mcp_vet/bench/grade_sample200_2026-09-05.py --snapshot ... --n 10   # smoke
    py projects/mcp_vet/bench/grade_sample200_2026-09-05.py --snapshot ... --ours-only

Output: bench/results/sample200_2026-09-05_rows.jsonl (one row per server) and
bench/results/sample200_2026-09-05_summary.json. Resumable: a name already on
disk is skipped, never re-cloned. Per-server clone timeout and grade-target
timeout are each 60s (two separate 60s windows, not one shared budget — see the
FAILURE_DISTRIBUTION report's Method section for why).

Three failure states, never folded into "no findings":
  UNFETCHABLE  - clone did not succeed and did not merely time out (private,
                 deleted, 404, auth prompt refused)
  TIMEOUT      - the clone OR the grade-target subprocess ran past 60s
  UNPARSED     - grade-target exited but stdout was not valid JSON (crash,
                 traceback, truncated output)
A server that cloned and graded lands as GRADED, even when it graded to
"no findings" or the tool found no gradeable file inside it (that is
`no-handler`, a real outcome, not a fetch failure).
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
from pathlib import Path

HERE = Path(__file__).resolve().parent          # projects/mcp_vet/bench
MCP_VET_DIR = HERE.parent                        # projects/mcp_vet (cwd for `py -m mcp_vet`)
SNAP_DIR = HERE / "snapshots"
RES_DIR = HERE / "results"
SEED = 20260905
SAMPLE_N = 200
CLONE_TIMEOUT = 60
GRADE_TIMEOUT = 60

BUCKETS = ("ungradable:remote-only", "ungradable:no-source-no-remote",
           "gradable:package-only", "gradable:repo")

# Our own two local trees, graded with the identical CLI call, reported FIRST
# and OUTSIDE the sample (task instruction: "our own failures first").
OURS = {
    "arcaeon_mcp": Path("projects/arcaeon_mcp"),
    "mcp_vet": Path("projects/mcp_vet"),
}


def load_snapshot(name: str):
    path = SNAP_DIR / name
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    summary = json.loads(path.with_suffix(".summary.json").read_text(encoding="utf-8"))
    return rows, summary


def population(rows):
    seen, out = set(), []
    for r in rows:
        if r["is_latest"] and r["status"] == "active" and r["name"] not in seen:
            seen.add(r["name"])
            out.append(r)
    return out


def sample200(pop, n: int):
    frame = [r for r in pop if r["gradability"] == "gradable:repo"]
    rng = random.Random(SEED)
    return rng.sample(frame, min(n, len(frame))), len(frame)


def _kill_tree(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        os.kill(pid, 9)


def clone(url: str, dest: Path) -> tuple[str, str | None]:
    """Returns (state, reason). state in {"ok", "timeout", "unfetchable"}."""
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
        return "timeout", "clone exceeded %ds" % CLONE_TIMEOUT
    if p.returncode != 0:
        return "unfetchable", (err or "clone failed").strip().splitlines()[-1][:200]
    return "ok", None


def grade_target_cli(path: Path) -> tuple[str, dict | None, str | None]:
    """Run `py -m arcaeon.prove.vet grade-target <path>` as a subprocess from MCP_VET_DIR.
    Returns (state, parsed_json_or_None, raw_or_error). state in
    {"graded", "timeout", "unparsed"}."""
    cmd = [sys.executable, "-m", "mcp_vet", "grade-target", str(path)]
    # PYTHONIOENCODING forces the CHILD's stdout to utf-8 regardless of the
    # Windows console code page (cp1252 by default), which otherwise raises
    # UnicodeEncodeError inside the child on any repo whose source has a
    # non-cp1252 byte and reads as a spurious UNPARSED — a harness bug, not a
    # fact about the server. First smoke run (5 servers, pre-fix) hit this on
    # 1/5; fixed before the real 200-sample run started.
    env = {**os.environ, "PYTHONIOENCODING": "utf-8:replace", "PYTHONUTF8": "1"}
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, encoding="utf-8", errors="replace", cwd=str(MCP_VET_DIR),
                          env=env)
    try:
        out, err = p.communicate(timeout=GRADE_TIMEOUT)
    except subprocess.TimeoutExpired:
        _kill_tree(p.pid)
        try:
            p.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        return "timeout", None, "grade-target exceeded %ds" % GRADE_TIMEOUT
    try:
        parsed = json.loads(out)
    except json.JSONDecodeError:
        return "unparsed", None, (err or out or "empty stdout")[:500]
    return "graded", parsed, None


def grade_row(name: str, url: str, subfolder: str | None, work: Path) -> dict:
    out = {"name": name, "repo_url": url, "subfolder": subfolder}
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:80]
    dest = work / safe
    t0 = time.time()
    state, reason = clone(url, dest)
    if state != "ok":
        out.update(outcome=state.upper() if state == "timeout" else "UNFETCHABLE",
                    reason=reason, verdict=None, findings=[], seconds=round(time.time() - t0, 1))
        return out
    root = dest / subfolder.strip("/") if subfolder and (dest / subfolder.strip("/")).exists() else dest
    gstate, parsed, err = grade_target_cli(root)
    shutil.rmtree(dest, ignore_errors=True)
    out["seconds"] = round(time.time() - t0, 1)
    if gstate == "timeout":
        out.update(outcome="TIMEOUT", reason=err, verdict=None, findings=[])
        return out
    if gstate == "unparsed":
        out.update(outcome="UNPARSED", reason=err, verdict=None, findings=[])
        return out
    out.update(outcome="GRADED", verdict=parsed["verdict"],
                findings=[{"check": f["check"], "severity": f["severity"]} for f in parsed["findings"]],
                files_scanned=len(parsed["files_scanned"]), checks_run=parsed["checks_run"],
                no_gradeable_files=(len(parsed["files_scanned"]) == 0))
    return out


def grade_ours() -> list[dict]:
    rows = []
    for name, relpath in OURS.items():
        abspath = (MCP_VET_DIR.parent.parent / relpath) if not relpath.is_absolute() else relpath
        # relpath is already "projects/arcaeon_mcp" relative to repo root; MCP_VET_DIR is
        # projects/mcp_vet, so repo root is MCP_VET_DIR.parent.parent
        t0 = time.time()
        gstate, parsed, err = grade_target_cli(abspath)
        row = {"name": "ours:" + name, "repo_url": str(relpath), "ours": True,
               "seconds": round(time.time() - t0, 1)}
        if gstate == "timeout":
            row.update(outcome="TIMEOUT", reason=err, verdict=None, findings=[])
        elif gstate == "unparsed":
            row.update(outcome="UNPARSED", reason=err, verdict=None, findings=[])
        else:
            row.update(outcome="GRADED", verdict=parsed["verdict"],
                       findings=[{"check": f["check"], "severity": f["severity"]} for f in parsed["findings"]],
                       files_scanned=len(parsed["files_scanned"]), checks_run=parsed["checks_run"],
                       no_gradeable_files=(len(parsed["files_scanned"]) == 0))
        rows.append(row)
    return rows


def load_results(path: Path) -> dict:
    done = {}
    if not path.exists():
        return done
    for l in path.read_text(encoding="utf-8").splitlines():
        if l.strip():
            d = json.loads(l)
            done[d["name"]] = d
    return done


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", required=True)
    ap.add_argument("--n", type=int, default=SAMPLE_N)
    ap.add_argument("--ours-only", action="store_true")
    a = ap.parse_args()

    RES_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RES_DIR / "sample200_2026-09-05_rows.jsonl"
    done = load_results(out_path)

    rows, summary = load_snapshot(a.snapshot)
    pop = population(rows)
    picked, frame_n = sample200(pop, a.n)

    all_results = []
    with out_path.open("a", encoding="utf-8") as fh:
        for r in grade_ours():
            if r["name"] in done:
                all_results.append(done[r["name"]]); continue
            fh.write(json.dumps(r, sort_keys=True) + "\n"); fh.flush()
            all_results.append(r)
            print("OURS  %-30s %s" % (r["name"], r["outcome"]), file=sys.stderr)

        if not a.ours_only:
            work = Path(tempfile.mkdtemp(prefix="mcpbench200_"))
            try:
                for i, r in enumerate(picked, 1):
                    if r["name"] in done:
                        all_results.append(done[r["name"]]); continue
                    row = grade_row(r["name"], r["repo_url"], r.get("repo_subfolder"), work)
                    fh.write(json.dumps(row, sort_keys=True) + "\n"); fh.flush()
                    all_results.append(row)
                    print("%d/%d %-12s %-50s %5.1fs" %
                          (i, len(picked), row["outcome"], r["name"][:50], row["seconds"]),
                          file=sys.stderr)
            finally:
                shutil.rmtree(work, ignore_errors=True)

    summ = {
        "snapshot": a.snapshot, "snapshot_sha256": summary["sha256"],
        "seed": SEED, "sample_n": len(picked), "frame_gradable_repo": frame_n,
        "servers_distinct_active": len(pop),
        "outcomes": {},
    }
    from collections import Counter
    theirs = [d for d in all_results if not d.get("ours")]
    summ["outcomes"] = dict(Counter(d["outcome"] for d in theirs))
    (RES_DIR / "sample200_2026-09-05_summary.json").write_text(
        json.dumps(summ, indent=2), encoding="utf-8")
    print(json.dumps(summ, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
