# Reproducing the registry benchmark table

Everything below runs from the repository root (`projects/mcp_vet` is the
package; commands are written for a checkout where it sits at
`projects/mcp_vet`). Windows `py`; on other platforms substitute `python3`.

The chain is: snapshot file -> its sha256 -> a seeded sample of names ->
one row per name in a results file -> a summary JSON -> a markdown table.
Each link is checkable on its own.

## 0. Install the tool at the version that graded

    py -m pip install "arcaeon-mcp-vet[ts]==0.0.16"

`[ts]` pulls tree-sitter; without it every TypeScript file grades
"unparseable, 0 checks ran" and the table changes. The summary records
`mcp_vet_version`; use that one.

## 1. Get the snapshot and check its hash

The 2026-09-02 snapshot is `bench/snapshots/registry_2026-09-02T2142Z.jsonl`
(about 36 MB, published beside the report, not committed). Its sha256 must be

    4990529da87c02f3f783b84bbead3ab15d43ddb642d1311989776c34a648dbe2

    py -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" projects/mcp_vet/bench/snapshots/registry_2026-09-02T2142Z.jsonl

If the hash differs you have a different population and none of the numbers
below apply. The committed `registry_2026-09-02T2142Z.summary.json` carries
the same hash.

To take a NEW snapshot instead (a different population, a different table):

    py projects/mcp_vet/bench/registry_scrape.py

## 2. Check the sample is the one the plan describes

The sample is `random.Random(int(sha256[:8], 16)).sample(frame, 100)` over
the `gradable:repo` rows of the population (latest, active, one per name),
in snapshot order. No stratification. This prints the 100 names in order:

    py - <<'EOF'
    import sys; sys.path.insert(0, "projects/mcp_vet/bench")
    import grade_sample as gs
    rows, snap = gs.load_snapshot("registry_2026-09-02T2142Z.jsonl")
    pop = gs.population(rows)
    print(gs.bucket_counts(pop))                      # every server in one bucket
    picked, frame_n = gs.sample(pop, snap["sha256"], 100)
    print(frame_n); print("\n".join(r["name"] for r in picked))
    EOF

The names must match, in order, the non-`ours:` rows of
`bench/results/2026-09-02T2142Z_sample.jsonl`. `test_bench.py::
test_same_snapshot_same_sample_order_twice` asserts the seed is
deterministic on a synthetic snapshot.

## 3. Grade (the slow step; clones 100 repositories)

    py projects/mcp_vet/bench/grade_sample.py --snapshot registry_2026-09-02T2142Z.jsonl

Writes `bench/results/2026-09-02T2142Z_sample.jsonl` and
`..._summary.json`. Resumable: a name already in the results file is not
re-cloned. Append-only: a re-run that produces a DIFFERENT row for a name
already on disk raises `ResultConflict` instead of overwriting; delete or
rename the results file deliberately if a regrade is intended.

Repositories move. A repo that was public on 2026-09-02 and is private
today comes back `clone-failed`, which changes the outcome counts but not
any graded row. That is why the results file is the record and the clone
is not.

Our own five are graded first from local checkouts (`OURS` in
`grade_sample.py`); a stranger without those paths gets `clone-failed:
path missing` for them, which is honest and does not touch the sample.

## 4. Validate the summary against the schema

    py projects/mcp_vet/bench/summary_schema.py --validate projects/mcp_vet/bench/results/2026-09-02T2142Z_summary.json

Refuses a summary missing any of `summary_schema.REQUIRED_KEYS` (snapshot
sha, seed expression, tool version, plan path, buckets, gate histogram,
exclusions, battery digest, the no-handler split).

## 5. Render the table

    py projects/mcp_vet/bench/render_report.py projects/mcp_vet/bench/results/2026-09-02T2142Z_summary.json --out projects/mcp_vet/bench/results/2026-09-02T2142Z_report.md

Read-only over the summary. `test_bench.py::
test_rendered_report_on_disk_matches_the_summary` asserts the committed
report is exactly this function of the committed summary.

## 6. Run the tests

    py -m pytest projects/mcp_vet -q

## What was done to the 2026-09-02 files after the run

The summary was written before the schema existed. On 2026-09-02 it was
brought to schema 1 by `summary_schema.py --backfill`, which ADDS keys and
refuses to change any existing one (asserted in code and in
`test_backfill_adds_keys_only_and_never_changes_a_number`). The original
file is a byte prefix of the backfilled one. `battery_digest` on that summary
is `unrecorded:run-predates-schema-1` because the exact check-battery bytes
at 21:42Z were not recorded; the digest of the tree at backfill time sits
beside it, labelled, and is not the tree that graded.
