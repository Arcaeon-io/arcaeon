# `gradable:package-only`: fetch sdists in v1, or state the exclusion?

Board item M21 (2026-09-02). The 2026-09-02 snapshot has 26,197 active
servers. 20,029 carry a repository URL (the v1 sampling frame). 3,515 carry a
PyPI package and 8,063 an npm package with NO repository URL: 11,578 servers,
44% of the active registry, that a source scanner could grade if it fetched
the published archive instead of cloning a repo.

## What fetching would cost

* No code runs. An sdist or npm tarball is downloaded and unpacked; the grader
  reads files. Same static read as a clone, same blind spots.
* Size: a sample of 100 is a few hundred MB at most; the whole 11,578 is on the
  order of 2 to 3 GB and hours of wall time, mostly network.
* Two new fetchers (PyPI JSON API to find the sdist URL; npm registry to find
  `dist.tarball`), each maybe 40 lines, plus a bucket change in
  `registry_scrape.py` and a second sampling frame in `grade_sample.py`.
* A new failure class: packages with wheels only and no sdist (grade the wheel:
  it is a zip of the same .py files), and npm packages that ship compiled
  `dist/` with no `src/` (then the TS front end sees minified JS and grades
  "unparseable", which is honest but uninformative).

## What it would change about the number

Nothing about the headline, if reported correctly. Package-only servers are a
different population (published artifacts, often older, often unmaintained),
so their gate histogram must be its own table, never averaged into the repo
frame. Merging them would let a reader think "46% of the registry was graded"
when two different samples were graded under two different procedures.

## Decision

**v1 excludes `gradable:package-only` and says so in the same sentence as the
result.** The published report reads: "100 sampled from the 20,029 servers with
a repository URL; the 11,578 package-only servers (44% of active) were not
graded in this pass." The renderer refuses to print a pass rate without that
exclusion list (M26), so the sentence cannot go missing.

**v1.1 (owed, not scheduled):** a second, separately seeded sample of 100 from
`gradable:package-only`, graded from the published archive, reported as its own
table with its own denominator and its own `checks_run` column. Reason to do it
at all: it is the population a stranger actually installs; the repo may be
ahead of or behind the artifact, and the artifact is what runs. Reason to wait:
the repo-frame result is not yet published, and one honest number beats two
half-checked ones.

## What must stay true either way

* Every one of the 26,197 rows sits in exactly one bucket and the buckets sum
  to 26,197 (M22 test).
* No number about the registry appears without its exclusions beside it.
* Nothing about our own five changes: they are graded from working trees or
  from `pip install`, labelled which, outside both denominators.
