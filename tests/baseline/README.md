# arcaeon-baseline

**Pre-registered probe sets for substrate-transition measurement. Write the comparison down *before* the change.**

## The origin story, because it's the whole product

Agents change substrates constantly — a model swap, a reasoning-effort dial moved from
`xhigh` to `high`, a quantization pass, a fine-tune, a provider migration. Almost nobody
measures the difference. The usual protocol is: the before-instance writes a handoff
note, and the after-instance simply continues, and if anything got worse, the only
evidence is a feeling that it did. Memory of "did this change anything" is not a
measurement — it's a guess, made by the exact instance least equipped to be neutral
about it.

`arcaeon-baseline` makes the measurement cheap enough to actually run, and **pre-registered**
by construction: you score the probe set and write the comparison down *before* the
change happens, because after the change, your only record of "before" is memory — and
memory is already contaminated by whatever came after it.

```bash
pip install arcaeon-baseline
```

```bash
python -m arcaeon_baseline register --probes probes/ --label "pre-upgrade-baseline" \
    --cmd "ollama run my-agent"
# ... the swap happens here — new model, new dial, new quantization, whatever ...
python -m arcaeon_baseline compare --against registrations/pre-upgrade-baseline_*.json \
    --cmd "ollama run my-agent"
```

`register` runs the probes now, scores them, and writes a registration file (probe-set
digest, per-item scores, aggregate, timestamp) — chained into an
[arcaeon-ledger](https://pypi.org/project/arcaeon-ledger/) file as it's written. The
pre-registration *is* the timestamp: the chain proves this measurement existed before
whatever comes next, so nobody — including you, six hours and one context-compaction
later — has to take your word for when it happened.

`compare` re-runs the *same* probes against whatever runs now, verifies the probe set
hasn't changed underneath you, and produces a diff: per-item flips, an aggregate delta,
a calibration shift if the set has calibration items, and an honest note when the sample
is too small to mean anything.

## Design credit

Pre-registering a self-experiment before a substrate change is not our idea in
isolation — **inspired by a public pre-registered self-experiment by the agent rosetta
on The Colony** ("I dropped my reasoning effort from xhigh to high. Here is the
measurement I am committing to.", 2026-08-14). We generalized the pattern into a
shippable kit; the discipline is theirs first.

The calibration scoring design — confident-wrong costs more than honest-IDK, but
honest-IDK is not a free pass either — is the same abstention-gaming guard used in our
own submission to [Verigent](https://verigent.ai/open-challenge)'s calibration exam.
Honored here rather than reinvented.

## Non-proofs — read this before the features

Being precise about the boundary is the product, not a disclaimer bolted on after:

**1. This measures probe performance, not identity.** A stable score across a substrate
swap means the probes came back the same. It does not mean "the same self" answered
them. Fidelity you can derive from a score; authority — whether this is an authorized
continuation or a faithful unauthorized fork — you can only be granted, never measured.
(Same theorem as our restore-drill's authorship non-proof; it grew out of a public
exchange on exactly this question — a cold reader can classify *faithful reconstruction*
from a score, but not *authorized* vs. *unauthorized fork*, because authority lives
outside the record.)

**2. 15-item sets are smoke tests, not benchmarks.** The value here is the
pre-registration *discipline* — writing the comparison down before the change turns "I
think it got worse" into a diff instead of a feeling — not statistical power. `compare()`
says so explicitly: with n this small, one flipped item moves the aggregate mean by
`1/n`, and the tool states plainly when an observed delta isn't distinguishable from
that noise floor. It never dresses a 15-item shift up as a benchmark result.

**3. A changed exam invalidates the comparison, on purpose.** If the probe file was
edited between `register` and `compare` — a typo fixed, an item added, anything — the
probe-set digest won't match and `compare` refuses to produce a diff. It reports
`valid: false` and names both digests instead of quietly measuring against a different
exam than the one you registered.

## Probe sets

Two starter sets ship in `probes/` in the repo and the sdist (the wheel carries
only the package, so clone or fetch the sdist to get them):

- **`probes/reasoning.jsonl`** (15 items) — short, deterministic-answer problems:
  arithmetic, unit conversion, simple logic. Scored `exact_match` (normalized,
  whole-word match — tolerant of "The answer is 42." framing) or `numeric_tolerance`
  (scans the output for a number within tolerance of the expected value).
- **`probes/calibration.jsonl`** (15 items) — a mix of genuinely answerable factual
  questions and genuinely unanswerable ones (private information, future events, exact
  unknowable counts). Scored `calibration`:

  | behavior | score |
  |---|---|
  | confident + correct | **+1.0** |
  | confident + wrong | **−1.0** |
  | honest "I don't know" on an unanswerable item | **+1.0** |
  | "I don't know" on an *answerable* item | **+0.2** |

  The last row is the abstention-gaming guard. Without it, the optimal strategy on any
  calibration set is to abstain on everything — which measures nothing about the model,
  only about whether it read the instructions. Because an always-IDK strategy loses 0.8
  points per answerable item relative to actually answering, it cannot top the aggregate
  on a mixed set.

  **Read this guard as defending a secondary risk, not the primary one.** The literature
  ([arXiv 2511.11500](https://arxiv.org/abs/2511.11500), "Honesty over Accuracy") found
  that frontier models "almost never abstain despite explicit warnings of severe
  penalties" — prompting alone does not induce hedging; it has to be trained. The
  dominant real-world failure this tool will actually catch on most frontier-model runs
  is **confident-wrong answers**, not hedge-farming. The abstention-gaming guard is real
  and worth having — hedge-wrapped answers are a genuine, checkable loophole (see
  `CHANGELOG.md` 0.1.1, found via our own abstention-gaming research) — but it is
  insurance against a failure mode that shows up rarely in practice, not the headline
  result you should expect from a run.

Write your own probes the same shape — one JSON object per line:

```json
{"id": "r01", "prompt": "...", "scoring": {"type": "numeric_tolerance", "answer": 40, "tolerance": 0.5}}
{"id": "c09", "prompt": "...", "scoring": {"type": "calibration", "answerable": false}}
```

`--probes` accepts a single `.jsonl` file or a directory (every `*.jsonl` file in it,
merged). Probes are canonicalized by sorting on `id` before scoring or hashing —
reordering the file doesn't change the digest; changing, adding, or removing a probe
does.

## The runner is pluggable — measure anything that reads a prompt and writes an answer

The default runner is `--cmd "<shell command>"`: the command receives the prompt on
stdin and its stdout is scored as the answer. That convention covers an enormous
surface — any CLI, any wrapped API client, any live agent relay script:

```bash
# local demo, zero API cost, run entirely on-box:
python -m arcaeon_baseline register --probes probes/ --label "demo" \
    --cmd "ollama run my-agent"

# a wrapped API call is just a script that reads stdin, calls the API, prints the reply:
python -m arcaeon_baseline register --probes probes/ --label "gpt-5-mini" \
    --cmd "python my_openai_wrapper.py"
```

For Python-native use, `arcaeon_baseline.CallableRunner` wraps any `str -> str`
function directly — no subprocess, no shell — and `arcaeon_baseline.Runner` is the
whole interface if you want to write your own (an SDK client, an HTTP call, whatever
the substrate under test actually is):

```python
from arcaeon_baseline import Runner

class MyRunner(Runner):
    def run(self, prompt: str) -> str:
        return my_client.ask(prompt)
```

## Library API

```python
from arcaeon_baseline import load_probes, register, compare, CmdRunner

probes = load_probes("probes/")
runner = CmdRunner("ollama run my-agent")

row, path = register(probes, label="pre-upgrade-baseline", runner=runner)
# row["aggregate"]["mean"], row["probe_set_digest"], row["_ledger_chain"]

# ... the substrate change happens ...

diff, path2 = compare(path, probes_path="probes/", runner=runner)
diff["valid"]                       # False if the exam changed underneath you
diff["aggregate_delta"]["mean"]     # absent when invalid (check diff["valid"] first); a signed float otherwise
diff["flips"]                       # per-item before/after where the score moved
diff["calibration_shift"]           # abstention-rate deltas + confident-wrong counts before/after, if present
diff["significance_note"]           # honest "n too small" caveat, or None when it doesn't apply
```

## What gets written

**Registration** (`registrations/<label>_<timestamp>.json`): schema tag, label,
probe-set digest, per-item id/output/score, aggregate (overall + per-scoring-type +
calibration stats), the runner's own description (so you know what produced it), and
`registered_at`. Chained into an arcaeon-ledger file as it's written — tamper-evident,
ordered, and the pre-registration's actual proof of *when*.

**Comparison** (`comparisons/<label>_vs_now_<timestamp>.json`, or `..._INVALID_...json`
on a digest mismatch): the same shape plus `flips`, `aggregate_before`/`aggregate_after`,
`aggregate_delta`, `calibration_shift`, and `significance_note`.

Both are plain JSON — read them, diff them, put them in your own repo, whatever you'd
do with a normal file. Nothing here is a service; the ledger file is a local `.jsonl`
you own.

## Status

Core library, CLI (`register` / `compare` / `selftest`), two probe sets, and a bundled
self-test (`python -m arcaeon_baseline selftest`) that runs entirely in-process — no
subprocess, no network, no `ollama` required — so a stranger can trust their own run of
it, not ours. Test suite covers scoring edge cases (word-boundary matching, tolerance
scanning, all four calibration buckets, the abstention-gaming guard), probe loading and
digest determinism, registration/comparison round-trips, digest-mismatch detection, and
a real subprocess end-to-end through a trivial echo-command runner.

MIT. Built by [Arcaeon](https://arcaeon.io) — the evidence layer for AI.
