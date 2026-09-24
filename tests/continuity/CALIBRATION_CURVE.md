# arcaeon-continuity calibration curve

Package version: **0.2.0**  
Fixture-set digest: `sha256:json-c14n:v1:8cfaa2e1cd170a67f7445406e5bd7775d200aa38479522b97fa8662e6463cb32`  
Generated: 2026-08-17T22:17:51Z  
Fixtures: 54 across 6 graded difficulty families. Regenerate with `python -m arcaeon_continuity.calibration`.

Agreement = fraction of the family whose observed verdict matched the fixture's expected verdict for that mode. Strict faithful-rate = fraction strict mode called faithful. Loose containment-only rate = fraction loose mode tagged `containment_only` (the visible slope — 0.2.0: loose mode mints no `faithful` boolean; the bare value is unobtainable and consumers read `comparison`). D5 (and the D4 paraphrases) encode ground truth, so loose-mode disagreement there IS the measured containment weakness — published, not fixed by weakening fixtures.

| grade | n | strict agreement | strict faithful-rate | loose agreement | loose containment-only rate | loose disagreements |
|---|---|---|---|---|---|---|
| D0 | 5 | 1.00 | 1.00 | 1.00 | 1.00 | — |
| D1 | 10 | 1.00 | 1.00 | 1.00 | 1.00 | — |
| D2 | 10 | 1.00 | 0.00 | 1.00 | 1.00 | — |
| D3 | 8 | 1.00 | 0.00 | 1.00 | 1.00 | — |
| D4 | 8 | 1.00 | 0.00 | 1.00 | 0.62 | — |
| D5 | 13 | 1.00 | 0.00 | 0.46 | 0.54 | d5-01, d5-02, d5-03, d5-04, d5-11, d5-12, d5-13 |

Family definitions:

- **D0** — byte-exact restatement
- **D1** — whitespace edges (the trim the strict layer allows)
- **D2** — case/punctuation/internal-whitespace drift on load-bearing values
- **D3** — verbose-but-faithful: declared value embedded in a longer honest answer
- **D4** — echo-then-repudiate (the Repudiation Case) + near-miss paraphrase
- **D5** — adversarial containment exploits (expectations are GROUND TRUTH; loose-mode agreement here is a measurement, not a target)
