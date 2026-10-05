# Slicing stack-2026-10-05f into PRs (read order for Daniel)

Stack: `stack-2026-10-05f` at `fe38ad9`. Base: `main` at `a46c7f1` (the merge base, so main is fully inside the stack).
Written 2026-10-05, Batch 200 item L1-07.

## Why slices

Going from main to 05f is 102 first-parent steps (202 commits counting merged branches): 251 files, +51792 / -110 lines. Nobody can read that as one PR, and if one part is wrong the whole thing is stuck. So here it is cut into 10 PRs. Each PR is one area of the work. Each one sits on top of the one before it (PR 2's base is PR 1's branch, and so on), so you open and merge them in order. When all 10 are in, main has exactly the tree of `fe38ad9`. That was checked by building it, see "Feasibility" below.

### The order is "what everything else needs" first, not "least risky" first

The brief asked for least risk first: docs and tests, then adapters, then register/tally, then gateways and default-on, then release machinery. I built that order for real and it does not work. 54 of the 102 steps hit conflicts. The adapters, the register and the docs all build on the envelope and gate code (the stack-2026-10-04 core), and almost every step adds a line to CHANGELOG.md and MIGRATION.md, so steps taken out of order trip over each other.

So the order below keeps the dependencies in place and puts risk last wherever it can:

- The core has to go first. Nothing else builds without it.
- Adapters come before register/tally. Gateways and default-on come after register.
- The release workflow (the only part that can publish anything) comes last.
- Smaller orders I also tried and dropped:
  - Moving the B50c fold ahead of the protocol-reach PR gave 17 conflicts.
  - Moving the check-in and release work to the very end conflicts in `src/arcaeon/mcp/server.py`, because the reconcile tools are written on top of the check-in change.

## How each PR branch is built

Slice N's branch = slice N-1's branch plus the listed stack steps, in the listed order. Plain commits are cherry-picked as they are. The stack's merge commits are cherry-picked with `-m 1`, which brings in the whole merged branch as one step. Short SHAs below are the stack's own. The branch names in brackets are where the work started (from `bridge/state/batch200_state.json`).

How test counts were taken: each slice's command was run twice.
- On `fe38ad9`, using the repo's root `conftest.py` harness (src/ first on sys.path, plus a temp HOME and ARCAEON_HOME for every test). That is the "expected" number.
- On the slice's own tip in the scratch build. That proves the slice passes without anything that comes after it.

Every run exited 0, with 0 failed.

---

## PR 1. Core: envelope, gate, dispute packet, exchange log, tally

- Contains (12 steps): 313603f (PR #2 bearer-class merge), 46be6e3, fcb2856 (envelope), 3f88dde, d60a9b4, a980fa3 (gate, dispute packet, gate.evidence row), 5836f25 (exchange log), 228a4a2, 9e1b744 (tally, tally chain), 204acea, d979527 (deal needs ledger, checker veto), 1e3c609 (account id as counterparty). This is stack-2026-10-04's own work (D050-D071). There are no Batch 200 items in it.
- Touches: 30 files (src 10, tests 11, docs 6, CHANGELOG, MIGRATION, pyproject.toml). +9267 / -61.
- What it does: adds the signed envelope that any agent can check before acting, and the gate that says allow or refuse from that check. It also adds the exchange log and the tally, which records who said what about whom as plain facts with no score.
- What could break: this is the base for everything after it. A wrong rule in the gate would refuse a good action or allow a bad one, all the way up the stack. It does not change any existing verb's behaviour on main, though. It only adds new verbs (`envelope`, `gate`, `exchange`, `tally`).
- Test: `py -m pytest tests/evidence/test_pack_bearer.py tests/evidence/test_pack_readme.py tests/test_cli.py tests/test_dispute_packet.py tests/test_envelope.py tests/test_exchange_log.py tests/test_gate.py tests/test_gate_checker_broken.py tests/test_gate_evidence_row.py tests/test_tally.py tests/test_tally_chain.py -q`
  - On fe38ad9: **570 passed, 2 skipped**.
  - On the slice's own tip: 508 passed, 2 skipped. The same files have fewer tests at this point; later slices add tests to them.
- Receipts: none in the Batch 200 state (this work predates it).

## PR 2. Protocol reach and the outside red-team fixes (A2A, x402, MCP scan, non-party rule)

- Contains (24 steps):
  - Merges: 919c931 (D062 A2A), 7efce9e (D068 x402 + escrow HOLD), a4b38cb (D069 connector + D060 mcp-scan), 388f249 (D061 non-party check).
  - Then 20 follow-up commits from e5d5243 to ad98ba5: the F1-F12 review fixes and the outside red team round 3 (R3-1..R3-3). Examples: pay/act need `--deal` and `--purpose`, the did:key length guard, and a fork in the tally chain counts as BROKEN.
- Touches: 41 files (src 12, tests 19, docs 8, CHANGELOG, MIGRATION). +7168 / -168.
- What it does: lets the gate take part in A2A messages, x402 payments and MCP tool scans, and adds the rule that a check from someone outside the deal cannot release money. It also closes every hole the outside reviewers found.
- What could break: this changes what `gate` demands. pay, act and irreversible now refuse without `--deal` and `--purpose`, so a script written against PR 1 alone would start getting refusals. That is on purpose: these fail closed on money.
- Test: `py -m pytest tests/test_a2a_receiver.py tests/test_connector_adapter.py tests/test_connector_base.py tests/test_dispute_packet.py tests/test_docs.py tests/test_envelope_didkey_length.py tests/test_exchange_log.py tests/test_exchange_log_didkey_length.py tests/test_gate.py tests/test_gate_checker_broken.py tests/test_gate_evidence_row.py tests/test_gate_nonparty.py tests/test_mcp_scan.py tests/test_tally.py tests/test_tally_chain.py tests/test_tally_didkey_length.py tests/test_x402_ext.py -q`
  - On fe38ad9: **784 passed, 5 skipped**.
  - On the slice's own tip: 768 passed, 5 skipped.
- Receipts: none in the Batch 200 state.

## PR 3. The B50c fold: 18 small fixes and their docs (L1-01, L1-02)

- Contains (19 steps): 48c7fd8 to 5dd8314, the `fold b50c-a01..a18` commits, plus df3f24f (a test docstring names no private repo).
- Touches: 59 files (src 14, tests 26, docs 12, conftest.py, policies, examples, MANIFEST.in, README, CHANGELOG, MIGRATION). +5383 / -134.
- What it does: a batch of small, separately reviewed fixes. Examples: the receipt digest check, the tally pairing fixes, policies shipped inside the sdist, the OPA decision log, the tally HTML page, and the escrow timer. It also adds the temp-HOME test harness every later slice's tests rely on.
- What could break: `conftest.py` now moves HOME into a temp folder for every test. A test that quietly read the real home folder would now fail, which is the point. Packaging also changes (MANIFEST.in, policies in the sdist).
- Test: `py -m pytest tests/baseline/test_sdist_hygiene.py tests/receipt/tests/test_aer1_false_mismatch.py tests/test_a2a_receiver.py tests/test_cli.py tests/test_connector_opa.py tests/test_envelope.py tests/test_envelope_pins.py tests/test_escrow.py tests/test_escrow_demo.py tests/test_exchange_log_owner_refusal.py tests/test_gate.py tests/test_opa_gate.py tests/test_policies_in_sdist.py tests/test_tally.py tests/test_tally_chain.py tests/test_tally_chain_vs_verify_pins.py tests/test_tally_html.py tests/test_temp_home.py tests/test_x402_ext.py -q`
  - On fe38ad9: **656 passed, 3 skipped, 1 xfailed**.
  - On the slice's own tip: 642 passed, 3 skipped, 1 xfailed.
- Receipts: L1-01 R1395, L1-02 R1401.

## PR 4. Connector adapters (L2)

- Contains (25 steps):
  - Adapter branches: b200-l202-snyk-agent-scan (29de144), l203-lakera-guard (cc64ea8), l204-prisma-airs (866a3f9), l201-opa-bundle-signing (2cad9e7), l201b-signed-by-vendor-plain (b4990a0), l205-kyverno (5217516), l206-cedar (75d3504), l206b-cedar-deny-broken (5fe64ef), l207-reported-by-sender (98cbbaa), l208-hiddenlayer (98db0e7), l209-sentinelone (6a794fe), l211-e2b-run-receipt (ff636e9), l2conf-adapter-conformance (e1d6033), l210-ocsf13-compat (25499aa), l212-checks-end-to-end (87e3722), l212b-predicate-v2 (5e9f93f), l1xx-pip-cache-tmp (5d05c40).
  - Fold touch-ups: dfdeae2, cf2c78d, ca9aea7, 280c675.
  - Review fixes: t4a-ocsf-refuse (fd09d2e), t4d-envelope-broken-rows (63615d5), t4c-connector-rollups (09ed75c).
  - b200-l213-datadog-llmobs (4e10df7).
- Touches: 110 files (tests 87, most of them vendor fixture files; src 16, docs 5, CHANGELOG, MIGRATION). +14671 / -53.
- What it does: teaches arcaeon to read the verdicts that outside tools already produce. Those tools are Snyk, Lakera, Prisma AIRS, OPA bundles, Kyverno, Cedar, HiddenLayer, SentinelOne, E2B, OCSF and Datadog LLM Obs. Each verdict becomes a check the gate can use, and one conformance table holds every adapter to the same rules.
- What could break: an adapter that misreads a vendor's output could turn a "blocked" into a pass. The conformance test and the "BROKEN on deny" fixes are there to catch exactly that. Nothing here changes what the gate does when no adapter is used.
- Test: `py -m pytest tests/baseline/test_sdist_hygiene.py tests/test_connector_cedar.py tests/test_connector_checks_end_to_end.py tests/test_connector_conformance.py tests/test_connector_e2b.py tests/test_connector_hiddenlayer.py tests/test_connector_kyverno.py tests/test_connector_lakera_guard.py tests/test_connector_opa.py tests/test_connector_opa_bundle.py tests/test_connector_prisma_airs.py tests/test_connector_reported.py tests/test_connector_sentinelone.py tests/test_connector_snyk_agent_scan.py tests/test_datadog_llmobs.py tests/test_envelope_checks.py tests/test_envelope_predicate_version.py tests/test_mcp_scan.py tests/test_ocsf.py tests/test_ocsf_refusal.py -q`
  - On fe38ad9: **1715 passed, 6 skipped**.
  - On the slice's own tip: 1693 passed, 6 skipped.
- Receipts:
  - L2-02 R1392, L2-03 R1394, L2-04 R1396, L2-01 R1397, L2-05 R1398, L2-06 R1399, L2-07 R1400, L2-01b R1402, L2-06b R1404, L2-09 R1405, L2-08 R1406, FOLD-05b R1407, L2-11 R1408, L2-10 R1409, L2-12 R1410, L2-CONF R1411, L2-12b R1412, L1-xx-cache R1413.
  - F-R1, F-R5..F-R9: no receipt in state.
  - L2-13 and L2-xx-e2b-empty: tag **parity**.

## PR 5. Account ids and pairing (L3 register, part 1)

- Contains (9 steps): b200-l301-account-id (efd37a9), l302-binding-vs-account (c4ed242), b1d357b (05b changelog), l302b-dropped-pairing-reason (3d9fc07), a70098b (05c changelog), t4b2-account-server (752c5f4), t4b1-pairing (a81ffe2), f1b3292 (the "as of" line), b2311cf (05d changelog).
- Touches: 14 files (src 3, tests 5, docs 4, CHANGELOG, MIGRATION). +2953 / -29.
- What it does: gives an agent an arcaeon.io account id that its keys bind to through a signed row, and makes the tally pair two sides by that account. It also says plainly when a pairing was dropped and why.
- What could break: two records that used to pair by key alone may now pair, or stop pairing, through the account binding. The tally text also gains an "as of" line, which anything reading the text output would see.
- Test: `py -m pytest tests/test_account_id.py tests/test_account_id_public_view.py tests/test_account_id_server_rules.py tests/test_account_service_freshness.py tests/test_account_service_pairing.py -q`
  - On fe38ad9: **97 passed**.
  - On the slice's own tip: 97 passed.
- Receipts: L3-01 R1393, L3-02 R1403, L3-02b R1414, FOLD-05c R1415, FOLD-05d R1421, F-R2/F-R3/F-R4/F-R10/F-R11/F-R12 (no receipt in state).

## PR 6. Version check-in, reconcile, revocation, Rekor plan, tick-6 fixes

- Contains (6 steps): b200-l1-checkin (3cca4c8), l3-recon (7f89eb0), l5-rekor-plan (7cb6769), l303-register-revocation (6664a8f), d964ec4 (05e changelog), t6b-fixes (562621f).
- Touches: 44 files (src 10, tests 22, docs 6, tools 2, conftest.py, README, CHANGELOG, MIGRATION). +5617 / -50.
- What it does:
  - Adds a once-a-day signed version check-in (a signed `latest.json`, Ed25519, plus the tool that writes it) and the reconcile tools that show where two sides disagree.
  - Adds register revocation, and the plan for anchoring to Rekor (the witness lane). The Rekor part is a written plan plus an offline skeleton that is switched off (`ARMED = False`); it sends nothing.
- What could break:
  - The check-in is the first code that reads a signed answer from arcaeon.io. A mistake in how its signature is checked would show up here; verify never fetches. `src/arcaeon/mcp/server.py` also gains new tools.
  - The 05e CHANGELOG lines already mention the release workflow, which only lands in PR 10. That is just text in the changelog. If it reads oddly, merge PR 10 right after.
- Test: `py -m pytest tests/connector/test_connector.py tests/connector/test_connector_call_record.py tests/connector/test_exchange_pair_tool.py tests/connector/test_second_read_tools.py tests/heavy/test_kh3_pack_stranger.py tests/heavy/test_kh8_mcp_http.py tests/test_checkin.py tests/test_checkin_ed25519_rfc8032.py tests/test_datadog_llmobs.py tests/test_exchange_disagreement.py tests/test_make_latest_json.py tests/test_register_revocation.py tests/test_rekor_anchor.py tests/test_release_check.py tests/test_temp_home.py -q`
  - On fe38ad9: **444 passed, 2 skipped**.
  - On the slice's own tip: 444 passed, 2 skipped.
- Receipts:
  - L1-CHECKIN and L6-CHECKIN: his-#6.
  - L3-RECON: **unique-lane**, his-#3.
  - L5-REKOR: his-#5.
  - L3-03: **parity**.
  - FOLD-05e: R1430.
  - CHECKIN-ED25519: his-#6.
  - DATADOG-CNL: **parity**.
  - HARNESS-USERSITE: no tag.

## PR 7. Default-on gate (L4-01 / L8)

- Contains (1 step): b200-t6a-default-on (85be0e1).
- Touches: 13 files (src 3, tests 6, docs 2, CHANGELOG, MIGRATION). +1231 / -24.
- What it does: on the receiving side, the gate now defaults to `block`. act, pay and irreversible are refused unless the check reads VERIFIED, and a missing envelope counts as a refusal too. `--enforce warn`, `ARCAEON_GATE_MODE`, or a signed `block_after` from the check-in can soften that to warn-only. Warn mode lets the action through but says it "would refuse".
- What could break: this is the first slice that changes behaviour for someone who did nothing new. A call that used to get through is refused when its check is not VERIFIED, and with no signed answer cached it fails closed to block. Read the MIGRATION lines before tapping.
- Test: `py -m pytest tests/connector/test_connector.py tests/connector/test_connector_call_record.py tests/connector/test_gate_tools.py tests/connector/test_second_read_tools.py tests/heavy/test_kh8_mcp_http.py tests/test_gate_enforce.py -q`
  - On fe38ad9: **116 passed, 2 skipped**.
  - On the slice's own tip: 116 passed, 2 skipped.
- Receipts: L4-01, his-#2.

## PR 8. Two-sided exchange and the register page (L3, part 2)

- Contains (3 steps): b200-t6c-exchange (6bf82bd), t6e-register-page (f4ac1b3), 020de32 (MIGRATION spacing).
- Touches: 23 files (src 7, tests 7, docs 5, examples, README, CHANGELOG, MIGRATION). +2060 / -80.
- What it does: either side of an exchange can now withdraw what it said, and a pair can be pinned. The docs explain both sides' view. It also adds the public register page that lists accounts and their records.
- What could break: a withdrawn statement now shows as withdrawn in the tally and on the page. Anything counting statements would see different numbers.
- Test: `py -m pytest tests/connector/test_exchange_pair_tool.py tests/test_cli.py tests/test_docs_two_sided.py tests/test_exchange_disagreement.py tests/test_exchange_pair_pin.py tests/test_exchange_withdraw.py tests/test_register_page.py -q`
  - On fe38ad9: **280 passed, 2 skipped**.
  - On the slice's own tip: 280 passed, 2 skipped.
- Receipts:
  - L3-EX-03 WITHDRAW: **unique-lane**, his-#3.
  - L3-EX-10 PAIR PIN: **unique-lane**, his-#3.
  - L3-EX-11: his-#3.
  - L3-04: **parity**.

## PR 9. Gateways and SCITT-shaped receipts (L4-02, L4-03, L3-05)

- Contains (2 steps): b200-t6d-gateways (066e94b), t6f-scitt (fe38ad9, the stack tip).
- Touches: 17 files (src 8, tests 4, docs 3, CHANGELOG, MIGRATION). +2988 / -20.
- What it does: reads results from the Docker MCP gateway and the Lasso gateway as checks. It also writes receipts in the SCITT shape, with RFC 9162 Merkle proofs, so outside tools can verify them.
- What could break: a gateway's result read wrongly would pass or block the wrong call. A Merkle proof mistake would make good receipts read BROKEN, the safe direction.
- Test: `py -m pytest tests/test_gateway_docker_after.py tests/test_gateway_lasso.py tests/test_merkle_rfc9162.py tests/test_scitt_receipts.py -q`
  - On fe38ad9: **183 passed, 2 skipped**.
  - On the slice's own tip: 183 passed, 2 skipped.
- Receipts: L4-02 and L4-03 his-#2; L3-05 R1440, **parity**; FOLD-05f R1441.

## PR 10. Release machinery (L1-03, L1-04, L1-06)

- Contains (1 step): b200-l103-release-yml (a438745).
- Touches: 7 files (.github 1, tools 2, tests 2, docs 1, MANIFEST.in). +963 / -0.
- What it does: adds `.github/workflows/release.yml`, which builds and uploads releases through PyPI Trusted Publishing. It also adds a tool that checks the published files match what was built.
- What could break: this is the only slice that can publish anything. Merging it does not release. A release only happens when a tag is pushed. Still, the PyPI trusted-publisher setting must match the workflow's name before the first tag.
- Test: `py -m pytest tests/test_release_workflow.py tests/test_verify_published.py -q`
  - On fe38ad9: **40 passed**.
  - On the slice's own tip: 40 passed.
- Receipts: L1-03+L1-04+L1-06, his-#1.

---

## Feasibility check (done mechanically)

How it was run:
- Inside the worktree, a scratch branch was started at `main`.
- The 102 first-parent steps were cherry-picked in the PR 1..10 order above, with `-m 1` for merges.
- The scratch branch was deleted afterwards.

Result:
- **0 conflicts across all 10 slices.**
- `git diff --stat fe38ad9` on the finished scratch branch was **empty**: the final tree is identical to fe38ad9.
- Each slice's tests also pass at its own tip (second count above), so every slice stands alone. None of them depends on a later one.

Orders that were tried and dropped (same method):

| Order | Conflicts | Why it fails |
|---|---|---|
| Strict least-risk-first by lane (docs/tests, adapters, register/tally, gateways/default-on, witness, release core) | 54 of 102 steps | Everything depends on the core. CHANGELOG/MIGRATION lines collide. |
| B50c fold before protocol reach | 17 | The fold fixes code that PR 2 adds. |
| Check-in and release both last | conflict in `src/arcaeon/mcp/server.py`, plus CHANGELOG/MIGRATION | Reconcile is written on top of check-in. The tick-5 and tick-6 changelog lines sit in history order. |
| Default-on and gateways together, before PR 8 | CHANGELOG/MIGRATION | The changelog lines are stacked in history order. |

Things to know:
- PR 1 is the biggest risk and has to go first. There is no way round that short of rewriting history.
- PR 4 is the biggest by file count (110), but 87 of those are test files and vendor fixtures.
- PR 6 mixes lanes (L1 check-in, L3 reconcile, L5 Rekor) because reconcile cannot apply without check-in.
- PR 9 pairs L4 gateways with L3 SCITT for the same changelog reason.

## Tick-7 work not yet in 05f

- These sit on fe38ad9 and are not in any slice above:
  - `b200-t7a-account-e2e` (87568f3; L3-06, L3-07, **unique-lane**): 2 commits, 11 files.
  - `b200-t7b-gateway-shapes` (e2600c5; L4-04, L4-05, **parity**): 2 commits, 11 files.
- `git merge-tree` shows t7a and t7b merge with each other cleanly.
- Once folded they become PR 11 (t7a) and PR 12 (t7b), stacked on PR 10.
- `b200-t7c-vendor-samples` has no commits past fe38ad9 yet.
- L5-02 (t7d btc headers) and L6-01 (t7e how-it-works) are listed in state, but those branches are not in this repo.

## His taps (in order)

1. Core: envelope, gate, dispute packet, exchange log, tally
2. Protocol reach: A2A, x402, MCP scan, non-party rule, red-team fixes
3. B50c fold: 18 small fixes, temp-HOME test harness
4. Connector adapters: Snyk, Lakera, Prisma, OPA, Kyverno, Cedar, HiddenLayer, SentinelOne, E2B, OCSF, Datadog
5. Account ids and pairing through a signed binding
6. Version check-in, reconcile, register revocation, Rekor plan
7. Default-on gate: receiver blocks unless VERIFIED (warn mode by flag, env, or signed check-in)
8. Two-sided exchange (withdraw, pair pin) and the register page
9. Docker and Lasso gateways, SCITT-shaped receipts
10. Release workflow (PyPI Trusted Publishing)
