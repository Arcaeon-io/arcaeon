# arcaeon-receipt

**One receipt, five buyers.** A hash-chained, witnessed, timestamp-anchored record of what an AI checked, called, was approved to do, watched being typed, or graded, built for the person who has to hand it to a third party: a court, an auditor, a marketplace buyer, an accuser, a hiring center.

```
pip install arcaeon-receipt
```

That installs the library and the `arcaeon-receipt` command. The browser pages (`web/`), the worked examples (`examples/`), the test fixtures (`tests/fixtures/`) and `docs/` are in the source distribution, not the wheel; the paths below are relative to it (`pip download --no-binary :all: --no-deps arcaeon-receipt`, then unpack). The receipt verifier page is also hosted at https://arcaeon.io/verify-receipt (the same page with site navigation added). For `call_proxy --tape`, add the tape writer: `pip install "arcaeon-receipt[tape]"`.

Every receipt carries, on its face, what it proves and what it does not. That block prints before the results, and it is inside the digest: change a limit sentence and the receipt no longer verifies. A receipt that overstates itself is worse than none.

## The five adapters

| adapter | who must produce it, and to whom | proves | does not prove |
|---|---|---|---|
| `cite` Citation Receipt | a lawyer filing under an AI-disclosure order, to the court | each citation was submitted to CourtListener at time T and returned status S | that any case supports the point, is good law, or is quoted right; not Shepard's, not KeyCite |
| `call` Receipted Call | a seller on an agent-payment marketplace (x402 and kin), to the buyer | request digest, response digest, payment-header digest, in sequence, with timing | that the answer was correct, or that the payment settled |
| `call.phone_call_receipt` Receipted Phone Call | a call-taking/dispatch operation, to whoever needs proof a call happened | opaque participant ids, start/end timestamps, derived duration, and a transcript hash occurred together | the truth of anything said, the real identity behind a participant id, or consent |
| `approval` Approval Receipt | a team running agents in production, to a SOC 2 / ISO 42001 auditor | a named principal decided on an action with this digest before it ran, and what ran matched (or did not) | that the principal was human, read it, or was authorized |
| `approval.artifact_approval_receipt` Artifact Approval | anyone who needs proof a named party signed off on one artifact | this approver's credential signed this artifact hash at this time, attested by the approval-text hash | authority to approve, competence to judge, or that the artifact is good |
| `authorship` Authorship Receipt | a writer or student accused by an AI detector, to the accuser | the edit stream (typed / pasted / deleted / idle) was recorded as it happened and the final text was bound | that a human made the keystrokes, or that pasted text was not generated |
| `ballot` Ballot Receipt | a trainee finishing a graded simulation, to a hiring center — issued one at a time, or a whole class at once by the academy whose name is sealed inside the digest (`--issuer` / `--cohort` / `--roster`) | the score and the ballot are unaltered since the timestamp | the score is correct; the sim was not attempted before |

## Ballot Receipt: one trainee, or a whole class

```
arcaeon-receipt ballot run.json --trainee "p. lindqvist" --scenario oral_board.set1 \
    --issuer "Westbrook Regional Training Academy" --cohort WRTA-2026-OB-14

arcaeon-receipt ballot --roster roster.csv --issuer "Westbrook Regional Training Academy" \
    --cohort WRTA-2026-OB-14 --namespace wrta-ob-14 --ledger wrta-ob-14.jsonl --out-dir class/
```

The roster is a CSV with `trainee` and `ballot_path` columns (`scenario`, `grader`, `timestamp` optional, each falling back to the flag). One receipt and one exhibit per row, all into one ledger under one namespace, so the chain itself carries the order the class was issued in. One summary line comes back with the count and the ledger tip. A malformed row refuses the **whole** roster, naming the row number, before anything is minted: a class that comes out silently one receipt short is the failure this driver must not have.

`--issuer` and `--cohort` ride inside the body digest, not in a cosmetic header, so the academy's name cannot be changed without breaking verification. What that buys is unalterability, not authentication: the receipt proves the name has not moved since issue, and says nothing about whether the academy that appears on it is who it claims to be. A branded receipt verifies on the CLI and in `web/verify-receipt.html` with no change to either — `extra` was already one of the seven digested body fields. See `examples/ballots/` for ten plain examples, one branded one, and the example roster.

## MCP servers (stdio, local)

Every wrapper below speaks the same JSON-RPC 2.0 over stdio as `approval_mcp.py`: `initialize`, `tools/list`, `tools/call`; a bad call comes back `isError: true` and the process stays alive. These are local Python tools an MCP host launches over stdio, not deployed functions.

| module | wraps | tool(s) | reaches |
|---|---|---|---|
| `approval_mcp` | `approval.py` | `approval_propose` / `approval_status` / `approval_executed` / `approval_list_pending` | an agent host gating a consequential action on a human decision dropped in a side-channel file |
| `cite_mcp` | `cite.py` / `cite_batch.py` | `cite_check` | a lawyer's own MCP-capable agent, checking citations for existence directly instead of shelling out to the CLI |
| `call_mcp` | `call.py` | `call_receipt` | an agent that just made a paid x402 (or kin) call, issuing its own delivery receipt without a reverse proxy in front of the traffic |
| `authorship_mcp` | `authorship.py` / `authorship_ingest.py` | `authorship_open` / `authorship_event` / `authorship_close` / `authorship_ingest_export` | an editor plugin or CLI wrapper other than the browser recorder, driving or ingesting an authorship session directly |

## Citation Receipt, the first one

```
export COURTLISTENER_TOKEN=...        # free account at courtlistener.com
arcaeon-receipt cite brief.txt --exhibit brief.exhibit.txt
```

Exit 0 when every detected citation was found; exit 3 when any citation came back `not_found` or `invalid_reporter`, so a pre-filing script stops on a flag. The exhibit is plain text a clerk can read; the JSON receipt is what a stranger verifies:

```
arcaeon-receipt verify brief.receipt.json --ledger receipts.log.jsonl --ots
```

Offline demo with a planted fake citation (no token needed):

```
arcaeon-receipt cite tests/fixtures/brief.txt --fixture tests/fixtures/courtlistener_planted_full.json --no-anchor
```

## Verify: one receipt, or a whole class

```
arcaeon-receipt verify class/lindqvist.receipt.json --ledger wrta-ob-14.jsonl --ots

arcaeon-receipt verify --batch class/                 # a directory, a glob, or a list of paths
arcaeon-receipt verify --batch examples/ballots/*.receipt.json --ledger examples/ballots/ledger.jsonl
```

One line per receipt, one summary line, and an exit code a script can gate on:

```
01_oral_board_pass_clean.receipt.json    VERIFIED       ledger=consistent
02_oral_board_fail_partial.receipt.json  VERIFIED       ledger=consistent
...
11 receipts: 11 VERIFIED, 0 BROKEN, 0 COULD NOT LOOK
```

**Three verdicts, never two.** VERIFIED and BROKEN cannot carry a file that will not open, or a receipt whose ledger nobody in this run could find. Folding either into VERIFIED overclaims; folding it into BROKEN accuses a receipt that may be perfectly good. So COULD NOT LOOK is its own count with its own exit code: **0** every receipt VERIFIED, **2** at least one BROKEN, **4** nothing BROKEN but the check COULD NOT LOOK at one or more, **1** the batch itself was refused. A determinable negative still wins — a broken body digest is BROKEN even when the ledger is also missing. (These are the printed words, the same on every Arcaeon surface. The machine values in `roster-report` (CSV and `--json`) and the archive manifest are unchanged: `ok`, `FAIL`, `undetermined`, and the `verified` / `failed` / `undetermined` counts.)

Without `--ledger`, each receipt is checked against the ledger named on its own face if that file sits beside it, which is the shape a bulk export already has. With `--ledger`, one ledger covers the batch. A receipt that claims a ledger row nobody could check comes back COULD NOT LOOK, not VERIFIED.

**The cap is a refusal, not a truncation.** 20 receipts per pass, the number published in `docs/VENDOR_PACKAGE_SPEC.md` next to the words *free to verify*. Past it, nothing is verified and the message names the cap and the count — a partial pass wearing a finished pass's clothes is worse than an error.

`web/verify-receipt.html` does the same thing offline in a browser: drop a whole class on the page (same cap, same refusal, same three verdicts, a row each and a summary). The page has no ledger file, so its verdicts are body-digest verdicts and it says so on its own face.

## Roster report: the page the training manager opens

```
arcaeon-receipt roster-report class/ --out report.csv          # or the class ledger
arcaeon-receipt roster-report class/ledger.jsonl --json --out report.json
```

One row per trainee — receipt id, issuer, cohort, the trainee label the ballot carries, scenario, the score as the receipt states it, issued-at, the verification verdict, ledger status, anchor status when there is one, and the reason behind any verdict that is not `ok`. Header rows carry the issuer, the cohort, when the report was generated, how many receipts it counted, the three verdict counts, and the scope block's own sentences copied verbatim out of the receipts. Exit codes match `verify --batch`: **0** all ok, **2** a definite FAIL, **4** something could not be determined.

**Verdict counts, never score statistics.** No class average, no pass rate, no ranking. The scope block denies exactly one thing — *the score is correct* — and every one of those three asserts its opposite by arithmetic. This report says what was issued and whether it still verifies; grading is untouched by it (`docs/VENDOR_PACKAGE_SPEC.md` §6.1). A FAIL is a row with the same columns as every other row: never dropped, never a footnote, because finding the one document that stopped verifying is the whole reason to run it.

**It pages; it does not truncate.** A class of 25 is verified in two passes of 20 and 5 through the same `verify_batch` the CLI uses, and the header says so on its face: `2 passes of at most 20 (20, 5); every receipt was verified`. The cap's refusal exists so a partial pass is never reported as a finished one, and that failure cannot happen here — every receipt is verified, and no single pass exceeds the published 20.

`--json` emits the same table, same header, same rows, all values strings: the same table for a machine, not a richer one that could disagree with the CSV. `examples/ballots/roster_report_example.csv` is a real report over the committed examples, regenerated by `arcaeon-receipt roster-report examples/ballots/` and held to that command by the test suite.

## Archive: the class in one file, checkable after we are gone

```
arcaeon-receipt archive class/ --out wrta-ob-14.zip          # or the class ledger
```

One portable file a coordinator hands to an auditor, a records department, or a successor:

```
wrta-ob-14.zip
  MANIFEST.json       archive version, generated-at, issuer, cohort, every file's sha256,
                      every receipt's verdict, the verdict counts, the scope block verbatim
  README.txt          how a human with no tools checks it: the free browser verifier, or
                      `pip install arcaeon-receipt`. No account, no contact with us, ever
  roster_report.csv   the coordinator's page, from `roster_report.py` rather than rebuilt
  cohort/             every receipt, every exhibit, the ledger files they name and the
                      witness sidecars beside them, copied byte for byte
```

**It verifies offline.** Extract it anywhere, with the network off, and run `arcaeon-receipt verify --batch cohort/`: every receipt checks against the ledger bundled next to it. That is the export claim — *a form they own and can hand to anybody, including us going away* — and the test suite proves it by doing it, unzipping into a temp directory with the socket layer shut.

`cohort/` is flat because a receipt finds its ledger by looking for that filename beside itself. Sorting receipts and ledgers into separate folders would make every extracted receipt come back COULD NOT LOOK. And the whole ledger file travels, not the rows this class references: a hash chain cannot be subset, and a trimmed ledger would fail its own chain check.

**Nothing is mutated on the way in.** Receipts are copied as bytes, and the digests in the manifest are recomputed *out of the finished archive* and compared against both the manifest and the file still on disk before the command returns. A re-serialized receipt — same values, different key order — verifies fine and is still the wrong artifact to hand somebody.

**A receipt that fails is packed.** With its verdict on the manifest, beside the ones that pass. Exit **0** all VERIFIED, **2** at least one BROKEN inside, **4** nothing BROKEN but something COULD NOT LOOK; the archive is written at all three, because the receipt somebody is looking for is usually the one that stopped verifying. Verdict counts only, same rule as the roster report: nothing in the archive is a statistic about scores.

**Deterministic.** Same cohort, same stamp, identical bytes: fixed entry order, a fixed zip timestamp instead of the wall clock, and one clock reading shared by the manifest and the roster report. Two archives of one class that differ in bytes make a reader ask which is the real one. `examples/class_archive_example.zip` is a real archive over the committed examples, regenerated by `arcaeon-receipt archive examples/ballots/` and held to that command by the test suite.

## What binds a receipt to the world

1. **Body digest**: sha256 over canonical JSON of the body (kind, issued time, subject, checks, scope). Any edit breaks it.
2. **Ledger row**: the digest is appended to an [arcaeon-ledger](https://pypi.org/project/arcaeon-ledger/) hash chain, so receipts have a sequence.
3. **Witness pin**: the chain head is pinned outside the issuer (hosted arcaeon-witness if `ARCAEON_WITNESS_URL` / `ARCAEON_WITNESS_KEY` are set; otherwise a local file the receipt labels *self-controlled*, which is worth nothing to a stranger and says so).
4. **Anchor**: an [OpenTimestamps](https://opentimestamps.org) stamp of the body digest, carried inside the receipt as base64. Fresh stamps are calendar-pending and upgrade to a Bitcoin attestation within hours. A verifier reconstructs the stamped file from the receipt alone and runs `ots verify`; no contact with the issuer is required.

## AB 1405 report elements

California Gov. Code §11549.83(d)(1) requires a registered AI auditor's report to the auditee to include six elements. Verbatim, from the leginfo bill text (`projects/arcaeon/AB1405_REPORT_ELEMENT_MAP_2026-09-15.md` has the full statute-to-field mapping this section implements):

> "A registered AI auditor that conducts a covered AI audit shall provide the auditee with a report that includes, but is not limited to, all of the following information:
> (A) The scope and objectives of the audit.
> (B) The results of the audit and any documentation necessary to demonstrate the basis of those results.
> (C) For each deficiency identified in the audit, a description of any technical, operational, or governance measures the AI auditor determines would reasonably address the deficiency, if appropriate.
> (D) A description of whether the auditee has implemented and adhered to internal safety standards and protocols that are within the scope of the covered AI audit.
> (E) A description of the limitations of the audit, including any matters within the scope of the audit that were not assessed and any material gaps in the evidence, information, systems, or access available to the AI auditor.
> (F) A statement indicating that the audit was conducted in accordance with the requirements of this chapter, signed and dated by the AI auditor."

None of this is a compliance claim by the tool, and issuing a receipt with every field filled in does not mean, and is never rendered as meaning, that an audit "complied" with anything.

| Element | Receipt carries | Auditor writes |
|---|---|---|
| (A) scope and objectives | `extra.engagement_scope` (`core.engagement_scope()`) — the engagement-level statement | Which systems, what period, against which named requirement |
| (B) results and documentation | `checks` + `subject` (already existed) | The check content itself |
| (C) remediation per deficiency | `checks[].remediation`, an optional string | Whether a flagged check is a deficiency at all, and what remediation "if appropriate" — the statute's own qualifier — means here. Never generated by this tool. |
| (D) adherence to internal standards | `subject.internal_standards_ref` (which standard) + `checks[].adherence` (`"adhered"` / `"not_adhered"` / `"not_assessed"`) | The finding itself — whether the auditee actually met its own named standard |
| (E) audit limitations | `scope["does_not_prove"]` (already existed, mandatory) | — |
| (F) signed, dated compliance statement | `extra.attestation` (`core.attestation()`: statement, auditor name, optional registry id, signed-at date) plus a separate detached `receipt["attestation_signature"]` (`core.attach_attestation_signature()`) over the body digest | The statement itself and the actual signature — by law, the auditor's act, never this tool's |

**Inside the digest vs. outside.** `engagement_scope`, `checks[].remediation`, `subject.internal_standards_ref`, `checks[].adherence`, and `extra.attestation` (statement/auditor_name/auditor_registry_id/signed_at) are all ordinary keys under `subject`/`checks`/`extra` — already-digested `BODY_FIELDS` — so they're tamper-evident the same way every other body field is: edit one after issue and `body_digest_ok` goes false. The one exception is the detached `attestation_signature`: a signature computed over the body digest cannot also be one of the inputs that produced that digest without becoming circular, so it lives as a fourth top-level attachment beside `ledger`/`witness`/`anchor`, outside `BODY_FIELDS`, by construction. `verify_receipt()` never uses any of these fields' presence or contents to compute its `ok` verdict — only that the digested ones, if present, are unaltered since issue.

All four are optional and fully backward-compatible: a receipt minted before this existed has no `extra.attestation`, no `engagement_scope`, no `internal_standards_ref`, no `checks[].adherence`/`remediation`, and still verifies byte-for-byte.

## Library

```python
from arcaeon_receipt import (cite, call, approval, authorship, ballot, archive,
                             roster_report, verify_receipt)

rc = cite.citation_receipt(open("brief.txt").read(), ledger_path="receipts.log.jsonl")
rc = call.call_receipt(request, response, ledger_path="calls.log.jsonl", seller="acme")
rc = call.phone_call_receipt(["caller-1", "dispatcher-2"], start_iso, end_iso, transcript_sha256,
                             ledger_path="calls.log.jsonl")

rc = approval.artifact_approval_receipt(approval.hash_artifact(pdf_bytes), "dana-approver",
                                        "I approve this release for production",
                                        ledger_path="approvals.log.jsonl")

rc = ballot.ballot_receipt(graded_ballot, trainee="j. alvarez", scenario="oral_board.set1",
                           ledger_path="ballots.log.jsonl", grader="ascenvo.vcs.oral_board",
                           issuer="Westbrook Regional Training Academy",  # optional, sealed
                           cohort="WRTA-2026-OB-14")                      # optional, sealed

rows = ballot.read_roster("roster.csv", scenario_default="oral_board.set1")   # refuses, by row
minted = ballot.mint_cohort(rows, ledger_path="wrta-ob-14.jsonl", namespace="wrta-ob-14",
                            issuer="Westbrook Regional Training Academy",
                            cohort="WRTA-2026-OB-14", out_dir="class/")

gate = approval.ApprovalGate("approvals.log.jsonl", agent="billing-agent")
p = gate.decide(gate.propose(action), principal="dana", decision="approved")
rc = gate.executed(p, action_that_ran)          # checks[0].executed_as_approved

s = authorship.AuthorshipSession("writing.log.jsonl", author="a. writer", document="essay")
s.event("type", text="The quick "); s.event("paste", text="brown fox")
rc = s.close(final_text)                          # typed vs pasted, rolling hash, final digest

report = roster_report.build_report("class/")     # verdict counts, never score statistics
manifest = archive.build_archive("class/", "wrta-ob-14.zip")   # portable, checkable offline

verify_receipt(rc, ledger_path=..., ots=True)     # typed verdicts, never raises
```

Spans, request bodies and response bodies are digested, never stored, unless the issuer explicitly opts in, and then the receipt says so.

## Status

0.1.0, foundation. Python >= 3.9, one dependency (`arcaeon-ledger`). Tests: `py -m pytest -q tests`.

MIT.
