<!--
Vendor package spec for the Ballot Receipt. Written 2026-09-13 against the
M5 ruling in
projects/online_business/LANE_COUNCIL/decisions/PRICING_MOTION_2026-09-13_HELD_NUMBERS.md
(council sitting + Daniel's CEO approval at 6:49 AM).

Research and specification only. No product code is written by this file.

Three standing rules this document obeys, and a reader should hold it to:
1. The word "correct" never appears here as a claim about a score. Its one
   appearance in the body of this file is inside the quoted scope block,
   where it is a DENIAL. The claim this package makes is AUTHENTIC and
   UNALTERED.
2. No price for anything we sell appears in this file. Pricing is Fable's
   call and is not set here. Section 4 gives the STRUCTURE only.
3. Every competitor price in section 5 carries the URL it was read on, or
   is marked UNVERIFIED. Nothing in that table is estimated.
-->

# Vendor Package: the Receipted Ballot

## 1. What it is

A training vendor already grades people. An academy runs a cohort through an
oral board, a PSAP runs new hires through call-taking scenarios, and at the
end of each run a score exists. Today that score leaves the building as a
screenshot, a PDF, or a line a candidate typed into an application, and the
hiring center on the other end has no way to tell an honest result from an
edited one. The Ballot Receipt closes that gap: at the moment a graded run
closes, the finished ballot object is sealed with a sha256 digest bound to a
stated time and written into a hash chain, so a stranger can recompute the
digest from the document itself and see whether one digit moved. Issuing a
receipt is free. Verifying a receipt is free, public, and requires no
account, forever, because a verifier anyone has to pay is a verifier with an
interest in the answer. The vendor package sells everything that sits around
that verdict and never the verdict itself: the academy's own name on the
document, issuing across a whole class instead of one trainee at a time,
roster reporting for the person who runs the class, an API into the system
the vendor already operates, and bulk export of the class's sealed record.

The claim is fixed in code and is copied verbatim onto every document the
package produces. From `arcaeon_receipt/ballot.py`:

```python
SCOPE = {
    "proves": [
        "the score and the ballot are unaltered since the timestamp",
    ],
    "does_not_prove": [
        "the score is correct",
        "the sim was not attempted before",
    ],
    "method": "sha256 digest of the canonical JSON ballot object (score, verdict, and whatever "
              "fields the grading engine produced), bound to a stated timestamp inside the receipt "
              "body; hash-chained in arcaeon-ledger, one row per ballot.",
}
```

That block is the only claim language this package is allowed to use. It
prints on the face of every exhibit, above the results, so the first thing a
hiring manager reads is the limit. A vendor who wants a stronger sentence
than that one is asking for a sentence we do not have.

## 2. The five components

Each component below says what the vendor receives, in what form, and what
it rests on in the stack today. Where the answer is that the piece is not
built, the entry says so plainly and names the nearest thing that is.

### 2.1 Vendor branded ballots

**STATUS: EXISTS as of c7836bc (2026-09-13)** -- `ballot_receipt(issuer=, cohort=)` seals both in the digested `extra` dict, `exhibit()` renders them, the verifier was not touched. The two DOES NOT EXIST YET entries below are now historical; one limit is new and real: the name is unalterable after issue, not authenticated.

**What the vendor gets.** Their academy's name on the document a trainee
hands to a hiring center. The exhibit header carries the issuing
organization, the grader that produced the score, and the class it belongs
to, so the receipt reads as the academy's paper rather than as a third
party's utility that happened to touch their data.

**In what form.** Two files per finished run, the same pair the tool
produces today: a JSON receipt, which is the thing a stranger verifies, and
a plain-text exhibit, which is the thing a human reads. Branding rides
inside the sealed body, not in a cosmetic header. A vendor name printed
outside the digest is a name anyone can retype; a vendor name inside the
digest cannot be changed without breaking verification, which is the only
version of branding worth selling.

**What it rests on.**
- EXISTS: `arcaeon_receipt/core.py`, `build_receipt()`. Its body already
  carries an `extra` dict that is digested along with everything else. That
  is the right home for issuer identity and it is already sealed.
- EXISTS: the `grader` field on `arcaeon_receipt/ballot.py`,
  `ballot_receipt()`. It already carries a product string such as
  `ascenvo.vcs.oral_board` and already appears in the `subject` block and on
  the exhibit line. This is the nearest shipping approximation of vendor
  identity today.
- DOES NOT EXIST YET: `ballot_receipt()` does not accept or pass an `extra`
  payload, so there is no issuer, class, or cohort field in a ballot receipt
  today. The signature would need an issuer argument that flows into
  `build_receipt(extra=...)`.
- DOES NOT EXIST YET: a vendor title line on the exhibit.
  `arcaeon_receipt/ballot.py`, `exhibit()` calls `render_exhibit()` with a
  fixed `title="BALLOT RECEIPT"`. Nothing reads a vendor name into it.

### 2.2 Issuing at volume across a class

**STATUS: the cohort driver EXISTS as of c7836bc (2026-09-13)** -- `arcaeon-receipt ballot --roster roster.csv` (library: `ballot.read_roster()` / `ballot.mint_cohort()`) mints one receipt and exhibit per row into one ledger and namespace, refusing a malformed row by number before anything is minted. The class MANIFEST named below is still not written, and the production JS mint at the grading path remains design only.

**What the vendor gets.** One cohort, one command or one call, a sealed
receipt per trainee, and a chain that proves the order the class was issued
in. A twenty-seat academy class finishes its oral boards on a Thursday and
the coordinator has twenty verifiable documents on Thursday, not twenty
manual runs.

**In what form.** A per-class ledger namespace, one receipt and one exhibit
per trainee written into it, and a class manifest listing what was issued.
Because every ballot appends one row to the same chain, the class ledger
itself proves the relative order of the cohort, which is a fact a
per-trainee screenshot cannot carry at any price.

**What it rests on.**
- EXISTS: per-class separation. `ballot_receipt()` already takes
  `namespace` and `ledger_path` as parameters, and `arcaeon_receipt/cli.py`
  already exposes both as `--namespace` and `--ledger`. A class namespace
  needs no new primitive.
- EXISTS: the hash chain itself, `arcaeon-ledger`, called through
  `Ledger.append()` in `arcaeon_receipt/core.py`, one row per ballot.
- DOES NOT EXIST YET: a cohort driver. `arcaeon_receipt/cli.py`'s `ballot`
  subcommand takes exactly one `path` and one `--trainee`. Issuing a class
  today is a shell loop somebody writes by hand. The nearest precedent in
  this repo is `arcaeon_receipt/cite_batch.py`, which is a batching layer
  for citations and shares none of this code path.
- DOES NOT EXIST YET: the production mint. `docs/ballot-wiring-note.md`
  records the decision that the live mint is JavaScript at the grading path
  (`projects/ascenvo_site/api/grade_board.js`) with the Python here as the
  reference implementation checked by a shared canonicalization vector.
  That JS mint is design only and has not been written. Every receipt that
  exists today was minted from the Python CLI by hand.

### 2.3 Roster reporting for a training manager

**STATUS: the report EXISTS as of 2026-09-13** -- `arcaeon-receipt
roster-report <cohort-dir|class-ledger.jsonl> [--out report.csv] [--json]`
(library: `roster_report.build_report()`) reads a cohort, verifies every
receipt through `verify_batch`'s own functions, and writes one row per
trainee (receipt id, issuer, cohort, trainee label, scenario, stated score,
issued-at, verdict, ledger status, anchor status) under a header carrying
the issuer, cohort, generated-at, receipts counted, the three verdict counts,
the pass structure, and the scope block verbatim. Verdict counts only: no
class average, no pass rate, no ranking, held there by a grep test over the
real output. A class over 20 is verified in pages of 20 and the header says
how many passes it took; no single pass exceeds the published cap. The two
DOES NOT EXIST YET entries below about a roster and a cohort view are now
historical. The two ascenvo-side gaps under them are NOT: there is still no
instructor view behind the `assessment_view` entitlement, and still no
per-dispatcher seat assignment. This report is a file a coordinator
generates, not a page they log into.

**What the vendor gets.** One view of the class: who finished, what the
grading engine returned, whether each receipt still verifies today, and
which of them carry an independent timestamp. The person who runs the class
gets one page instead of a folder of JSON.

**In what form.** A roster table, regenerable from the class ledger and the
receipt files alone, with one row per trainee and a verification state per
row. Machine-readable CSV for the coordinator's own records, plus a
readable rendering for a report that goes upstairs. The roster is derived,
never authoritative: it is regenerated from the receipts, so a roster and
its receipts cannot drift into disagreeing.

**What it rests on.**
- EXISTS: the per-receipt verification the roster would call.
  `arcaeon_receipt/core.py`, `verify_receipt()`, recomputes the body digest,
  the ledger chain, and optionally the OpenTimestamps anchor, and is typed
  and does not raise.
- DOES NOT EXIST YET: anything that reports across more than one receipt.
  There is no roster, no cohort view, and no aggregate anything in this
  repo. `arcaeon_receipt/cli.py`'s `verify` takes one path.
- DOES NOT EXIST YET on the ascenvo side, with a specific gap worth naming:
  the agency seat SKU already grants `app_metadata.agency.assessment_view`
  (`projects/ascenvo_site/api/stripe-webhook.js`, `grantAgencySeats()`,
  pinned by `tests/test_webhook_agency_seat.js`), and that flag is true on
  every agency purchase today. There is no instructor view behind it. The
  entitlement for a training manager's view exists and the view does not.
- DOES NOT EXIST YET: per-dispatcher seat assignment. The ascenvo pricing
  spec, Layer 3, states this plainly: a purchase grants the coordinator's
  own account, and does not yet provision N separate dispatcher logins. A
  roster of trainees who each have their own account is downstream of that
  build, not of this one.

### 2.4 An API into what they already run

**What the vendor gets.** A call their own platform makes at the moment a
grade closes, and a verification surface they can put on their own page.
The vendor keeps their LMS, their rubric, and their grading engine. We seal
what it produced and hand back the two files.

**In what form.** Two surfaces with opposite commercial treatment, and the
asymmetry is the product, not an oversight.
- The issuing surface is the one the vendor integrates: it takes the graded
  object verbatim, plus trainee, scenario, grader, issuer, and class, and
  returns the receipt JSON and the exhibit text. It is authenticated,
  because it writes into the vendor's own chain.
- The verification surface is free, public, unauthenticated, and stays that
  way. A hiring center checking one receipt is the moment the whole thing
  either earns trust or does not, and a paywall at that moment converts a
  proof into a sales call.

**What it rests on.**
- EXISTS: the only HTTP surface in this repo today, the hosted witness pin.
  `arcaeon_receipt/core.py`, `_witness_pin()`, POSTs to
  `ARCAEON_WITNESS_URL` + `/api/pin` with a bearer key and records the
  result, or records `pin_failed` with the reason and says the receipt is
  unwitnessed. That is a working pattern to copy, and it is not a ballot
  issuing endpoint.
- EXISTS: free verification, two independent implementations, both today.
  `arcaeon-receipt verify` in `arcaeon_receipt/cli.py`, and
  `web/verify-receipt.html`, which runs entirely in the reader's browser
  with no call home and carries its own JS canonicalizer between its
  `C14N-START` and `C14N-END` markers, held to the Python implementation by
  `tests/test_verify_page_parity.py` against the vectors in
  `tools/c14n_vectors.py`.
- DOES NOT EXIST YET: any ballot issuing endpoint, in any language. The
  wiring note names the open question and refuses to answer it alone: a
  Vercel Node function can reproduce the digest, but the ledger append, the
  witness pin, and the anchor are not pure functions of the body and their
  replication from a Node function is undecided.
- DOES NOT EXIST YET: an MCP wrapper for ballots. Four adapters have one
  (`cite_mcp.py`, `call_mcp.py`, `approval_mcp.py`, `authorship_mcp.py`).
  There is no `ballot_mcp.py`. For a vendor whose stack is agent-shaped
  rather than HTTP-shaped, that is the integration surface, and it is the
  cheapest one on this list to build because the pattern is written four
  times already.

### 2.5 Bulk export

**What the vendor gets.** The class, in a form they own and can hand to
anybody, including us going away. Receipts, exhibits, the ledger, and the
witness sidecar, as one archive, checkable by a stranger with the free
verifier and no cooperation from us.

**In what form.** An archive per class, plus a bulk verification pass that
answers over the whole set at once instead of one file at a time. The
published cap on free bulk verification is 20 receipts in one pass, and per
the M5 ruling that number is printed on the surface next to the words "free
to verify", because free with a silent cap is a small overclaim and this is
a product about not making those.

**STATUS: BOTH HALVES EXIST as of 2026-09-13** -- bulk verification at 4033305, the archive builder at the commit carrying this line. `arcaeon-receipt verify --batch <dir|glob|paths...>` (library: `verify_batch.verify_batch()`) verifies a whole class in one pass, one line per receipt and one summary line, and `web/verify-receipt.html` takes a whole class dropped on it. The cap of 20 is enforced as a **refusal**: past it nothing is verified and the message names the cap and the count, in the CLI and in the page. Verdicts are three, never two -- `ok`, `FAIL`, and `undetermined` for a file that will not open or a receipt whose ledger nobody in the run could find -- with exit codes 0 / 2 / 4 (and 1 for a refused batch). `arcaeon-receipt archive <cohort-dir|class-ledger.jsonl> --out class.zip` (library: `archive.build_archive()`) writes one portable file: every receipt and exhibit and the ledger files they name, copied byte for byte and asserted so by sha256 read back out of the finished archive; the roster report CSV; a `MANIFEST.json` carrying the archive version, the generated-at, issuer, cohort, every file's sha256, every receipt's verdict, the verdict counts, and the scope block verbatim; and a `README.txt` telling a stranger with no tools and no account how to check it. It verifies offline: extracted with the network shut, every receipt reads `ok` against the bundled ledger, which is a test rather than a claim. A receipt that FAILS is packed with its verdict on the manifest and the archive still builds (exit 2 says so); verdict counts only, no statistic about scores, held by a grep. A class over 20 is verified in pages of 20 the way the roster report does it. Both DOES NOT EXIST YET entries below are now historical, and limit 5 in §6 has been narrowed accordingly. What is still a directory copy is nothing; what is still absent is a hosted download -- this is a file the coordinator generates at a command line.

**What it rests on.**
- EXISTS: the portable artifacts themselves. The ledger is a JSONL file the
  vendor already holds, the witness pin writes a `.witness.jsonl` sidecar
  beside it (`arcaeon_receipt/core.py`, `_witness_pin()`, local-file
  branch), and every receipt is self-contained JSON. Nothing needs to be
  extracted from a database that belongs to us, because there is no such
  database in this path.
- EXISTS as a worked example of the export shape:
  `examples/ballots/`, ten receipts, ten exhibits, a shared `ledger.jsonl`,
  and one anchored receipt carrying a real OpenTimestamps stamp.
- DOES NOT EXIST YET: bulk verification. `arcaeon_receipt/cli.py`'s
  `verify` takes one path. `web/verify-receipt.html` reads one file: a
  single `file-input` and a drop handler that takes
  `e.dataTransfer.files[0]`. There is no multi-file path in either, so the
  cap of 20 is a constraint on a feature that has not been written, not a
  limit currently being enforced.
- DOES NOT EXIST YET: any archive builder. Today an export is a directory
  copy.

### 2.6 Line item: the pin absorption ceiling

Not a price and not billed to anybody. Stated here because a vendor
evaluating a free-forever claim is right to ask what stops it from being
withdrawn, and the honest answer is a number we wrote down before we needed
it.

The optional witness pin, which is what gives a receipt a sequence outside
the issuer's own filesystem, costs us money per pin. The absorption ceiling
for ballot pins is **$25 per month**, held separate from the $50 monthly AI
ceiling so that the two cannot mask each other's overruns. It is
approximately 5,000 pins per month at current rates. Per the ruling's own
condition, the counter is built and read before the number is cited as a
control: a ceiling nobody counts against is a sentence, not a control.

Issuance stays free and verification stays free. If pin volume ever
approaches that ceiling, the lever is the optional pin, never the free
verification, and never a charge to check whether a document is genuine.

## 3. The first customer path

**Who.** Not the large consolidated center. On 2026-09-10 an executive
director of a consolidated PSAP told us directly that they already run an AI
call simulator and that it has worked well for them, and in the same reply
drew the segmentation line himself: the value is for the centers that do not
have access to other call simulators. Take him at his word. The first
customer is a single-jurisdiction PSAP or a community-college dispatch
academy that runs entry-level cohorts on paper and a spreadsheet, has no
simulation vendor, and has at least one downstream consumer of its results,
which means a neighboring agency that hires from it or a chief who asks how
the class did.

Everything on the public surface for this buyer is entry-level
telecommunicator content. Supervisory and promotional material is internal
and is not part of what is sold or shown here.

**What they get in week one.**
1. A class namespace of their own, and the first cohort's graded runs
   sealed into it, one receipt and one exhibit per trainee.
2. The exhibit, which is the artifact that actually does the work: one page
   per trainee, the scope block at the top, the score and verdict the
   grading engine produced, and the integrity block underneath.
3. A verification link they can put in an email signature or at the bottom
   of a transcript, which resolves to a page that runs in the reader's own
   browser and needs nothing from us.
4. One walkthrough with the coordinator on what the document claims and what
   it declines to claim, using the scope block as the script. A coordinator
   who can state the limit out loud is a coordinator who will not be
   embarrassed by it in front of a hiring panel.

**What we need from them.** A roster. One file, two required columns: a
trainee identifier and a class label. Nothing else. No system access, no
integration, no credentials, no LMS project, no email addresses required for
the receipt to work. If the first ask is larger than a CSV, the pilot has
become a procurement and will not happen in week one.

## 4. Pricing scaffold, structure only

**Prices are not set in this file.** They are Fable's call. What follows is
the shape a price would attach to, so that when a number is chosen it has
somewhere to go and the shape is not being invented under time pressure.

Two things are fixed by the M5 ruling and are not pricing variables at all:

- **Issuance is free.** A paid mark reads as a grade warranty, and the scope
  block explicitly denies being one.
- **Verification is free, public, and account-free, forever.** A paid
  verifier is a conflicted verifier.

Three candidate structures for what is sold around that:

| Structure | Unit | Fits when | Against it |
|---|---|---|---|
| Per seat | One trainee in the vendor's roster for a term | The vendor thinks in headcount and already budgets per-student, which every academy comparable in section 5 does | A class of six and a class of sixty are the same amount of work for us, so per-seat overcharges the large cohort and underprices the small one relative to cost |
| Per class | One cohort, any size, one namespace, one export | Matches how an academy actually operates, which is in cohorts with start and end dates, and matches the natural unit of the export | A vendor running continuous intake rather than cohorts has no class boundary to buy against |
| Flat | The vendor's whole operation, all classes, one term | Simplest to sell, no counting, no true-up conversation, no incentive for the vendor to under-report headcount | Gives away the volume story completely: the largest and smallest customer pay the same, and there is no expansion path inside an account |

The recommendation this spec makes, for Fable to accept or discard: **per
class, with the export and the roster attached to the class**, because the
class is the unit the buyer already manages and the unit our own ledger
namespace already is. Per-seat is the structure most familiar to this buyer,
and if familiarity beats fit, that is a legitimate call and the plumbing
does not change.

The pin absorption ceiling in section 2.6 is a cost line, not a price line,
and does not belong in any of the three structures above.

## 5. What a training coordinator already buys

Three products a PSAP or academy training coordinator is already spending
money on in this lane. All pages below were read on 2026-09-13. Every price
carries the URL it was read on. Where a vendor does not publish a price, the
row says so and cites the page that shows the absence, rather than
substituting an estimate.

| What they buy | What it is | What it costs | What it does not do that a receipted ballot does |
|---|---|---|---|
| **GovWorx CommsCoach TRAIN** | AI-driven 911 call and radio simulations with, in the vendor's own words, "objective automated scoring" and "AI-powered scoring and benchmarking." One module of a larger telecommunicator lifecycle platform that also covers hiring, QA, promotion, and live call assist. This is the direct incumbent in our exact lane: a PSAP executive director named it to us unprompted on 2026-09-10 as already in use and working well for his center. | **Not published.** No price appears on the product page or the site. The page's pricing section was still unpopulated template text when read on 2026-09-13. Contact is by email for a quote. [product page](https://www.govworx.ai/solutions/ecc-call-radio-simulations-training) / [site](https://www.govworx.ai/) | The score lives in the agency's own instance of the vendor's dashboard. The product page names no certificate, credential, or portable artifact a trainee can carry to a different employer. A trainee who trains at Agency A and applies to Agency B arrives with nothing an outsider can check. A receipted ballot is the trainee's document, verifiable by a stranger with no account and no contact with the issuer. |
| **APCO Institute, Public Safety Telecommunicator 1, 8th Edition** | The core telecommunicator certification course. Five weeks online or five days virtual classroom. The recognized entry credential in this field, and the thing a coordinator's training budget is already shaped around. | **$595 non-member, $545 member**, per student, either format. Tuition "includes a comprehensive course manual and all certification fees." Earns 40 CDE hours. Contract and live classes are "Contact us for pricing." [course category page](https://www.apcointl.org/apco_course_category/pst/) | It certifies a person, once, at a point in time. It says nothing about any individual graded run afterward, and it produces no per-result artifact. A hiring center reading "PST1 certified" learns the candidate passed a course; it learns nothing about the score on the oral board they sat last Tuesday, which is the number actually in dispute. The two are complements, not substitutes. |
| **CritiCall 3D** | Pre-employment applicant testing software. In the vendor's words it "tests 911 and public-safety dispatcher, calltaker, and telecommunicator applicants for the multitasking and requisite hard and soft skills necessary in today's dispatch and telecommunication environment," across operational, behavioral, and situational dimensions. The site states it "is used by over 1,500 agencies, and half of all state police." | **Not published.** The site shows "Ready for a Demo or Custom Quote?" and no figure, per-test, per-seat, or annual. State-level programs are noted as having "Special pricing may apply" with no number attached. [site](https://criticall911.com/) / [state programs page](https://criticall911.com/additional-resources/stateprovincial-programs) | It is the hiring agency's screening gate, not the candidate's document. Whether a result can travel with the candidate to a second agency is **UNVERIFIED**: the vendor's own applicant-facing page does not state it either way ([applicants page](https://criticall911.com/dispatcher-testing/applicants)). A receipted ballot is portable by construction, because the proof is the document itself rather than a record in somebody's system. |

**Three things that table does not let us say.**

- The 2026-09-10 "incredibly successful" line about GovWorx is from a direct
  email reply to our own outreach, not from any public source. It is
  verified as an email we hold and is **UNVERIFIED as a public claim**. It
  does not go into copy as though it were a published endorsement.
- Whether GovWorx scores a trainee specifically on what they extracted from
  an uncooperative caller, which is Ascenvo's own narrower claim, is
  **UNVERIFIED**. The product page describes automated scoring and added
  realism through accents and background noise; it does not describe an
  evasive or uncooperative caller, and absence from a marketing page is not
  evidence of absence from a product.
- No dollar figure for GovWorx or CritiCall exists in any source read here.
  Both are quote-only. Any sentence that positions our package as cheaper
  than either one is unsupported, and stays unwritten until somebody hands
  us a quote.

**The nearest trainee-side product, noted rather than tabled** because the
buyer specified here is a coordinator and not a candidate: JobTestPrep sells
a CritiCall practice pack directly to individual applicants
([product page](https://www.jobtestprep.com/criticall-test-practice-prep)).
Its price is **UNVERIFIED**: the live product page rendered no static figure
on 2026-09-13, and the $79 figure that circulates comes from the vendor's
own plans FAQ used as an illustrative example
([plans FAQ](https://www.jobtestprep.com/plans-faqs)) plus a third-party
review site, not from the checkout page. What matters for this spec is the
structural point, which is verified: it is study practice, and it issues
nothing a candidate can hand to a hiring board.

**What the table actually shows.** Nobody in this lane sells a portable,
per-result, independently checkable artifact. The incumbent simulator keeps
the score in its own dashboard. The certification body certifies the person
and not the run. The screening vendor serves the employer and not the
candidate. That gap is the whole reason this package has a place, and it is
also why the free half has to stay free: the artifact is only worth
something if the stranger reading it can check it without joining anything.

## 6. What this package does not do

Same register as `examples/ballots/WHAT_THESE_DO_NOT_SHOW.md`, and for the
same reason: a gap named here is smaller than a gap a buyer finds.

1. **It does not grade, and it does not improve grading.** Everything about
   whether a rubric measures dispatcher competence is untouched by this
   package and unaddressed by it. A receipted 91 is the same 91, sealed.
2. **It does not stop a trainee from showing only their best receipt.** The
   scope block warns about this in its own words, but that warning only
   reaches a reader who receives every receipt or knows to ask. A trainee
   who runs a scenario three times can hand over one document, and nothing
   in that document reveals the other two. Roster reporting to the vendor is
   the partial answer, because the coordinator sees all three; it does
   nothing for the hiring center reading one receipt cold.
3. **It does not verify identity.** Nothing here proves the person named on
   the receipt is the person who sat the scenario. That is the vendor's
   proctoring problem before the grade exists, and sealing an unproctored
   result seals an unproctored result.
4. **The production path is not built.** Every ballot receipt in existence
   was minted by hand from the Python CLI. The JavaScript mint at the
   grading path is design only (`docs/ballot-wiring-note.md`), the shared
   canonicalizer it must use has not been extracted, and the parity vector
   that would hold the two legs together has not been run against a JS mint
   because there is no JS mint.
5. **One of the five components is unbuilt today, and the four that exist
   are command-line tools.** The issuing API (§2.4) does not exist in any
   form: no ballot issuing endpoint in any language, and no `ballot_mcp.py`.
   The other four exist as of 2026-09-13 -- vendor branding and volume
   issuing in c7836bc, bulk verification in 4033305, roster reporting in
   3f363b8, and the bulk-export archive in the commit carrying this line.
   What a vendor runs today is a Python CLI on their own machine, not a
   service: there is no hosted issuing path (limit 4), no instructor view
   behind the entitlement that already grants it (§2.3), and no hosted
   download for the export. A vendor conversation that implies all five are
   shipping is describing a roadmap as an inventory, and one that implies
   the four that exist are a platform is describing a CLI as a product
   surface.
6. **Independence is only as good as the pin.** A receipt witnessed to a
   local file is self-controlled and proves nothing to a stranger, and the
   receipt says so on its own face
   (`independence: "none (self-controlled file)"`). The hosted pin and the
   OpenTimestamps anchor are what make the timing independently checkable,
   and they are optional, off by default on ballots, and cost money per use.
7. **It does not replace a hiring center's own process.** It removes one
   specific doubt, which is whether the number in front of them is the
   number the sim issued. Every other doubt a hiring panel has is still
   theirs to resolve.
