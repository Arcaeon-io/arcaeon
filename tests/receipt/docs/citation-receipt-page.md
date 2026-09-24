<!--
DRAFT landing page copy for arcaeon.io. Not published. Written to target
the searches a lawyer runs after a hallucinated-citation scare: "AI
hallucinated citations sanctions", "certify citations AI brief", "verify
citations before filing". Plain English, no em dashes, no exclamation
marks, and no claim of correctness anywhere on the page: the receipt
attests existence checks only, and the first screen says so before
anything else.
-->

# Citation Receipt

### Proof you checked every citation exists, before you file.

Courts have sanctioned filings with fabricated case citations. Some of the
resulting orders run into six figures, on top of a public record with the
lawyer's name on it. The fix is not a promise that your brief is right. It
is a receipt that shows what you checked, when you checked it, and what
the check came back with.

**What this receipt proves:** each citation in your document was
submitted to CourtListener's citation-lookup service at a stated time, and
the service returned a stated status (found, not found, invalid reporter,
ambiguous).

**What it does not prove:** that any case supports the point it is cited
for, that a case is still good law, or that a quotation is accurate. This
is not Shepard's. It is not KeyCite. It is not legal research. It is an
existence check, stated as one, on the face of the document, before the
results.

---

## Why this exists now

A public tracker of AI-hallucination incidents in court filings counts
more than a thousand U.S. decisions where a party relied on fabricated or
mangled AI output and a court responded. In the first quarter of 2026
alone, sanctions for fabricated citations totaled roughly $145,000 across
multiple cases, including a $110,000 award in Oregon and a five-figure
punitive sanction from a federal circuit court. [UNVERIFIED: the exact
figures and case totals above come from a secondary tracker, not a court
docket; verify against the underlying orders before quoting a number in
any final published copy.]

At the same time, a fast-growing list of judges and courts now require an
AI-use certification with every filing: a signed statement saying whether
generative AI was used, and if so, that a human checked the citations.
Three current examples:

- **U.S. District Court, District of Colorado** (Judge Nina Y. Wang),
  *Standing Order Regarding the Use of Generative Artificial Intelligence*,
  effective December 1, 2025: every filing before the judge must carry an
  AI certification, signed by everyone who contributed to drafting it,
  confirming a human reviewed AI-drafted language and verified the cited
  authorities.
- **U.S. District Court, Western District of North Carolina**, *Standing
  Order Re: Use of Artificial Intelligence* (revised December 8, 2025):
  every brief must certify that no AI outside the embedded research tools
  in Westlaw, Lexis, Fastcase, or Bloomberg was used, and that every
  statement and citation was checked by a person for accuracy.
- **U.S. Bankruptcy Court, Southern District of California**, *General
  Order 210*, effective January 1, 2026: governs the use of generative AI
  for all pleadings, motions, and papers filed in the court.

Certifying that a human checked the citations is now a filing requirement
in a growing number of courts. A Citation Receipt is the paper you produce
when someone (a judge, a bar disciplinary panel, opposing counsel) asks
what "checked" meant.

---

## How it works

Run it before you file, not after someone else finds the problem:

```
export COURTLISTENER_TOKEN=...        # free account at courtlistener.com
arcaeon-receipt cite brief.txt --exhibit brief.exhibit.txt
```

The tool submits every citation your document contains to CourtListener,
one existence check per citation, and writes two files: a JSON receipt
(what a stranger verifies) and a plain-text exhibit (what a clerk reads).

**The gate is the exit code, not a dashboard you have to remember to
check.** If every citation was found, the command exits 0. If any citation
comes back not found or with an invalid reporter, it exits 3. Wire that
into whatever runs before your filing goes out:

```
arcaeon-receipt cite brief.txt --exhibit brief.exhibit.txt || echo "STOP: a citation did not check out"
```

A pre-filing script that stops on exit 3 catches the fabricated citation
before it reaches a judge. That is the whole point of running the check
before submission instead of defending it after.

### What the exhibit looks like

This is real, unedited tool output (`arcaeon-receipt cite
tests/fixtures/brief.txt --fixture tests/fixtures/courtlistener_planted_full.json
--no-anchor`, the package's own offline demo, run against a sample motion
with two fabricated citations -- one with a made-up reporter no lookup
will ever recognize, one with a real-looking reporter but a case that does
not exist -- and one more citation the fixture simply never returned,
demonstrating the "silently dropped" flag from
`memory/FINDING_courtlistener_silently_drops_unrecognized_citations_2026-09-11.md`;
regenerated 2026-09-12 when the 5th planted citation, "100 Cal. 200," was
retired for being a real, unambiguous case (Austin v. Dick) rather than the
fake it was meant to demonstrate. The fixture used here
(`courtlistener_planted_full.json`) is a separate, wider file than the one
the unit tests use (`courtlistener_planted.json`, scoped to a short inline
brief): it covers every real citation the full `brief.txt` actually
contains, so this transcript does not falsely flag a real, uncovered
citation as unrecognized):

```
CITATION EXISTENCE RECEIPT  (arcaeon-receipt)
Issued (UTC): 2026-09-12T15:45:08Z

WHAT THIS RECEIPT PROVES
  - Each citation listed below was submitted to the CourtListener citation-lookup service at the issue time shown, and the service returned the status recorded beside it.
  - The results, the scope statement and the issue time were bound into this receipt at issue; any later change to any of them breaks the body digest.
WHAT THIS RECEIPT DOES NOT PROVE
  - That any cited authority supports the proposition it is cited for.
  - That any cited authority is good law, current, unreversed, or quoted accurately. This is not Shepard's, KeyCite, or legal research of any kind.
  - That the brief contains no other citations: only citations the service's parser detected were checked. Citation-shaped text the service did not return is listed as unrecognised and was not checked. Statutes, regulations, law-journal, id. and supra citations are never looked up.
  - That a 'found' citation was cited correctly, or that a 'not found' citation is fabricated: CourtListener's coverage is broad but not complete, and a valid citation can be absent from it.

SUBJECT
  document: brief.txt
  document_chars: 4158
  citations_detected: 9
  citations_flagged: 3

RESULTS (9 checks)
     found                    347 U.S. 483  -> Brown v. Board of Education
     found                    410 U.S. 113  -> Roe v. Wade
  !! not_found                999 F.3d 1234  Citation not found in CourtListener
  !! invalid_reporter         12 Fak. 34  Invalid reporter
     found                    477 U.S. 242  -> Anderson v. Liberty Lobby, Inc.
     found                    477 U.S. 317  -> Celotex Corp. v. Catrett
     found                    282 U.S. 555  -> Story Parchment Co. v. Paterson Parchment Paper Co.
     found                    327 U.S. 251  -> Bigelow v. RKO Radio Pictures, Inc.
  !! not_recognized_by_service 88 Zzq. 12  citation-shaped text the lookup service did not return; it could not be checked

INTEGRITY
  body digest: sha256:json-c14n:v1:74ebda8220c99bf3accddc1520aa8439fe61e3a37e4e84d4ac293bc30ad1565f
  ledger: namespace=citation-receipt rows=1 chain=12e7a237532ee8b9da7b337b305ec55a
  witness: local-file (none (self-controlled file))
  anchor: none status=skipped
```

The scope statement prints before the results. That ordering is
deliberate: the first thing anyone reading the exhibit sees is what the
document is not claiming, not the list of checks.

### Filing it as an exhibit

The exhibit is plain text. A clerk, a client, or opposing counsel can read
it without installing anything. Attach it the way you would attach any
other supporting document: `brief.exhibit.txt` next to `brief.receipt.json`.

### Verifying it without contacting us

A receipt that only we can check is not a receipt, it is a promise.
Every Citation Receipt carries a body digest (a sha256 hash over the
checks, the scope statement, and the issue time) and, when anchoring is
on, an OpenTimestamps proof of that digest. A verifier does not need our
API, our servers, or our cooperation:

```
arcaeon-receipt verify brief.receipt.json --ledger receipts.log.jsonl --ots
```

That command recomputes the body digest from the receipt's own fields,
walks the ledger to confirm sequence, and runs `ots verify` against the
attached OpenTimestamps proof, reconstructing the stamped file from the
receipt alone. Change one word in the scope statement, or one status in
the results, and the digest no longer matches. No call home required, by
design: the point of a receipt handed to a court is that the court does
not have to trust the party that produced it.

---

## What it does not do

Said once here plainly, because it is the whole product, not fine print:

- It does not check whether a case supports the argument it is cited for.
- It does not check whether a case is still good law.
- It does not check whether a quotation from a case is accurate.
- It does not catch a citation to a statute, a law journal, an "id.," or a
  "supra": CourtListener's citation parser does not look those up, so
  neither does this.
- It does not replace Shepard's or KeyCite, and it does not try to.

If a citation exists in CourtListener's database and was cited to say the
wrong thing, this receipt will say "found" and be entirely correct to say
so. Existence and correctness are different questions. This tool answers
one of them, honestly, and says which one on every page it produces.

---

## Sources

- [Standing Order Regarding the Use of Generative Artificial Intelligence, U.S. District Court, District of Colorado (Judge Nina Y. Wang), effective December 1, 2025](https://www.cod.uscourts.gov/Portals/0/Documents/Judges/NYW/NYW_Standing_Order_Regarding_AI_Certification.pdf)
- [Standing Order Re: Use of Artificial Intelligence, U.S. District Court, Western District of North Carolina, revised December 8, 2025](https://www.ncwd.uscourts.gov/news/standing-order-re-use-artificial-intelligence)
- [General Order 210: Filings Using Generative Artificial Intelligence, U.S. Bankruptcy Court, Southern District of California, effective January 1, 2026](https://www.casb.uscourts.gov/news/general-order-210-filings-using-generative-artificial-intelligence)
- [UNVERIFIED, secondary source, not a court docket] [The AI Sanction Wave: $145K in Q1 Penalties Signals Courts Have Lost Patience with GenAI Filing Failures](https://complexdiscovery.com/the-ai-sanction-wave-145k-in-q1-penalties-signals-courts-have-lost-patience-with-genai-filing-failures/)
- [UNVERIFIED, secondary source, not confirmed against the order text] [No Constitutional Problem with Compelling AI Disclosures in Court Filings (discussing Hessert v. Street Dog Coalition, D. Colo., decided 2026-04-21, upholding Judge Wang's standing order against First Amendment, due process, and equal protection challenges)](https://reason.com/volokh/2026/04/21/no-constitutional-problem-with-compelling-ai-disclosures-in-court-filings/)
