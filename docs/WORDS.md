# The words

Every arcaeon check answers in one of a few fixed words, and the words mean
the same thing in every verb. This page is for the person who reads the
answer, not the one who wired it up: what each word tells you, and what to do
about it. The exit code for each word is in the README's exit-code table.

## Verdict words

**VERIFIED.** Every row of the record was checked and the chain holds from the
first row to the last. Nobody changed, removed or reordered a row in the middle
since it was written; cutting rows off the end needs a pin to catch.

**BROKEN.** The check found a row that no longer matches the chain, and it
names the line. Someone or something changed the record after it was written,
so treat what follows that line as unconfirmed until you know why.

**COULD NOT LOOK.** Nothing wrong was found, but not everything could be
checked: a file was missing, unreadable or empty, or part of it sat outside
what the check can see. It is never a pass; find out what was not looked at
before you sign off.

**MATCHED.** Two records of the same work (the agent's tape and the tool's
tape, or a buyer's and a seller's) agree on every step both were expected to
hold. Agreement is what it shows, not truth: two sides run by one party can
agree on a lie.

**MISSING.** A step one record holds has no partner on the other, or a record
holds fewer rows than a pin says it once had. Something was not written down,
or was taken out afterwards.

**ALTERED.** Both records hold the step, but its contents differ between them,
and the check names the fields. One side wrote something different from the
other, and a person has to decide which one is right.

**NO GRADEABLE FILES.** The source grader (`vet`, `badge`, `seal`) found no
file it knows how to read. It is a could-not-look, not a clean grade: nothing
was graded, so nothing was cleared.

**COMPARED.** Two readings ledgers (`second-read compare A B`) were both read
and lined up, claim by claim, against one frozen sentence. It means "both
ledgers were read and lined up", never "the claims are true". Claims the two
readers answered differently are filed as DISAGREED beside it, with both
readings and both reader ids; two readers agreeing measures how ambiguous the
sentence was for them, not whether a claim holds.

## Reason words

A COULD NOT LOOK answer carries one of these in `reason_word`, next to
`looked_for` (what the check wanted) and `where` (where it looked), so a
script can branch on the cause without reading the sentence.

- `unreadable`: the thing was there but could not be read (no permission, not text, not valid JSON, a directory).
- `missing`: the file or record was not there at all.
- `empty`: it was there and held nothing to check.
- `name_not_found`: the file was read, but the name the check needed (a key, a namespace, a record) was not in it.
- `bounded`: only part of it could be checked, for example rows written before the chain began, so the answer covers less than the whole.
- `network`: the request to the hosted witness never completed, so the answer is unknown, not no.
- `redirect_refused`: the endpoint answered with a redirect to another address. It was not followed and the key was not sent there, so there is no answer to record.

## Bearer words

Every sentence on an evidence pack's first page ends in one of these, in
square brackets, naming what bears it. The full definitions are in
[What it can and cannot prove](WHAT_IT_CAN_AND_CANNOT_PROVE.md).

- `bytes`: a hash over frozen content proves it, the manifest hashes and the chain.
- `order`: only a commitment made before the act proves it, the witness pin and the build time against the pin time.
- `asserted`: no field carries it, the operator's own statement of the window and the system, the completeness of the could not look list, that any row is true.

## Many logs at once

A summary over many logs keeps these words side by side: so many VERIFIED, so
many BROKEN, so many COULD NOT LOOK. It never folds them into one rate, because
a file nobody could read is neither a pass nor a break.
