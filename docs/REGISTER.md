# The register page

The register of named operators (`arcaeon.prove.register`, design in
[design/REGISTER_REVOCATION.md](design/REGISTER_REVOCATION.md)) is one
append-only, hash-linked list of rows signed by the register operator key.
Like a Certificate Transparency log names who runs each log, the register
names each operator and the keys, chains and witness endpoints it holds. The
page is that register as something a person can read.

```console
$ arcaeon register page register.jsonl --operator-key did:key:z6Mk... --out page.html
register VERIFIED: 4 rows, linked and signed by the operator key you named; head sha256:json-c14n:v1:2d3c...
wrote page.html
```

`register.jsonl` is the register's rows, one JSON object per line (a JSON
array is read too). `--operator-key` names the register operator key you
trust; it is repeatable and it comes from you, never from the rows. Without
`--out` the page goes to stdout and the verdict line to stderr. `--out` is
never overwritten. Library: `arcaeon.prove.register_page.render_page(rows,
operator_keys=[...], source=None)`.

## What the page shows

At the top, the verdict of checking the register itself (`check_register`):

- **VERIFIED**: every row in place, linked and signed by a key you named.
  The page then lists the head digest and the row count, and for each
  operator (by name and account) every key (its did:key and its register
  digest), chain and witness endpoint, when it was added, and whether it is
  current or REVOKED (when, the reason and, for `key_compromise`, compromised
  since). Then the witness endpoints across operators and every revocation
  row. Publishing cadence reads "not stated": the register's rows carry none.
  With `--pin-log MEMBER=FILE` (see below) it reads what a pin log shows.
- **BROKEN**: the reason (which row, and why). No row is shown, not the rows
  past the break and not the rows before it as the register's word: a
  register that does not check as a whole names no one. No head is given.
- **COULD NOT LOOK**: no rows, no operator key named, or no Ed25519 backend.
  The reason, and no rows.

The page is static: inline CSS, no script, no link, no image, no font,
nothing fetched. Every value is HTML-escaped (the tally page's escaping). The
same register and the same named keys give the same bytes; nothing on it
depends on the clock or on where the file sits.

## Publishing cadence from a pin log

```console
$ arcaeon register page register.jsonl --operator-key did:key:z6Mk... --pin-log acct:operator-a@arcaeon.io=witness_pin_log.jsonl --out page.html
```

`--pin-log MEMBER=FILE` (repeatable) names the log a member's pin task
writes: JSONL, one row per pin, with its time in the first of `at`,
`pinned_at`, `ts`, `timestamp`, `time` (RFC 3339 with a zone, `Z` or an
offset). A pin task logs every run, so a row with an `outcome` counts only
when it is `pinned` (a `nothing-new` run pinned nothing), and a row with a
non-zero `exit_code` never counts. Rows with neither field count as pins.
A bare `FILE` is read only when the register names one member.
From the newest 10 dated rows the member's line says, for example,
"publishing cadence: observed every ~6 hours (last 10 pins) in the pin log
witness_pin_log.jsonl, latest pin 2026-10-05T18:00:00Z". N is the median gap
between those pins, in whole hours from 2 hours up and to one decimal under
that. It is what the log shows, not a promise, and the log is the pinner's
own record. A log that is missing, not UTF-8, over 16 MiB, or with fewer than
two rows with a zoned time keeps "not stated", and a bare log with more than
one member is not given to any of them. Nothing is guessed. The page names
the log by its file name only, so the same register and the same log give the
same bytes.

Exit codes: 0 VERIFIED, 1 BROKEN, 3 COULD NOT LOOK (the page is written in
all three; a file that is missing or not JSON writes nothing and is 3), 2
bad usage or `--out` exists.

## What this page cannot tell you

The page shows what the register's signed rows say, in one copy of the
register, and nothing more. It cannot show that a named operator is who they
claim to be offline, that a key was never copied, that a time a row states is
true, or that this copy is the newest one: a revocation written after it is
not seen. A reader checks the chain themselves, from the register file and
the operator key they trust, with the command above; it prints the verdict
and writes the same page byte for byte.
