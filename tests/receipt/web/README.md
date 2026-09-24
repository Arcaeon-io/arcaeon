# verify-receipt.html

A single self-contained, static HTML page for verifying an `arcaeon-receipt`
JSON file without installing anything. No server, no build step, no external
scripts or frameworks -- open it directly in a browser (`file://` works) or
serve it as a static asset.

```
open web/verify-receipt.html
```

Paste a receipt's JSON, or drop the `.json` file onto the page, and click
**Verify receipt**. Everything happens client-side:

- The body digest is recomputed from the seven body fields
  (`receipt_version`, `kind`, `issued_at`, `subject`, `checks`, `scope`,
  `extra`) using a hand-rolled canonicalizer that reproduces
  `arcaeon_ledger.digest_json`'s `json-c14n:v1` recipe byte for byte, then
  hashed with the browser's own `crypto.subtle.digest("SHA-256", ...)`. VERIFIED
  or BROKEN is shown with the reason (COULD NOT LOOK in a batch when a file
  will not open or parse).
- The scope block (what the receipt proves / does not prove) renders before
  the checks, matching `render_exhibit`'s own ordering in
  `arcaeon_receipt/core.py`.
- Checks render as a table; ledger, witness, and anchor fields render below.
- For an OpenTimestamps anchor (`anchor.ots_b64` present), the page offers
  the reconstructed `receipt.anchor` file (`body_digest + "\n"`) and the
  `.ots` proof as downloads, plus the exact `ots verify receipt.anchor.ots`
  command -- OTS verification itself is never run in the browser.
- For a `witness.kind == "local-file"` receipt, the page says plainly that
  the pin is self-controlled and proves nothing to a stranger. For
  `witness.kind == "hosted"`, it builds the
  `<url>/api/verify?ns=<namespace>&rows=<rows>&chain=<chain>` link for the
  reader to click -- it does not fetch it automatically.

This page never re-walks the issuer's ledger file (it was not given one) and
never contacts the issuer, the witness service, or anything else on its own;
the one link it builds is left for a human to click.

## The canonicalizer

The JS canonicalization code lives between two marker comments in
`verify-receipt.html`:

```
// C14N-START
...
// C14N-END
```

That block is pure and synchronous (no DOM, no network, no crypto) so it can
be extracted and run under plain Node, which is exactly what
`tests/test_verify_page_parity.py` does: it pulls the block out of the HTML
file and checks it against the vectors from `tools/c14n_vectors.py`.

Supported number shapes: JSON integers of any size (the literal digit text
is preserved exactly, matching Python's arbitrary-precision `int`), and any
finite JSON float that fits an IEEE-754 double, reformatted to Python's
`repr()` layout (fixed notation for roughly `1e-4 <= |x| < 1e16`, scientific
notation with a zero-padded signed exponent outside that range -- e.g.
`1.0`, `0.5`, `-2.25`, `1e+16`, `1e-07`). A float literal that overflows a
double to Infinity is refused loudly (matching `digest_json`'s own
`allow_nan=False` refusal) rather than silently mismatched.

If the `json-c14n` recipe is ever bumped to `v2` upstream, this page's
canonicalizer and the `sha256:json-c14n:v1:` prefix it hardcodes both need to
be updated to match -- `tests/test_verify_page_parity.py`'s Python-side leg
(which imports `arcaeon_ledger.digest_json` directly) will fail first and
say so.

# authorship-recorder.html

A single self-contained, static HTML page that records a writing session for
an Authorship Receipt (`arcaeon_receipt/authorship.py`), client-side. No
server, no build step -- open it directly (`file://` works) or serve it as a
static asset.

```
open web/authorship-recorder.html
```

Type or paste into the textarea; the page listens to the standard `input`
event and reads `event.inputType` to classify each change as `type`,
`paste` (`insertFromPaste` / `insertFromPasteAsQuotation` / `insertFromDrop`),
or `delete`, and inserts a synthetic `idle` event whenever the gap since the
last keystroke exceeds the idle threshold. This does not use the Clipboard
API (`navigator.clipboard`) or a `paste` event listener, so it is not subject
to clipboard-read permission prompts or denials -- `input`/`beforeinput`
fire on every edit regardless of clipboard permission state. Each event's
text span is digested in the browser (`crypto.subtle.digest`) and folded
into a running `rolling` hash the same way `authorship.AuthorshipSession
.event()` does server-side; the raw span text is never stored, only its
digest and length.

**Export**, not live ingestion: the page has no ledger and issues no
receipt itself. It writes a JSON file (author, document, the full event
list with span digests, the final text, and the declared `rolling_hash`) for
`arcaeon_receipt.authorship_ingest.from_export()` to turn into a real,
ledgered Authorship Receipt. `authorship_ingest.verify_export()` recomputes
the rolling hash from the export's own events and reports whether it matches
the export's declared value, independent of the page that produced it.
