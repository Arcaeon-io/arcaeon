"""mcp_vet.verify_page: the page a stranger lands on from a badge (M38, 2026-09-02).

The badge is one image. It cannot carry the caveats, and a badge without caveats
is a certification in everything but name. This module renders the page the
badge's verify link is meant to point at: what the mark records, and, at
greater length, what it cannot prove.

Two rules keep this page honest by construction rather than by copy-editing:

1. The blind-spot list is NOT typed here. It is pulled from `grade.BLIND_SPOTS`
   at render time, so a scanner change moves the page in the same commit, and
   `test_verify_page.py` asserts the rendered list equals the constant word for
   word. A page that paraphrased the scanner's own admission would drift from it.
2. The header phrase is `badge.RECEIPTED_NOT_REVIEWED`, the same constant the
   badge draws, so the two surfaces cannot say different things about what the
   mark is.

URL shape: there is no verify URL yet. `receipts.py` leaves `verify_url` empty
until the hosted receipt lookup lands (R15), and `badge_report` accepts it as a
parameter. When the URL exists, this page is what should be served at it; until
then `render_verify_page()` returns a self-contained HTML string a caller may
write to disk or embed. No network, no JavaScript, no external assets.
"""
from __future__ import annotations

import html
from datetime import date

from . import __version__
from . import grade as _grade
from .badge import RECEIPTED_NOT_REVIEWED, FOOTER_LINE_1, FOOTER_LINE_2
from .checks import check_names
from .ts_checks import TS_CHECKS

# Marker comments around the generated list so a test (or a human with grep)
# can cut the exact rendered items out of the page without parsing HTML.
BLIND_SPOTS_BEGIN = "<!-- blind-spots: generated from grade.BLIND_SPOTS, do not edit -->"
BLIND_SPOTS_END = "<!-- /blind-spots -->"

# The four things the page must tell a stranger the badge cannot prove. Kept as
# data so the test can assert each one is present, and so the wording lives in
# exactly one place.
CANNOT_PROVE = (
    ("Static read only",
     "The scanner read the server's source bytes. It never ran them. Nothing the "
     "server does at runtime, in a container, behind a wrapper, or on a network, "
     "was observed."),
    ("Two checks on TypeScript",
     "On .ts and .js files exactly two checks run (audit-record and "
     "except-returns-success, both via tree-sitter). The rest of the Python battery "
     "does not run on TypeScript, and a mixed tree's receipt lists only the checks "
     "that ran on every file."),
    ("Blind spots are real and listed",
     "Every pattern below slips past the scanner with zero findings. A clean grade "
     "means none of the checks fired on these bytes, not that the server is clean. "
     "The list is generated from the scanner's own declaration, not retyped."),
    ("No runtime evidence",
     "The grade carries two separate fields: record_static (what the scanner "
     "inferred from bytes) and record_dynamic (what a runner observed). The badge "
     "draws them on two rows and never merges them. Unless the runtime row says a "
     "record was observed by a runner, nobody launched this server on your behalf."),
)


def blind_spot_items() -> list[str]:
    """The blind-spot strings the page renders, in the scanner's own order.
    This is the single source: the page calls it, and the test compares it
    to `grade.BLIND_SPOTS`."""
    return list(_grade.BLIND_SPOTS)


def _checks_line() -> str:
    py = ", ".join(check_names())
    ts = ", ".join(name for name, _ in TS_CHECKS)
    return f"Python battery: {py}. TypeScript/JavaScript: {ts}."


def render_verify_page(*, receipt_id: str = "", artifact_digest: str = "",
                       rendered_on: str | None = None) -> str:
    """Render the verify page as a self-contained HTML document.

    `receipt_id` and `artifact_digest` are optional and shown as-is when
    given; they are display only. This function does not look anything up and
    makes no claim about the receipt beyond echoing the identifiers it was
    handed."""
    when = rendered_on or date.today().isoformat()
    e = html.escape
    items = "\n".join(f"      <li>{e(s)}</li>" for s in blind_spot_items())
    cannot = "\n".join(
        f"    <h3>{e(title)}</h3>\n    <p>{e(body)}</p>" for title, body in CANNOT_PROVE
    )
    ident_rows = ""
    if receipt_id:
        ident_rows += f"      <tr><th>receipt</th><td><code>{e(receipt_id)}</code></td></tr>\n"
    if artifact_digest:
        ident_rows += f"      <tr><th>artifact</th><td><code>sha256:{e(artifact_digest)}</code></td></tr>\n"
    ident = (f"    <table>\n{ident_rows}    </table>\n" if ident_rows else
             "    <p><em>No receipt identifier was supplied to this page. Treat any badge "
             "that links here without one as unverified.</em></p>\n")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mcp-vet verify: {e(RECEIPTED_NOT_REVIEWED)}</title>
<style>
  body {{ font-family: system-ui, Segoe UI, Helvetica, Arial, sans-serif; max-width: 52rem;
         margin: 2rem auto; padding: 0 1rem; line-height: 1.45; color: #0f172a; }}
  h1 {{ font-size: 1.4rem; }} h2 {{ font-size: 1.15rem; margin-top: 2rem; }}
  h3 {{ font-size: 1rem; margin-bottom: 0.2rem; }}
  code {{ font-family: ui-monospace, Consolas, monospace; }}
  .lede {{ font-size: 1.05rem; border-left: 4px solid #0f172a; padding-left: 0.8rem; }}
  ol li {{ margin: 0.35rem 0; }}
  table th {{ text-align: left; padding-right: 1rem; }}
  footer {{ margin-top: 2.5rem; font-size: 0.85rem; color: #475569; }}
</style>
</head>
<body>
  <h1>mcp-vet scan report</h1>
  <p class="lede"><strong>{e(RECEIPTED_NOT_REVIEWED)}.</strong> {e(FOOTER_LINE_1.split(": ", 1)[1].capitalize())}
  {e(FOOTER_LINE_2)}</p>

  <h2>What this mark is</h2>
  <p>A receipt. It names the checks that ran, the bytes they ran on (by digest), the
  date, and the outcome of each check. That is the whole claim. Anyone with the same
  bytes and the same version of the scanner can re-run it and get the same result;
  that is what makes it verifiable and what limits what it means.</p>
{ident}
  <p>Checks in this version ({e(__version__)}): {e(_checks_line())}</p>

  <h2>What the badge cannot prove</h2>
{cannot}

  <h2>Blind spots, as the scanner declares them</h2>
  <p>Generated from <code>mcp_vet.grade.BLIND_SPOTS</code>. Each item is a pattern the
  scanner does not see. If the server does one of these, the grade does not know.</p>
{BLIND_SPOTS_BEGIN}
    <ol>
{items}
    </ol>
{BLIND_SPOTS_END}

  <h2>How to check it yourself</h2>
  <p>Install the same version, point <code>mcp_vet</code> at the same bytes, compare the
  findings and verdict to the receipt. If the digests differ, the receipt is about
  different bytes and says nothing about the ones you have.</p>

  <footer>Rendered {e(when)} by mcp_vet {e(__version__)}. No human reviewed the server this
  page describes. No runtime observation is implied unless the badge's runtime row states
  one.</footer>
</body>
</html>
"""
