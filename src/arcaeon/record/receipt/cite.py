"""Citation Receipt: existence checks against CourtListener.

Buyer: a lawyer filing under an AI-disclosure order or standing order, who
must be able to show that every case citation in the brief was checked to
exist. Courts have sanctioned filings with fabricated citations; the
receipt is the paper the lawyer produces when asked "what did you do".

The wording is the product. This receipt attests EXISTENCE checks only:
the citation string was submitted to CourtListener's citation-lookup API
at a stated time and came back with a stated status. It never says a case
supports a proposition, is good law, or is quoted correctly. A citation
that exists can still be misused; that is the lawyer's job, and Shepard's
/ KeyCite's, and this receipt says so on its face.

API (wiki.free.law/c/courtlistener/help/api/rest/v4/citation-lookup, read
2026-09-11): POST https://www.courtlistener.com/api/rest/v4/citation-lookup/
with `text` (<= 64,000 chars), token auth, at most 250 citations looked up
per request, throttled at 60 valid citations per minute; excess citations
are parsed but returned with status 429 (NOT looked up). Per-citation
status: 200 found, 404 valid-but-not-in-database, 400 invalid reporter,
300 multiple matches. Statutes, law-journal, id. and supra cites are not
looked up at all.
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Optional

from arcaeon.record.ledger import digest_bytes

from .core import build_receipt, render_exhibit

KIND = "citation-existence"
API_URL = "https://www.courtlistener.com/api/rest/v4/citation-lookup/"
MAX_TEXT = 64000
MAX_LOOKUPS_PER_REQUEST = 250

STATUS_MAP = {200: "found", 404: "not_found", 400: "invalid_reporter",
              300: "ambiguous", 429: "not_checked_rate_limit"}
FLAGGED = ("not_found", "invalid_reporter", "not_recognized_by_service")

SCOPE = {
    "proves": [
        "Each citation listed below was submitted to the CourtListener citation-lookup service "
        "at the issue time shown, and the service returned the status recorded beside it.",
        "The results, the scope statement and the issue time were bound into this receipt at issue; "
        "any later change to any of them breaks the body digest.",
    ],
    "does_not_prove": [
        "That any cited authority supports the proposition it is cited for.",
        "That any cited authority is good law, current, unreversed, or quoted accurately. "
        "This is not Shepard's, KeyCite, or legal research of any kind.",
        "That the brief contains no other citations: only citations the service's parser detected "
        "were checked. Citation-shaped text the service did not return is listed as unrecognised and "
        "was not checked. Statutes, regulations, law-journal, id. and supra citations are never looked up.",
        "That a 'found' citation was cited correctly, or that a 'not found' citation is fabricated: "
        "CourtListener's coverage is broad but not complete, and a valid citation can be absent from it.",
    ],
    "method": "CourtListener citation-lookup API v4 (free.law), text mode; statuses mapped "
              "200 found / 404 not_found / 400 invalid_reporter / 300 ambiguous / 429 not_checked_rate_limit.",
}


def default_transport(text: str, *, token: Optional[str] = None, timeout: int = 60) -> list:
    """POST the text; return the API's list of citation objects. Raises on
    transport failure so the caller can decide; never guesses a status."""
    token = token or os.environ.get("COURTLISTENER_TOKEN", "")
    if not token:
        raise RuntimeError("COURTLISTENER_TOKEN not set; the citation-lookup API requires a token "
                           "(free account at courtlistener.com)")
    data = urllib.parse.urlencode({"text": text}).encode("utf-8")
    req = urllib.request.Request(API_URL, data=data, method="POST")
    req.add_header("Authorization", "Token " + token)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "arcaeon-receipt/cite")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def fixture_transport(path: str | Path) -> Callable[[str], list]:
    """A transport that replays a saved API response. Used by tests and by
    the offline demo; the receipt's extra.transport says so."""
    saved = json.loads(Path(path).read_text(encoding="utf-8"))

    def _t(text: str) -> list:
        return saved
    _t.__name__ = "fixture"
    return _t


def _check_from_api(obj: dict) -> dict:
    code = obj.get("status")
    status = STATUS_MAP.get(code, f"unknown_status_{code}")
    clusters = []
    for c in (obj.get("clusters") or [])[:3]:
        url = c.get("absolute_url") or c.get("url") or ""
        if url.startswith("/"):
            url = "https://www.courtlistener.com" + url
        clusters.append({"case_name": c.get("case_name") or c.get("caseName") or "",
                         "url": url})
    return {"citation": obj.get("citation"),
            "normalized": obj.get("normalized_citations") or [],
            "span": [obj.get("start_index"), obj.get("end_index")],
            "status": status, "api_status": code,
            "detail": obj.get("error_message") or "",
            "clusters": clusters,
            "flagged": status in FLAGGED}


# A conservative "citation-shaped" matcher: volume, one or more reporter
# tokens that each end in a period (U.S., Cal., F., Supp., Fak.), an optional
# series token (2d, 3d, 4th), and a page. It exists for one reason, found on
# the first live run (2026-09-11): the lookup service SILENTLY drops what its
# parser does not recognise. "12 Fak. 34" (an invented reporter) and
# "999 F.3d\n1234" (a real-looking cite broken across a line) came back as
# nothing at all, not as 400 or 404. A receipt that reported "7 detected, 7
# found" over a brief holding two fabrications would have been a clean bill
# for the exact document the product exists to catch. Silence is not a
# receipt; anything citation-shaped the service did not return is flagged
# as unrecognised and left for a human.
_CITE_SHAPE = re.compile(
    r"\b(\d{1,4})\s+((?:[A-Z][A-Za-z]{0,7}\.\s*)+(?:\d{1,2}(?:st|nd|rd|th|d)\.?\s*)?)(\d{1,5})\b")


def normalize_text(text: str) -> str:
    """Collapse all whitespace runs (including line breaks) to single spaces so a
    citation wrapped across a line is one token to the parser."""
    return re.sub(r"\s+", " ", text)


def _shape_key(volume: str, reporter: str, page: str) -> str:
    rep = re.sub(r"\s+", " ", reporter).strip()
    rep = re.sub(r"\.\s+", ".", rep)          # "U. S." -> "U.S."
    return f"{volume} {rep} {page}".replace("  ", " ")


def local_citations(text: str) -> list:
    """Every citation-shaped string in the (normalized) text, with its span."""
    out = []
    for m in _CITE_SHAPE.finditer(text):
        out.append({"citation": m.group(0).strip(), "key": _shape_key(m.group(1), m.group(2), m.group(3)),
                    "span": [m.start(), m.end()]})
    return out


def reconcile(checks: list, text: str) -> list:
    """Add a flagged 'not_recognized_by_service' check for every citation-shaped
    string the service did not return. Comparison is on a whitespace-and-
    period-normalized key so '347 U. S. 483' and '347 U.S. 483' agree."""
    seen = set()
    for c in checks:
        for s in [c.get("citation") or ""] + list(c.get("normalized") or []):
            m = _CITE_SHAPE.search(str(s))
            if m:
                seen.add(_shape_key(m.group(1), m.group(2), m.group(3)))
            seen.add(re.sub(r"\s+", " ", str(s)).strip())
    extra = []
    for lc in local_citations(text):
        if lc["key"] in seen or lc["citation"] in seen:
            continue
        extra.append({"citation": lc["citation"], "normalized": [], "span": lc["span"],
                      "status": "not_recognized_by_service", "api_status": None,
                      "detail": "citation-shaped text the lookup service did not return; it could not be "
                                "checked here and must be verified by hand",
                      "clusters": [], "flagged": True})
    return checks + extra


def check_citations(text: str, *, transport: Optional[Callable[[str], list]] = None) -> list:
    """Run the lookup on one block of text (<= 64k chars). Returns receipt
    checks: the service's results plus a flagged row for every citation-shaped
    string the service silently dropped. Longer texts are the caller's problem
    to split on paragraph boundaries; splitting inside a citation would
    produce a false not_found."""
    if len(text) > MAX_TEXT:
        raise ValueError(f"text is {len(text)} chars; the API caps a request at {MAX_TEXT}. Split on paragraph boundaries first.")
    transport = transport or default_transport
    norm = normalize_text(text)
    raw = transport(norm)
    if not isinstance(raw, list):
        raise ValueError("transport returned a non-list; refusing to build a receipt from it")
    checks = [_check_from_api(o) for o in raw if isinstance(o, dict)]
    return reconcile(checks, norm)


def summarize(checks: list) -> dict:
    counts: dict = {}
    for c in checks:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    return {"total": len(checks), "by_status": counts,
            "flagged": [c["citation"] for c in checks if c.get("flagged")],
            "not_checked": [c["citation"] for c in checks if c["status"].startswith("not_checked")]}


def citation_receipt(text: str, *, ledger_path: str | Path, namespace: str = "citation-receipt",
                     document_name: str = "", transport: Optional[Callable[[str], list]] = None,
                     witness: bool = True, anchor: bool = True) -> dict:
    checks = check_citations(text, transport=transport)
    summ = summarize(checks)
    subject = {"document": document_name or "(pasted text)",
               "document_sha256": digest_bytes(text.encode("utf-8")),
               "document_chars": len(text),
               "citations_detected": summ["total"],
               "citations_flagged": len(summ["flagged"]),
               "citations_not_checked": len(summ["not_checked"])}
    extra = {"summary": summ,
             "transport": getattr(transport, "__name__", "courtlistener-live") if transport else "courtlistener-live",
             "service": API_URL}
    return build_receipt(KIND, subject, checks, SCOPE, ledger_path=ledger_path,
                         namespace=namespace, extra=extra, witness=witness, anchor=anchor)


def _line(c: dict) -> str:
    mark = "!!" if c.get("flagged") else ("??" if c["status"] == "ambiguous" else "  ")
    tail = ""
    if c.get("clusters"):
        tail = "  -> " + c["clusters"][0]["case_name"]
    if c.get("detail") and not c.get("clusters"):
        tail = "  " + c["detail"][:80]
    return f"{mark} {c['status']:<24} {c['citation']}{tail}"


def exhibit(receipt: dict) -> str:
    return render_exhibit(receipt, title="CITATION EXISTENCE RECEIPT", check_line=_line)
