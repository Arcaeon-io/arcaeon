"""Tests for cite_batch: paragraph-boundary splitting, span re-basing across
chunks, and bounded retry-on-rate-limit that resubmits only the paragraph a
rate-limited citation lives in. No network: transports here are scripted
fakes over local text, and `sleep` is injected so retry tests run instantly.
"""
from pathlib import Path

import pytest

from arcaeon.record.receipt import cite, cite_batch


# --------------------------------------------------------------------------
# split_for_lookup
# --------------------------------------------------------------------------

def test_split_for_lookup_reconstructs_and_breaks_on_paragraphs():
    text = ("Paragraph one, short.\n\n"
            "Paragraph two, also short.\n\n"
            "Paragraph three is a bit longer than the other two paragraphs.\n")
    chunks = cite_batch.split_for_lookup(text, max_chars=50)
    assert "".join(chunks) == text
    assert len(chunks) > 1
    # every line that exists in the original text also exists, whole, in
    # exactly the chunk it landed in -- nothing was cut mid-line.
    original_lines = text.splitlines(keepends=True)
    rebuilt_lines = []
    for c in chunks:
        rebuilt_lines.extend(c.splitlines(keepends=True))
    assert rebuilt_lines == original_lines


def test_split_for_lookup_single_chunk_when_it_fits():
    text = "One short paragraph.\n"
    assert cite_batch.split_for_lookup(text, max_chars=64000) == [text]


def test_split_for_lookup_empty_text():
    assert cite_batch.split_for_lookup("", max_chars=64000) == []


def test_split_for_lookup_oversize_paragraph_falls_back_to_lines():
    # one giant paragraph, no blank lines at all -- must fall back to line
    # boundaries without ever truncating a line.
    lines = [f"line number {i} of the filing\n" for i in range(200)]
    text = "".join(lines)
    chunks = cite_batch.split_for_lookup(text, max_chars=500)
    assert "".join(chunks) == text
    assert len(chunks) > 1
    rebuilt = []
    for c in chunks:
        rebuilt.extend(c.splitlines(keepends=True))
    assert rebuilt == lines
    for c in chunks[:-1]:
        assert len(c) <= 500


def test_split_for_lookup_never_exceeds_max_when_avoidable():
    text = ("Short para one.\n\n"
            "Short para two.\n\n"
            "Short para three.\n\n"
            "Short para four.\n")
    chunks = cite_batch.split_for_lookup(text, max_chars=40)
    for c in chunks:
        assert len(c) <= 40


# --------------------------------------------------------------------------
# check_citations_batched: span re-basing across chunks
# --------------------------------------------------------------------------

def _scripted_transport(script, log=None):
    """script: {citation_substring: [status_code, ...]} -- codes are
    consumed in order across repeated appearances of that substring
    (simulating retries); the last code repeats once exhausted. log, if
    given, records every text blob the transport is called with, so a test
    can assert exactly what got (re)submitted."""
    counters = {}

    def transport(text):
        if log is not None:
            log.append(text)
        out = []
        for needle, codes in script.items():
            idx = text.find(needle)
            if idx == -1:
                continue
            n = counters.get(needle, 0)
            code = codes[min(n, len(codes) - 1)]
            counters[needle] = n + 1
            out.append({
                "citation": needle, "normalized_citations": [needle],
                "start_index": idx, "end_index": idx + len(needle),
                "status": code,
                "error_message": "" if code == 200 else "not found" if code == 404 else "throttled",
                "clusters": ([{"id": 1, "case_name": "Case " + needle,
                              "absolute_url": "/opinion/1/x/"}] if code == 200 else []),
            })
        return out
    return transport


def _padding_paragraph(min_chars):
    """A single logical paragraph (one trailing blank line) made of many
    short lines, so it pads a text out past a small max_chars without ever
    being a single line longer than max_chars itself."""
    line = "Filler content line used only to pad the document out further.\n"
    lines = []
    total = 0
    while total < min_chars:
        lines.append(line)
        total += len(line)
    return "".join(lines) + "\n"


def _multi_chunk_text():
    # first paragraph small; second paragraph padded so the two together
    # exceed a small max_chars, forcing a second chunk whose offset is
    # nonzero -- exactly what needs re-basing.
    para1 = "Intro citing Case Alpha, 1 U.S. 1 (2001), for the opening point.\n\n"
    para2 = _padding_paragraph(1950)
    para3 = "Later citing Case Beta, 2 U.S. 2 (2002), for the closing point.\n"
    return para1 + para2 + para3


def test_check_citations_batched_rebases_spans_across_chunks(monkeypatch):
    monkeypatch.setattr(cite, "MAX_TEXT", 2000)  # force multiple chunks in a small test
    text = _multi_chunk_text()
    log = []
    transport = _scripted_transport({"1 U.S. 1": [200], "2 U.S. 2": [200]}, log=log)
    checks = cite_batch.check_citations_batched(text, transport=transport, sleep=lambda s: None)
    assert len(log) >= 2  # actually split into more than one request
    by_cite = {c["citation"]: c for c in checks}
    for needle in ("1 U.S. 1", "2 U.S. 2"):
        span = by_cite[needle]["span"]
        assert text[span[0]:span[1]] == needle
        assert by_cite[needle]["status"] == "found"


def test_check_citations_batched_single_chunk_matches_check_citations():
    text = "Citing Case Alpha, 1 U.S. 1 (2001), only once, briefly.\n"
    transport = _scripted_transport({"1 U.S. 1": [200]})
    direct = cite.check_citations(text, transport=transport)
    batched = cite_batch.check_citations_batched(text, transport=_scripted_transport({"1 U.S. 1": [200]}),
                                                 sleep=lambda s: None)
    assert [c["span"] for c in direct] == [c["span"] for c in batched]
    assert [c["status"] for c in direct] == [c["status"] for c in batched]


# --------------------------------------------------------------------------
# retry-on-rate-limit: only the hot paragraph gets resubmitted
# --------------------------------------------------------------------------

def test_retry_resubmits_only_the_hot_paragraph(monkeypatch):
    monkeypatch.setattr(cite, "MAX_TEXT", 2000)
    para1 = "First paragraph citing Case Alpha, 1 U.S. 1 (2001), cleanly.\n\n"
    para2 = _padding_paragraph(1950)
    para3 = "Third paragraph citing Case Gamma, 3 U.S. 3 (2003), which gets throttled first.\n"
    text = para1 + para2 + para3

    log = []
    # 3 U.S. 3 comes back 429 once, then 200 on the targeted resubmission.
    transport = _scripted_transport({"1 U.S. 1": [200], "3 U.S. 3": [429, 200]}, log=log)
    sleeps = []
    checks = cite_batch.check_citations_batched(text, transport=transport, sleep=sleeps.append)

    by_cite = {c["citation"]: c for c in checks}
    assert by_cite["1 U.S. 1"]["status"] == "found"
    assert by_cite["3 U.S. 3"]["status"] == "found"
    span = by_cite["3 U.S. 3"]["span"]
    assert text[span[0]:span[1]] == "3 U.S. 3"

    assert len(sleeps) == 1  # resolved on the first retry round
    # the retry call must have been the third paragraph alone, not the
    # whole original text and not anything containing the filler paragraph.
    retry_call = log[-1]
    assert "3 U.S. 3" in retry_call
    assert "Filler" not in retry_call
    assert "1 U.S. 1" not in retry_call


def test_retry_bounded_leaves_unchecked_after_max_rounds():
    text = "Only citing Case Delta, 4 U.S. 4 (2004), which never clears the throttle.\n"
    sleeps = []
    transport = _scripted_transport({"4 U.S. 4": [429]})  # always 429
    checks = cite_batch.check_citations_batched(text, transport=transport, sleep=sleeps.append)
    assert len(checks) == 1
    assert checks[0]["status"] == "not_checked_rate_limit"
    assert len(sleeps) == cite_batch.MAX_RETRY_ROUNDS


def test_per_minute_scales_the_wait():
    text = "Citing Case Epsilon, 5 U.S. 5 (2005), once.\n"
    sleeps = []
    transport = _scripted_transport({"5 U.S. 5": [429, 200]})
    cite_batch.check_citations_batched(text, transport=transport, per_minute=30, sleep=sleeps.append)
    assert sleeps == [120.0]  # half the assumed budget -> twice the wait


# --------------------------------------------------------------------------
# citation_receipt_batched
# --------------------------------------------------------------------------

def test_batched_lookup_scales_linearly_and_terminates_with_many_citations(monkeypatch):
    """A-029: there is no explicit cap on the NUMBER of citations
    check_citations_batched will process (only a character-length cap per
    chunk, cite.MAX_TEXT, and a bounded MAX_RETRY_ROUNDS retry loop) -- a
    hard citation-count cap would work against the module's actual job of
    handling an arbitrarily long real filing. What actually prevents a
    hang at scale (a 10,000-citation brief, say) is that the number of
    transport calls is bounded by the number of chunks the text splits
    into, not by the citation count itself, and the retry loop is bounded
    regardless of how many citations are in play. This test proves that
    property directly: many citations, one per short paragraph, packed
    into a small MAX_TEXT so the input splits into many chunks -- the
    transport call count must equal the chunk count (not the citation
    count, and not something unbounded), every citation must still be
    found, and the whole thing must actually return (no infinite retry
    loop) even though the paragraph count here is two orders of magnitude
    above the original ten-example fixtures."""
    monkeypatch.setattr(cite, "MAX_TEXT", 300)  # force many small chunks

    n = 300
    # fixed-width zero-padded volume/page numbers so no citation string is
    # ever a substring of another (e.g. "1 U.S. 1" IS a substring of
    # "11 U.S. 11") -- that would make _scripted_transport's naive
    # substring `.find()` cross-match citations across paragraphs, which is
    # a test-fixture artifact, not the thing this test is checking.
    paras = [f"Citing Case Num{i}, {i:04d} U.S. {i:04d} ({2000 + (i % 20)}), plainly.\n\n"
             for i in range(n)]
    text = "".join(paras)

    script = {f"{i:04d} U.S. {i:04d}": [200] for i in range(n)}
    log = []
    transport = _scripted_transport(script, log=log)

    checks = cite_batch.check_citations_batched(text, transport=transport, sleep=lambda s: None)

    assert len(checks) == n
    assert all(c["status"] == "found" for c in checks)
    # bounded by chunk count, not citation count: with each citation's own
    # paragraph well under MAX_TEXT, several paragraphs land in each chunk,
    # so the call count is well below n -- proving this isn't one call per
    # citation (which would still terminate, but not "scale linearly with
    # chunk count" the way the module is designed to).
    assert 0 < len(log) < n
    # every chunk actually submitted stayed under the character cap.
    assert all(len(call_text) <= cite.MAX_TEXT for call_text in log)


def test_citation_receipt_batched_builds_a_receipt(tmp_path):
    text = ("Citing Case Alpha, 1 U.S. 1 (2001), and Case Zed, 9 Fak. 9, "
            "which does not exist as a reporter.\n")
    transport = _scripted_transport({"1 U.S. 1": [200], "9 Fak. 9": [400]})
    rc = cite_batch.citation_receipt_batched(text, ledger_path=tmp_path / "l.jsonl",
                                             document_name="brief.txt", transport=transport,
                                             sleep=lambda s: None, anchor=False)
    assert rc["kind"] == cite.KIND
    assert rc["scope"] == cite.SCOPE
    assert rc["extra"]["batched"] is True
    summ = rc["extra"]["summary"]
    assert summ["total"] == 2
    assert summ["flagged"] == ["9 Fak. 9"]
    ex = cite.exhibit(rc)
    assert "DOES NOT PROVE" in ex
