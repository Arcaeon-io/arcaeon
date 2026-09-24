"""cite_batch.py: batching layer over cite.check_citations for texts longer
than the API's 64,000-char cap, plus bounded retry-on-rate-limit.

cite.check_citations refuses text over MAX_TEXT and tells the caller to
split on paragraph boundaries; this module does that split, walks the
chunks, and re-bases each chunk's checks -- whose spans are chunk-local --
back onto the full text's offsets, so a receipt built from a batched brief
looks exactly like one built from a brief that fit in a single request.

CourtListener throttles at 60 valid citations per minute even though a
single request can carry up to 250 (cite.py's docstring); excess citations
come back with status 429, mapped by cite.STATUS_MAP to
"not_checked_rate_limit". Rather than re-submit the whole chunk a
rate-limited citation happened to live in -- which could hold many other,
already-checked citations -- this module waits and resubmits ONLY the
paragraph(s) that citation's span falls inside. Retries are bounded
(MAX_RETRY_ROUNDS); anything still rate-limited after that stays marked
not_checked_rate_limit, so the receipt says so rather than guessing.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from arcaeon.record.ledger import digest_bytes

from . import cite
from .core import build_receipt

MAX_RETRY_ROUNDS = 3

# CourtListener's documented throttle (see cite.py's module docstring): 60
# valid citations per minute. A caller who configures a smaller per_minute
# budget is telling us the window effectively refills more slowly, so the
# wait before a retry scales inversely against that assumption.
_API_PER_MINUTE = 60


def _paragraphs(text: str) -> List[str]:
    """Split text into paragraphs that, joined, reconstruct it exactly. A
    paragraph ends at a blank line; consecutive blank lines stay attached to
    the paragraph that precedes them, so every boundary this module ever
    cuts on lands between paragraphs -- never inside a line."""
    if not text:
        return []
    lines = text.splitlines(keepends=True)
    paras: List[str] = []
    current: List[str] = []
    for line in lines:
        current.append(line)
        if line.strip("\r\n") == "":
            paras.append("".join(current))
            current = []
    if current:
        paras.append("".join(current))
    return paras


def _split_oversize_paragraph(para: str, max_chars: int) -> List[str]:
    """A single paragraph longer than max_chars, with no blank line to
    break on: fall back to line boundaries. Still never splits inside a
    line -- if one line alone exceeds max_chars it is kept whole rather
    than truncated mid-line, which would only produce a false not_found."""
    lines = para.splitlines(keepends=True)
    pieces: List[str] = []
    buf = ""
    for line in lines:
        if buf and len(buf) + len(line) > max_chars:
            pieces.append(buf)
            buf = ""
        buf += line
    if buf:
        pieces.append(buf)
    return pieces or [para]


def _paragraph_offsets(paragraphs: List[str]) -> List[int]:
    offsets = []
    pos = 0
    for p in paragraphs:
        offsets.append(pos)
        pos += len(p)
    return offsets


def _group_paragraphs(paragraphs: List[str], para_offsets: List[int],
                      max_chars: int) -> List[Tuple[str, int]]:
    """Group paragraphs into chunks <= max_chars. Returns (chunk_text,
    chunk_offset) pairs -- chunk_offset computed directly, not derived from
    a paragraph index, because an oversized paragraph can itself produce
    several chunks at different offsets within it (see
    _split_oversize_paragraph); deriving from the paragraph's own start
    offset would rebase every one of those pieces to the same (wrong)
    place except the first."""
    groups: List[Tuple[str, int]] = []
    buf = ""
    buf_offset = 0
    for para, para_offset in zip(paragraphs, para_offsets):
        if len(para) > max_chars:
            if buf:
                groups.append((buf, buf_offset))
                buf = ""
            off = para_offset
            for sub in _split_oversize_paragraph(para, max_chars):
                groups.append((sub, off))
                off += len(sub)
            continue
        if buf and len(buf) + len(para) > max_chars:
            groups.append((buf, buf_offset))
            buf = para
            buf_offset = para_offset
        else:
            if not buf:
                buf_offset = para_offset
            buf += para
    if buf:
        groups.append((buf, buf_offset))
    return groups


def split_for_lookup(text: str, max_chars: int = 64000) -> List[str]:
    """Split text into chunks each <= max_chars, breaking only at paragraph
    boundaries and never inside a line. (A single paragraph -- or, failing
    that, a single line -- that alone exceeds max_chars is kept whole
    rather than cut mid-line.) Concatenating the result reproduces text
    exactly."""
    paragraphs = _paragraphs(text)
    if not paragraphs:
        return []
    offsets = _paragraph_offsets(paragraphs)
    return [g[0] for g in _group_paragraphs(paragraphs, offsets, max_chars)]


def _rebase(check: dict, offset: int) -> dict:
    c = dict(check)
    span = c.get("span")
    if isinstance(span, (list, tuple)) and len(span) == 2 and span[0] is not None and span[1] is not None:
        c["span"] = [span[0] + offset, span[1] + offset]
    return c


def _paragraph_index_for_offset(para_offsets: List[int], para_lens: List[int], offset: int) -> Optional[int]:
    for i, (start, length) in enumerate(zip(para_offsets, para_lens)):
        if start <= offset < start + length:
            return i
    return None


def _units_in_paragraph(para_text: str, para_offset: int, max_chars: int) -> List[Tuple[str, int]]:
    """(unit_text, unit_offset) pairs covering one paragraph, each
    resubmittable on its own (<= max_chars). Almost always a single unit --
    the whole paragraph; only an oversized paragraph (already itself
    line-split for the initial submission) needs more than one."""
    if len(para_text) <= max_chars:
        return [(para_text, para_offset)]
    units: List[Tuple[str, int]] = []
    off = para_offset
    for piece in _split_oversize_paragraph(para_text, max_chars):
        units.append((piece, off))
        off += len(piece)
    return units


def _sort_key(c: dict):
    span = c.get("span")
    return span[0] if span and span[0] is not None else 0


def check_citations_batched(text: str, *, transport: Callable[[str], list],
                            per_minute: int = 60, per_request: int = 250,
                            sleep: Callable[[float], None] = time.sleep) -> list:
    """Like cite.check_citations, but for text of any length. Splits on
    paragraph boundaries (split_for_lookup's logic), submits each chunk
    through cite.check_citations, and re-bases every check's span from
    chunk-local to full-text offsets.

    On any check with status not_checked_rate_limit, waits (sized against
    per_minute) and resubmits only the paragraph(s) holding the affected
    citation(s) -- never the whole chunk that paragraph came from. Bounded
    to MAX_RETRY_ROUNDS; whatever is still not_checked_rate_limit after
    that stays that way in the returned list, honestly.

    per_request mirrors cite.MAX_LOOKUPS_PER_REQUEST for interface
    symmetry with the API's own cap; chunking is already sized in
    characters (via max_chars), which for real briefs keeps citation
    counts per request well under it.
    """
    paragraphs = _paragraphs(text)
    if not paragraphs:
        return []
    para_offsets = _paragraph_offsets(paragraphs)
    para_lens = [len(p) for p in paragraphs]

    groups = _group_paragraphs(paragraphs, para_offsets, cite.MAX_TEXT)
    checks: list = []
    for chunk_text, offset in groups:
        raw = cite.check_citations(chunk_text, transport=transport)
        checks.extend(_rebase(c, offset) for c in raw)

    wait_seconds = 60.0 * (_API_PER_MINUTE / per_minute) if per_minute > 0 else 60.0

    for _round in range(MAX_RETRY_ROUNDS):
        limited = [c for c in checks if c.get("status") == "not_checked_rate_limit"]
        if not limited:
            break
        hot_paras = set()
        for c in limited:
            span = c.get("span")
            if not span or span[0] is None:
                continue
            idx = _paragraph_index_for_offset(para_offsets, para_lens, span[0])
            if idx is not None:
                hot_paras.add(idx)
        if not hot_paras:
            break
        sleep(wait_seconds)
        for idx in sorted(hot_paras):
            for unit_text, unit_offset in _units_in_paragraph(paragraphs[idx], para_offsets[idx], cite.MAX_TEXT):
                if not unit_text.strip():
                    continue
                raw = cite.check_citations(unit_text, transport=transport)
                fresh = [_rebase(c, unit_offset) for c in raw]
                u_start, u_end = unit_offset, unit_offset + len(unit_text)
                checks = [c for c in checks
                         if not (c.get("span") and c["span"][0] is not None
                                 and u_start <= c["span"][0] < u_end)]
                checks.extend(fresh)

    checks.sort(key=_sort_key)
    return checks


def citation_receipt_batched(text: str, *, ledger_path: str | Path, namespace: str = "citation-receipt",
                             document_name: str = "", transport: Optional[Callable[[str], list]] = None,
                             per_minute: int = 60, per_request: int = 250,
                             sleep: Callable[[float], None] = time.sleep,
                             witness: bool = True, anchor: bool = True) -> dict:
    """cite.citation_receipt's shape, using check_citations_batched so a
    brief longer than 64k chars (or one that trips the per-minute throttle
    partway through) still produces one receipt over the whole document."""
    resolved = transport or cite.default_transport
    checks = check_citations_batched(text, transport=resolved, per_minute=per_minute,
                                     per_request=per_request, sleep=sleep)
    summ = cite.summarize(checks)
    subject = {"document": document_name or "(pasted text)",
               "document_sha256": digest_bytes(text.encode("utf-8")),
               "document_chars": len(text),
               "citations_detected": summ["total"],
               "citations_flagged": len(summ["flagged"]),
               "citations_not_checked": len(summ["not_checked"])}
    extra = {"summary": summ,
             "transport": getattr(transport, "__name__", "courtlistener-live") if transport else "courtlistener-live",
             "service": cite.API_URL,
             "batched": True}
    return build_receipt(cite.KIND, subject, checks, cite.SCOPE, ledger_path=ledger_path,
                         namespace=namespace, extra=extra, witness=witness, anchor=anchor)
