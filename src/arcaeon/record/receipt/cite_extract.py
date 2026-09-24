"""cite_extract.py: pull plain text out of the file formats a lawyer's
brief actually shows up in, so cite.check_citations / cite_batch can run
against it without anyone copy-pasting first.

.txt / .md are read as utf-8 with errors="replace" (never raise on a
mis-encoded filing). .pdf goes through PyMuPDF (`import fitz`), an optional
dependency this package does not require at install time; if it is missing
we raise a RuntimeError that names the exact pip command rather than
letting an ImportError leak out. .docx is read with the standard library
only -- zipfile plus xml.etree over word/document.xml -- since a .docx is
just a zip of XML and pulling the run text out of its <w:p> paragraphs
needs nothing else.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

_WORD_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _text_from_txt(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _text_from_pdf(path: Path) -> str:
    try:
        import fitz  # PyMuPDF
    except ImportError as e:
        raise RuntimeError(
            "reading .pdf files needs PyMuPDF: pip install pymupdf"
        ) from e
    parts = []
    doc = fitz.open(str(path))
    try:
        for page in doc:
            parts.append(page.get_text())
    finally:
        doc.close()
    return "\n\n".join(parts)


def _text_from_docx(path: Path) -> str:
    """Read word/document.xml directly: walk <w:p> paragraphs, join each
    paragraph's <w:t> run text, and join paragraphs with a blank line so
    cite_batch.split_for_lookup sees the same paragraph boundaries a human
    reading the document would."""
    with zipfile.ZipFile(path) as zf:
        xml_bytes = zf.read("word/document.xml")
    root = ET.fromstring(xml_bytes)
    paragraphs = []
    for p in root.iter(_WORD_NS + "p"):
        runs = [t.text or "" for t in p.iter(_WORD_NS + "t")]
        paragraphs.append("".join(runs))
    return "\n\n".join(paragraphs)


_READERS = {
    ".txt": _text_from_txt,
    ".md": _text_from_txt,
    ".pdf": _text_from_pdf,
    ".docx": _text_from_docx,
}


def text_from_path(path: str | Path) -> str:
    """Dispatch on suffix (case-insensitive). Raises ValueError for any
    extension this module does not know how to read."""
    p = Path(path)
    reader = _READERS.get(p.suffix.lower())
    if reader is None:
        raise ValueError(f"unsupported file type {p.suffix!r}; supported: {sorted(_READERS)}")
    return reader(p)
