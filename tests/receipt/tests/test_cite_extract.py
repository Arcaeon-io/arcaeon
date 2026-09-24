"""Tests for cite_extract: .txt/.md, .docx (built by hand with zipfile, no
python-docx dependency), and .pdf (via the PyMuPDF that's actually installed
here; the missing-dependency path is exercised by forcing the import to
fail rather than by uninstalling anything)."""
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import pytest

from arcaeon.record.receipt import cite_extract

_WORD_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"

_DOCUMENT_XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="{ns}">
<w:body>
{paragraphs}
</w:body>
</w:document>"""


def _make_docx(path: Path, paragraph_texts):
    body = []
    for text in paragraph_texts:
        body.append(f'<w:p><w:r><w:t xml:space="preserve">{text}</w:t></w:r></w:p>')
    xml = _DOCUMENT_XML_TEMPLATE.format(ns=_WORD_NS, paragraphs="\n".join(body))
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("[Content_Types].xml",
                    '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        zf.writestr("word/document.xml", xml)


def test_text_from_txt_reads_utf8_with_replace(tmp_path):
    p = tmp_path / "brief.txt"
    p.write_bytes("Citing Brown v. Board, 347 U.S. 483.".encode("utf-8") + b"\xff\xfe")
    text = cite_extract.text_from_path(p)
    assert "Brown v. Board" in text
    assert "�" in text  # the invalid bytes were replaced, not raised on


def test_text_from_md_same_as_txt(tmp_path):
    p = tmp_path / "notes.md"
    p.write_text("# Heading\n\nCiting 1 U.S. 1.\n", encoding="utf-8")
    assert cite_extract.text_from_path(p) == "# Heading\n\nCiting 1 U.S. 1.\n"


def test_text_from_docx_reads_paragraphs(tmp_path):
    p = tmp_path / "brief.docx"
    _make_docx(p, ["First paragraph citing 1 U.S. 1.", "Second paragraph citing 2 U.S. 2."])
    text = cite_extract.text_from_path(p)
    assert "First paragraph citing 1 U.S. 1." in text
    assert "Second paragraph citing 2 U.S. 2." in text
    # paragraphs come back separated so downstream paragraph-boundary
    # splitting (cite_batch.split_for_lookup) sees them as distinct.
    idx1 = text.index("First paragraph")
    idx2 = text.index("Second paragraph")
    assert "\n\n" in text[idx1:idx2]


def test_text_from_docx_multiple_runs_in_one_paragraph(tmp_path):
    p = tmp_path / "runs.docx"
    body = ('<w:p><w:r><w:t xml:space="preserve">Split </w:t></w:r>'
            '<w:r><w:t xml:space="preserve">across </w:t></w:r>'
            '<w:r><w:t xml:space="preserve">runs.</w:t></w:r></w:p>')
    xml = _DOCUMENT_XML_TEMPLATE.format(ns=_WORD_NS, paragraphs=body)
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("word/document.xml", xml)
    assert cite_extract.text_from_path(p) == "Split across runs."


def test_text_from_pdf_extracts_real_text(tmp_path):
    fitz = pytest.importorskip("fitz")
    p = tmp_path / "brief.pdf"
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Citing Brown v. Board, 347 U.S. 483 (1954).")
    doc.save(str(p))
    doc.close()
    text = cite_extract.text_from_path(p)
    assert "347 U.S. 483" in text


def test_text_from_pdf_missing_dependency_raises_clear_error(tmp_path, monkeypatch):
    p = tmp_path / "brief.pdf"
    p.write_bytes(b"%PDF-1.4 fake")
    monkeypatch.setitem(sys.modules, "fitz", None)  # forces ImportError on `import fitz`
    with pytest.raises(RuntimeError, match="pip install pymupdf"):
        cite_extract.text_from_path(p)


def test_unsupported_extension_raises_value_error(tmp_path):
    p = tmp_path / "brief.rtf"
    p.write_text("not supported", encoding="utf-8")
    with pytest.raises(ValueError):
        cite_extract.text_from_path(p)
