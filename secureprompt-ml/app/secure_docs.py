"""In-document redaction for DOCX / XLSX / TXT — replace PII strings with
`{{Type_N}}` labels so the underlying text is genuinely removed."""
from __future__ import annotations

import io
from typing import Callable

from app.secure_labels import build_labels, redact_text


def _set_paragraph_text(paragraph, text: str) -> None:
    """Put `text` in the first direct run (keeps its formatting), blank the rest.

    PII inside ``<w:hyperlink>`` runs is NOT part of ``paragraph.runs`` even
    though it IS part of ``paragraph.text`` — so we must blank hyperlink-nested
    runs too, else the original hyperlinked PII survives in the file (a security
    hole for a redaction control). PII that spanned multiple runs is flattened to
    run[0]'s style, and a redacted hyperlink loses its link formatting — both are
    v1 limitations; text removal (the security property) is unaffected.
    """
    for hl in paragraph.hyperlinks:
        for r in hl.runs:
            r.text = ""
    direct = paragraph.runs
    if direct:
        direct[0].text = text
        for r in direct[1:]:
            r.text = ""
    elif text:
        paragraph.add_run(text)


def _iter_paragraphs(doc):
    for p in doc.paragraphs:
        yield p
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    yield p


def secure_docx(data: bytes, detect_fn: Callable[[str], list[dict]]):
    import docx
    doc = docx.Document(io.BytesIO(data))
    paras = list(_iter_paragraphs(doc))
    full = "\n".join(p.text for p in paras)
    dets = detect_fn(full)
    labels = build_labels(dets)
    # Detection saw the joined document, but redaction is a per-paragraph substring
    # replace — so a PII value straddling a paragraph/cell boundary won't match
    # verbatim in any single paragraph. v1 assumes each PII value lies within one
    # paragraph (true for names/emails/ids; multi-paragraph spans are out of scope).
    for p in paras:
        new = redact_text(p.text, labels)
        if new != p.text:
            _set_paragraph_text(p, new)
    out = io.BytesIO()
    doc.save(out)
    return out.getvalue(), dets


def secure_xlsx(data: bytes, detect_fn: Callable[[str], list[dict]]):
    import openpyxl
    wb = openpyxl.load_workbook(io.BytesIO(data))
    cells = [c for ws in wb.worksheets for row in ws.iter_rows()
             for c in row if isinstance(c.value, str)]
    full = "\n".join(c.value for c in cells)
    dets = detect_fn(full)
    labels = build_labels(dets)
    # Detection saw the joined sheet, but redaction is a per-cell substring replace —
    # so a PII value straddling a cell boundary won't match verbatim in any single
    # cell. v1 assumes each PII value lies within one cell.
    for c in cells:
        c.value = redact_text(c.value, labels)
    out = io.BytesIO()
    wb.save(out)
    return out.getvalue(), dets


def secure_text(data: bytes, detect_fn: Callable[[str], list[dict]]):
    text = data.decode("utf-8", "replace")
    dets = detect_fn(text)
    labels = build_labels(dets)
    return redact_text(text, labels).encode("utf-8"), dets
