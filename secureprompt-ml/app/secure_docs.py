"""In-document redaction for DOCX / XLSX / TXT — replace PII strings with
`{{Type_N}}` labels so the underlying text is genuinely removed."""
from __future__ import annotations

import io
from typing import Callable

from app.secure_labels import build_labels, redact_text


def _set_paragraph_text(paragraph, text: str) -> None:
    """Put `text` in the first run (keeps its formatting), blank the rest. PII
    that spanned multiple runs is flattened to run[0]'s style (v1 limitation)."""
    if paragraph.runs:
        paragraph.runs[0].text = text
        for r in paragraph.runs[1:]:
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
