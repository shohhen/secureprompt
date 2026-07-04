"""Secure-file dispatch engine: route an uploaded file to the right redactor,
returning a same-format secured file. Runs detection under the bulk scan
profile (full coverage caps). One-way — no reverse mapping stored."""
from __future__ import annotations

import os
import re
from collections import Counter
from dataclasses import dataclass

from app.secure_docs import secure_docx, secure_text, secure_xlsx
from app.secure_visual import _font_path, secure_image, secure_pdf

_DPI = int(os.getenv("ML_SECURE_DPI", "200"))
_LANGS = os.getenv("ML_OCR_LANGS", "eng+rus+uzb+uzb_cyrl")
_MIN_CHARS = int(os.getenv("ML_OCR_PAGE_MIN_CHARS", "24"))
_IMAGE_MAGIC = {b"\xff\xd8\xff": "jpeg", b"\x89PNG": "png", b"GIF8": "gif",
                b"BM": "bmp", b"II*\x00": "tiff", b"MM\x00*": "tiff"}


class UnsupportedFormat(Exception):
    pass


@dataclass
class SecuredFile:
    data: bytes
    mime: str
    filename: str
    summary: dict


def _char_to_byte(text: str) -> list[int]:
    """``lookup[i]`` = UTF-8 byte offset of char ``i``; ``lookup[len(text)]`` =
    total byte length. ``scan_secrets`` reports CHAR offsets while NER reports
    BYTE offsets; converting keeps the merged detection list uniformly
    byte-indexed (secure_boxes / secure_docs both assume byte offsets)."""
    out = []
    b = 0
    for ch in text:
        out.append(b)
        b += len(ch.encode("utf-8"))
    out.append(b)
    return out


def _detect(analyzer, text: str) -> list[dict]:
    """NER PII + regex secrets under the bulk scan profile (indirection point for
    tests). Secrets (API keys, tokens, private keys) are merged so they are
    redacted in the secured file too — not just names/PII."""
    from app.detection.ner import detect
    from app.detection.scan_profile import scan_scope
    from app.detection.secrets import scan_secrets
    from app.secure_labels import merge_overlapping_spans
    with scan_scope("bulk"):
        dets = detect(analyzer, text)
    secrets = scan_secrets(text)
    if secrets:
        c2b = _char_to_byte(text)
        for s in secrets:
            dets.append({"entity_type": s.kind.upper(), "text": s.text,
                         "start": c2b[s.start], "end": c2b[s.end], "score": 1.0})
    # Collapse overlapping same-type spans (e.g. `SECURETECH` vs `"SECURETECH"`,
    # surname nested in full name) so one entity yields one placeholder + box.
    return merge_overlapping_spans(dets)


_UNSAFE_STEM = re.compile(r'[\r\n"\\/\x00-\x1f\x7f]')


def _stem(filename: str) -> str:
    base = os.path.basename(filename or "file")
    stem = os.path.splitext(base)[0]
    # strip control/quote/backslash chars that would break Content-Disposition
    stem = _UNSAFE_STEM.sub("", stem).strip()
    return stem or "file"


def _summary(dets: list[dict], pages: int, ocr: bool, mime: str, filename: str) -> dict:
    types = Counter(d["entity_type"].upper() for d in dets)
    # count distinct (type,value) as entities
    distinct = len({(d["entity_type"].upper(), d["text"]) for d in dets})
    return {"entities_count": distinct, "types": dict(types), "pages": pages,
            "ocr_used": ocr, "output_mime": mime, "output_filename": filename}


def secure_file(data: bytes, filename: str, analyzer) -> SecuredFile:
    from app.document_scan import scan_document, partition_by_page
    from app.secure_labels import build_labels
    ext = os.path.splitext(filename or "")[1].lower()
    head = data[:4]

    if head == b"%PDF" or next((v for m, v in _IMAGE_MAGIC.items() if data[:len(m)] == m), None):
        doc = scan_document(data, filename, analyzer)
        labels = build_labels(sorted(doc.detections, key=lambda d: d.get("start", 0)))
        page_lens = [len(p.text.encode("utf-8")) for p in doc.pages]
        per_page = partition_by_page(doc.detections, doc.page_byte_offsets, page_lens)
        if head == b"%PDF":
            out, _dets, ocr, pages = secure_pdf(
                doc.pages, per_page, labels, data, _DPI, _font_path())
            fn = f"{_stem(filename)}-secured.pdf"
            # summarize the whole-doc detections (not the post-partition list) so
            # the summary matches scan-file + the image branch exactly.
            return SecuredFile(out, "application/pdf", fn,
                               _summary(doc.detections, pages, ocr, "application/pdf", fn))
        img_fmt = next(v for m, v in _IMAGE_MAGIC.items() if data[:len(m)] == m)
        out, mime = secure_image(doc.pages, per_page[0], labels, img_fmt, _DPI, _font_path())
        fn = f"{_stem(filename)}-secured.{img_fmt}"
        return SecuredFile(out, mime, fn, _summary(doc.detections, 1, doc.is_ocr, mime, fn))

    detect_fn = lambda t: _detect(analyzer, t)  # noqa: E731
    if head[:2] == b"PK" and ext == ".docx":
        out, dets = secure_docx(data, detect_fn)
        mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        fn = f"{_stem(filename)}-secured.docx"
        return SecuredFile(out, mime, fn, _summary(dets, 0, False, mime, fn))
    if head[:2] == b"PK" and ext == ".xlsx":
        out, dets = secure_xlsx(data, detect_fn)
        mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        fn = f"{_stem(filename)}-secured.xlsx"
        return SecuredFile(out, mime, fn, _summary(dets, 0, False, mime, fn))
    if ext in (".txt", ".text", ".md", ".csv", ".log") or _looks_text(data):
        out, dets = secure_text(data, detect_fn)
        fn = f"{_stem(filename)}-secured.txt"
        return SecuredFile(out, "text/plain", fn, _summary(dets, 0, False, "text/plain", fn))
    raise UnsupportedFormat(f"unsupported file type: ext={ext!r}")


def _looks_text(data: bytes) -> bool:
    sample = data[:4096]
    if b"\x00" in sample:  # NUL byte = standard binary-file signal (git, file(1), grep -I)
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False
