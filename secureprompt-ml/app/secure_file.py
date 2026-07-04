"""Secure-file dispatch engine: route an uploaded file to the right redactor,
returning a same-format secured file. Runs detection under the bulk scan
profile (full coverage caps). One-way — no reverse mapping stored."""
from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass

from app import config
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


def _detect(analyzer, text: str) -> list[dict]:
    """Detection under the bulk scan profile (indirection point for tests)."""
    from app.detection.ner import detect
    from app.detection.scan_profile import scan_scope
    with scan_scope("bulk"):
        return detect(analyzer, text)


def _stem(filename: str) -> str:
    base = os.path.basename(filename or "file")
    return os.path.splitext(base)[0] or "file"


def _summary(dets: list[dict], pages: int, ocr: bool, mime: str, filename: str) -> dict:
    types = Counter(d["entity_type"].upper() for d in dets)
    # count distinct (type,value) as entities
    distinct = len({(d["entity_type"].upper(), d["text"]) for d in dets})
    return {"entities_count": distinct, "types": dict(types), "pages": pages,
            "ocr_used": ocr, "output_mime": mime, "output_filename": filename}


def secure_file(data: bytes, filename: str, analyzer) -> SecuredFile:
    ext = os.path.splitext(filename or "")[1].lower()
    head = data[:4]

    if head == b"%PDF":
        out, dets, ocr, pages = secure_pdf(
            data, lambda t: _detect(analyzer, t), _DPI, _LANGS, _MIN_CHARS, _font_path())
        fn = f"{_stem(filename)}-secured.pdf"
        return SecuredFile(out, "application/pdf", fn,
                           _summary(dets, pages, ocr, "application/pdf", fn))

    img_fmt = next((v for magic, v in _IMAGE_MAGIC.items() if data[:len(magic)] == magic), None)
    if img_fmt:
        out, dets, mime = secure_image(
            data, lambda t: _detect(analyzer, t), _DPI, _LANGS, _font_path())
        fn = f"{_stem(filename)}-secured.{img_fmt}"
        return SecuredFile(out, mime, fn, _summary(dets, 1, True, mime, fn))

    if head[:2] == b"PK" and ext == ".docx":
        out, dets = secure_docx(data, lambda t: _detect(analyzer, t))
        mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        fn = f"{_stem(filename)}-secured.docx"
        return SecuredFile(out, mime, fn, _summary(dets, 0, False, mime, fn))

    if head[:2] == b"PK" and ext == ".xlsx":
        out, dets = secure_xlsx(data, lambda t: _detect(analyzer, t))
        mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        fn = f"{_stem(filename)}-secured.xlsx"
        return SecuredFile(out, mime, fn, _summary(dets, 0, False, mime, fn))

    # plain text: only if it decodes cleanly as utf-8
    if ext in (".txt", ".text", ".md", ".csv", ".log") or _looks_text(data):
        out, dets = secure_text(data, lambda t: _detect(analyzer, t))
        fn = f"{_stem(filename)}-secured.txt"
        return SecuredFile(out, "text/plain", fn, _summary(dets, 0, False, "text/plain", fn))

    raise UnsupportedFormat(f"unsupported file type: ext={ext!r} head={head!r}")


def _looks_text(data: bytes) -> bool:
    sample = data[:4096]
    if b"\x00" in sample:  # NUL byte = standard binary-file signal (git, file(1), grep -I)
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False
