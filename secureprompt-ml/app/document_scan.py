"""Single extraction + whole-document detection core shared by /v1/scan-file and
/v1/secure-file, so both endpoints return identical detections. Heavy deps
(presidio, pdfminer, PIL) are lazy-imported inside functions only."""
from __future__ import annotations

from dataclasses import dataclass


def assemble_pages(page_texts: list[str], sep: str = "\n\n") -> tuple[str, list[int]]:
    """Join page texts into one document. Return (text, page_byte_offsets) where
    page_byte_offsets[i] is the UTF-8 byte offset at which page i's text begins."""
    parts: list[str] = []
    offsets: list[int] = []
    running = 0
    sep_bytes = len(sep.encode("utf-8"))
    for i, pt in enumerate(page_texts):
        if i > 0:
            parts.append(sep)
            running += sep_bytes
        offsets.append(running)
        parts.append(pt)
        running += len(pt.encode("utf-8"))
    return "".join(parts), offsets


def _page_of(byte_pos: int, page_byte_offsets: list[int]) -> int | None:
    """Largest page index i with page_byte_offsets[i] <= byte_pos, else None."""
    found = None
    for i, off in enumerate(page_byte_offsets):
        if off <= byte_pos:
            found = i
        else:
            break
    return found


def partition_by_page(detections: list[dict], page_byte_offsets: list[int],
                      page_byte_lengths: list[int]) -> list[list[dict]]:
    """Split whole-document detections (byte spans in the assembled text) into
    per-page lists with PAGE-LOCAL byte offsets. A detection is assigned to the
    page where it STARTS; its end is clamped to that page's length (the value-repeat
    pass in spans_to_rects covers any tail on later pages)."""
    per_page: list[list[dict]] = [[] for _ in page_byte_offsets]
    for d in detections:
        i = _page_of(d["start"], page_byte_offsets)
        if i is None:
            continue
        base = page_byte_offsets[i]
        local_start = d["start"] - base
        local_end = min(d["end"] - base, page_byte_lengths[i])
        if local_end <= local_start:
            continue
        per_page[i].append({**d, "start": local_start, "end": local_end})
    return per_page


import os


@dataclass
class ScannedDocument:
    text: str
    detections: list[dict]
    pages: list | None
    page_byte_offsets: list[int] | None
    is_ocr: bool
    page_count: int


_IMAGE_MAGIC = (b"\xff\xd8\xff", b"\x89PNG", b"GIF8", b"BM", b"II*\x00", b"MM\x00*")


def _extract_pages(raw: bytes, is_pdf: bool) -> list:
    """Per-page geometry pages via extract_boxes (lazy heavy import)."""
    from app.secure_boxes import extract_boxes
    dpi = int(os.getenv("ML_SECURE_DPI", "200"))
    langs = os.getenv("ML_OCR_LANGS", "eng+rus+uzb+uzb_cyrl")
    min_chars = int(os.getenv("ML_OCR_PAGE_MIN_CHARS", "24"))
    return extract_boxes(raw, is_pdf, dpi, langs, min_chars if is_pdf else 0)


def detect_all(analyzer, text: str) -> list[dict]:
    """Whole-document NER (bulk profile) + regex secrets, overlap-merged."""
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
    return merge_overlapping_spans(dets)


def _char_to_byte(text: str) -> list[int]:
    out, b = [], 0
    for ch in text:
        out.append(b)
        b += len(ch.encode("utf-8"))
    out.append(b)
    return out


def scan_document(raw: bytes, filename: str, analyzer) -> ScannedDocument:
    head = raw[:4]
    is_pdf = head == b"%PDF"
    is_image = any(raw[:len(m)] == m for m in _IMAGE_MAGIC)
    if is_pdf or is_image:
        pages = _extract_pages(raw, is_pdf)
        text, offsets = assemble_pages([p.text for p in pages])
        dets = detect_all(analyzer, text)
        return ScannedDocument(
            text=text, detections=dets, pages=pages, page_byte_offsets=offsets,
            is_ocr=any(getattr(p, "is_ocr", False) for p in pages),
            page_count=len(pages))
    # geometry-less formats: whole-doc text via the shared extractor
    from app.file_extract import decode_best_effort
    text = decode_best_effort(raw)
    dets = detect_all(analyzer, text)
    return ScannedDocument(text=text, detections=dets, pages=None,
                           page_byte_offsets=None, is_ocr=False, page_count=1)
