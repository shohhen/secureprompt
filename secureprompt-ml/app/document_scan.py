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
