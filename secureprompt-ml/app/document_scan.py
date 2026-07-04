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
