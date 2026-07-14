"""Position extraction + box geometry for visual redaction.

Char boxes come from pdfminer (text pages, PDF points, bottom-left origin) or
Tesseract word boxes (image/scanned pages, pixels, top-left origin). Detection
returns BYTE offsets, so spans are mapped byte->char before indexing char_boxes.
"""
from __future__ import annotations

import io
import logging
import math
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class PageBoxes:
    width: float
    height: float
    text: str
    char_boxes: list  # aligned to text; each (x0,y0,x1,y1) or None
    is_ocr: bool
    image: object | None = None


def byte_to_char_map(text: str) -> dict[int, int]:
    m: dict[int, int] = {}
    running = 0
    for i, ch in enumerate(text):
        m[running] = i
        running += len(ch.encode("utf-8"))
    m[running] = len(text)
    return m


def group_by_line(boxes: list[tuple]) -> list[list[tuple]]:
    """Group boxes whose vertical centers are within half the box height —
    i.e. on the same text line. A span crossing a line break yields >1 group."""
    groups: list[list[tuple]] = []
    for b in boxes:
        cy = (b[1] + b[3]) / 2.0
        h = abs(b[3] - b[1]) or 1.0
        placed = False
        for g in groups:
            gy = (g[0][1] + g[0][3]) / 2.0
            if abs(cy - gy) <= h * 0.6:
                g.append(b)
                placed = True
                break
        if not placed:
            groups.append([b])
    return groups


def to_pixels(page: PageBoxes, x0, y0, x1, y1, dpi: int) -> tuple[int, int, int, int]:
    if page.is_ocr:
        # round outward so the box never under-covers the glyph by a sub-pixel
        return (int(math.floor(x0)), int(math.floor(y0)),
                int(math.ceil(x1)), int(math.ceil(y1)))
    s = dpi / 72.0
    px0 = x0 * s
    px1 = x1 * s
    py0 = (page.height - y1) * s  # top edge (y-flip)
    py1 = (page.height - y0) * s  # bottom edge
    return (int(math.floor(px0)), int(math.floor(py0)),
            int(math.ceil(px1)), int(math.ceil(py1)))


def _emit_rects(page: PageBoxes, cs: int, ce: int, label: str, dpi: int, n: int, rects: list):
    boxes = [page.char_boxes[i] for i in range(cs, min(ce, n))
             if page.char_boxes[i] is not None]
    if not boxes:
        return
    for grp in group_by_line(boxes):
        gx0 = min(b[0] for b in grp)
        gy0 = min(b[1] for b in grp)
        gx1 = max(b[2] for b in grp)
        gy1 = max(b[3] for b in grp)
        px0, py0, px1, py1 = to_pixels(page, gx0, gy0, gx1, gy1, dpi)
        rects.append((px0, py0, px1, py1, label))


def _word_bounded(text: str, cs: int, ce: int) -> bool:
    """True when text[cs:ce] is not embedded inside a larger alphanumeric run — i.e.
    the chars immediately before/after it are not letters/digits. The value-repeat
    pass uses this so a short value (e.g. "от") is never boxed inside unrelated words
    (со*от*ветствии / *от*носительно / к*от*орые)."""
    before = text[cs - 1] if cs > 0 else ""
    after = text[ce] if ce < len(text) else ""
    return not (before.isalnum() or after.isalnum())


def spans_to_rects(page: PageBoxes, detections, labels, dpi: int):
    b2c = byte_to_char_map(page.text)
    n = len(page.char_boxes)
    rects: list = []
    covered: list[tuple[int, int]] = []

    def _overlaps(cs: int, ce: int) -> bool:
        return any(cs < e and ce > s for s, e in covered)

    # 1) Exact detection spans first — these cover noisy/spaced forms a plain
    #    string match can't, and pin the byte-accurate region.
    for d in detections:
        cs = b2c.get(d["start"])
        ce = b2c.get(d["end"])
        if cs is None or ce is None or cs >= ce:
            continue
        label = labels.get((d["entity_type"].upper(), d["text"]), "")
        _emit_rects(page, cs, ce, label, dpi, n, rects)
        covered.append((cs, ce))

    # 2) Value repeat: box EVERY occurrence of each labeled value on this page —
    #    repeats the model reported only once, and values first detected on OTHER
    #    pages (labels is the whole-document map). Longest first so a short value
    #    can't pre-empt a longer one; skip anything already covered.
    by_value: dict[str, str] = {}
    for (_typ, value), label in labels.items():
        if value:
            by_value.setdefault(value, label)
    for value in sorted(by_value, key=len, reverse=True):
        label = by_value[value]
        start = 0
        while (i := page.text.find(value, start)) >= 0:
            cs, ce = i, i + len(value)
            start = ce
            if not _overlaps(cs, ce) and _word_bounded(page.text, cs, ce):
                _emit_rects(page, cs, ce, label, dpi, n, rects)
                covered.append((cs, ce))
    return rects


def _pdf_text_boxes(page_layout):
    from pdfminer.layout import LTChar, LTAnno, LTTextContainer, LTTextLine
    chars: list[str] = []
    boxes: list = []
    for el in page_layout:
        if not isinstance(el, LTTextContainer):
            continue
        for line in el:
            if not isinstance(line, LTTextLine):
                continue
            for ch in line:
                if isinstance(ch, LTChar):
                    # LTChar.get_text() may return MORE THAN ONE character:
                    # ligatures ("fi"/"ffi") and unmapped glyphs (rendered as the
                    # literal "(cid:N)" marker). Emit one box per character so
                    # char_boxes stays index-aligned to the text — otherwise every
                    # box after such a glyph drifts and lands on the wrong words.
                    t = ch.get_text()
                    chars.append(t)
                    boxes.extend([(ch.x0, ch.y0, ch.x1, ch.y1)] * len(t))
                elif isinstance(ch, LTAnno):
                    t = ch.get_text()
                    chars.append(t)
                    boxes.extend([None] * len(t))
    return "".join(chars), boxes


def _ocr_boxes(image, langs: str):
    import pytesseract
    from pytesseract import Output
    d = pytesseract.image_to_data(image, lang=langs, output_type=Output.DICT)
    parts: list[tuple] = []
    for i in range(len(d["text"])):
        word = d["text"][i]
        if not word.strip():
            continue
        box = (d["left"][i], d["top"][i],
               d["left"][i] + d["width"][i], d["top"][i] + d["height"][i])
        if parts:
            parts.append((" ", None))
        for c in word:
            parts.append((c, box))
    text = "".join(c for c, _ in parts)
    boxes = [b for _, b in parts]
    return text, boxes


def _render_pdf_page(data: bytes, index: int, dpi: int):
    from pdf2image import convert_from_bytes
    imgs = convert_from_bytes(data, dpi=dpi, first_page=index + 1, last_page=index + 1)
    return imgs[0]


def image_regions(layout) -> list[tuple]:
    """Bounding boxes (PDF points) of the raster images drawn on a page."""
    from pdfminer.layout import LTFigure, LTImage
    out: list[tuple] = []

    def walk(el):
        for child in el:
            if isinstance(child, LTImage):
                out.append((child.x0, child.y0, child.x1, child.y1))
            elif isinstance(child, LTFigure):
                walk(child)

    walk(layout)
    return out


# Regions smaller than this (PDF points) are rules/bullets/icons — no legible PII.
_MIN_REGION_PT = 24.0


def append_image_ocr(page: PageBoxes, data: bytes, index: int, regions: list[tuple],
                     dpi: int) -> PageBoxes:
    """OCR the raster regions of a TEXT page and append their words to the page.

    A page with a real text layer never goes through OCR, so text baked into an
    image on it — a letterhead logo, a scanned signature, a stamp — is invisible
    to detection and survives redaction. We OCR only the image REGIONS (not the
    whole page, which would re-read and duplicate the text layer) and append the
    words with boxes converted back into PDF points, so the page keeps ONE
    coordinate system (`is_ocr=False`) and `to_pixels` maps everything correctly.
    """
    from app.secure_media import ocr_variants
    img = _render_pdf_page(data, index, dpi)
    s = dpi / 72.0
    h = page.height
    text = page.text
    boxes = list(page.char_boxes)

    for x0, y0, x1, y1 in regions:
        if (x1 - x0) < _MIN_REGION_PT or (y1 - y0) < _MIN_REGION_PT:
            continue
        # PDF points (bottom-left origin) -> render pixels (top-left origin)
        cx0, cy0 = max(int(x0 * s), 0), max(int((h - y1) * s), 0)
        cx1, cy1 = min(int(x1 * s), img.width), min(int((h - y0) * s), img.height)
        if cx1 - cx0 < 8 or cy1 - cy0 < 8:
            continue
        crop = img.crop((cx0, cy0, cx1, cy1))
        for otext, oboxes in ocr_variants(crop):
            text += "\n" + otext
            boxes.append(None)  # keeps char_boxes index-aligned to text
            for b in oboxes:
                if b is None:
                    boxes.append(None)
                    continue
                bx0, by0, bx1, by1 = b
                # crop pixels -> page pixels -> PDF points (y-flip back)
                boxes.append(((cx0 + bx0) / s, h - (cy0 + by1) / s,
                              (cx0 + bx1) / s, h - (cy0 + by0) / s))
    return PageBoxes(page.width, page.height, text, boxes, False, page.image)


def extract_boxes(data: bytes, is_pdf: bool, dpi: int, langs: str, min_chars: int):
    pages: list[PageBoxes] = []
    if is_pdf:
        from pdfminer.high_level import extract_pages
        for idx, layout in enumerate(extract_pages(io.BytesIO(data))):
            text, boxes = _pdf_text_boxes(layout)
            if len(text.strip()) >= min_chars:
                page = PageBoxes(layout.width, layout.height, text, boxes, False)
                regions = image_regions(layout)
                if regions:
                    try:
                        page = append_image_ocr(page, data, idx, regions, dpi)
                    except Exception as e:  # noqa: BLE001 — OCR must never break extraction
                        logger.warning("embedded-image OCR failed on page %d (%s)", idx, e)
                pages.append(page)
            else:
                img = _render_pdf_page(data, idx, dpi)
                otext, oboxes = _ocr_boxes(img, langs)
                pages.append(PageBoxes(img.width, img.height, otext, oboxes, True, img))
    else:
        from PIL import Image
        img = Image.open(io.BytesIO(data)).convert("RGB")
        otext, oboxes = _ocr_boxes(img, langs)
        pages.append(PageBoxes(img.width, img.height, otext, oboxes, True, img))
    return pages
