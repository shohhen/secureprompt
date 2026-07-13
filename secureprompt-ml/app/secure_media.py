"""OCR + box redaction for images EMBEDDED inside documents.

Text baked into a raster image — a letterhead logo, a scanned signature, a
stamp, a pasted screenshot — never reaches a document's text layer. The DOCX
redactor walks paragraphs and the PDF text-page path reads the text layer, so
both used to copy such an image through byte-for-byte: a report whose prose was
scrubbed to `АО «{{Organization_1}}»` still shipped with the bank's logo, which
*is* the organisation's name, rendered in pixels at the top of page one.

This module OCRs those images, hands the text to the caller's detector, and
paints the existing `{{Type_N}}` boxes over the hits.

Two OCR passes, not one. Tesseract with a Cyrillic-capable language set reads an
all-caps Latin logo (APEXBANK) as visually identical Cyrillic HOMOGLYPHS
(АРЕХВАМК) — a different codepoint sequence that NER does not recognise as an
organisation. Measured on the APEXBANK letterhead: `eng+rus+uzb+uzb_cyrl` yields
`АРЕХВАМК 44)` and detects nothing, while `eng` yields `APEXBANK` and detects
ORGANIZATION at 0.964. So each image is read once per language pass and the
detections are unioned; a single multilingual pass would silently find nothing.
"""
from __future__ import annotations

import io
import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Zip members a DOCX/XLSX stores its raster images under.
_MEDIA_PREFIXES = ("word/media/", "xl/media/")
_IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".gif")

# Pillow needs the source format keyword to re-encode in place.
_FMT_BY_EXT = {".png": "PNG", ".jpg": "JPEG", ".jpeg": "JPEG", ".bmp": "BMP",
               ".tif": "TIFF", ".tiff": "TIFF", ".gif": "GIF"}

# Images below this are icons/bullets/rules — too small to carry legible PII, and
# OCR on them is pure noise. Cheap guard against OCRing a hundred list bullets.
_MIN_SIDE = int(os.getenv("ML_MEDIA_MIN_SIDE", "32"))


def _dpi() -> int:
    return int(os.getenv("ML_SECURE_DPI", "200"))


def ocr_langs() -> list[str]:
    """Tesseract language passes to run over an embedded image, English first.

    See the module docstring: the multilingual pass alone misses Latin logos to
    homoglyph confusion, so `eng` is always run as well.
    """
    prod = os.getenv("ML_OCR_LANGS", "eng+rus+uzb+uzb_cyrl")
    return list(dict.fromkeys(["eng", prod]))


def ocr_variants(image) -> list[tuple[str, list]]:
    """`[(text, char_boxes)]`, one entry per language pass, duplicates dropped.

    `char_boxes` is aligned to `text` (one box per char, `None` for the spaces
    between words) — the shape `secure_boxes.spans_to_rects` indexes.
    """
    from app.secure_boxes import _ocr_boxes
    out: list[tuple[str, list]] = []
    seen: set[str] = set()
    for langs in ocr_langs():
        try:
            text, boxes = _ocr_boxes(image, langs)
        except Exception as e:  # noqa: BLE001 — a missing langpack must not break redaction
            logger.warning("OCR pass %s failed on embedded image (%s)", langs, e)
            continue
        if text.strip() and text not in seen:
            seen.add(text)
            out.append((text, boxes))
    return out


@dataclass
class ImageHit:
    """An embedded image that OCR'd to at least one detection."""
    name: str                      # zip member, e.g. "word/media/image1.png"
    fmt: str                       # Pillow format keyword for re-encoding
    image: object                  # PIL.Image (RGB)
    pages: list = field(default_factory=list)  # [(PageBoxes, dets)] per OCR pass
    dets: list = field(default_factory=list)   # offset-shifted copies, for labels


def _media_members(zf) -> list[str]:
    return [n for n in zf.namelist()
            if n.startswith(_MEDIA_PREFIXES) and n.lower().endswith(_IMAGE_EXTS)]


def scan_docx_images(data: bytes, detect_fn, base: int = 0) -> list[ImageHit]:
    """OCR every embedded image and detect PII in each reading.

    `base` shifts the returned `dets` offsets past the document's text so
    `build_labels` (which orders by first appearance) numbers prose entities
    before logo entities. The per-page dets keep their TRUE offsets — those index
    the OCR text and are what `spans_to_rects` needs.
    """
    import zipfile
    from PIL import Image
    from app.secure_boxes import PageBoxes

    hits: list[ImageHit] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        members = _media_members(zf)
    except Exception as e:  # noqa: BLE001 — a malformed package must not break text redaction
        logger.warning("could not list embedded media (%s)", e)
        return hits

    for name in members:
        try:
            img = Image.open(io.BytesIO(zf.read(name))).convert("RGB")
        except Exception as e:  # noqa: BLE001 — unreadable/exotic image: skip, keep redacting
            logger.warning("could not decode embedded image %s (%s)", name, e)
            continue
        if img.width < _MIN_SIDE or img.height < _MIN_SIDE:
            continue

        ext = os.path.splitext(name.lower())[1]
        hit = ImageHit(name=name, fmt=_FMT_BY_EXT.get(ext, "PNG"), image=img)
        for text, boxes in ocr_variants(img):
            found = detect_fn(text)
            if not found:
                continue
            page = PageBoxes(img.width, img.height, text, boxes, True, img)
            hit.pages.append((page, found))
            hit.dets.extend({**d, "start": d["start"] + base, "end": d["end"] + base}
                            for d in found)
        if hit.pages:
            hits.append(hit)
    return hits


def _redacted_bytes(hit: ImageHit, labels: dict, dpi: int, font_path: str) -> bytes | None:
    """Paint every hit's boxes onto the image; None when nothing landed."""
    from app.secure_boxes import spans_to_rects
    from app.secure_visual import draw_page

    rects: list = []
    for page, dets in hit.pages:
        rects.extend(spans_to_rects(page, dets, labels, dpi))
    if not rects:
        return None
    draw_page(hit.image, rects, font_path)
    buf = io.BytesIO()
    hit.image.save(buf, format=hit.fmt)
    return buf.getvalue()


def redact_docx_images(data: bytes, hits: list[ImageHit], labels: dict) -> bytes:
    """Rewrite the package with each hit's image replaced by its redacted render.

    Every other member is copied through with its original `ZipInfo`, so the
    package keeps its structure (rels, content-types, styles) untouched.
    """
    import zipfile
    from app.secure_visual import _font_path

    dpi = _dpi()
    font = _font_path()
    replacements: dict[str, bytes] = {}
    for hit in hits:
        try:
            payload = _redacted_bytes(hit, labels, dpi, font)
        except Exception as e:  # noqa: BLE001 — a draw failure must not lose the text redaction
            logger.warning("could not redact embedded image %s (%s)", hit.name, e)
            continue
        if payload:
            replacements[hit.name] = payload
    if not replacements:
        return data

    zin = zipfile.ZipFile(io.BytesIO(data))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            zout.writestr(item, replacements.get(item.filename) or zin.read(item.filename))
    return out.getvalue()
