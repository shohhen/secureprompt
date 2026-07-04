"""Visual redaction: rasterize pages, draw black boxes + white `{{Type_N}}`
labels over PII, reassemble. The page becomes an image, so no PII text layer
survives. Used for PDF and image inputs."""
from __future__ import annotations

import io
import os

from app.secure_boxes import _render_pdf_page, extract_boxes, spans_to_rects
from app.secure_labels import build_labels

_FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
]


def _font_path() -> str:
    for p in _FONT_CANDIDATES:
        if os.path.exists(p):
            return p
    return _FONT_CANDIDATES[0]  # let PIL raise a clear error if truly missing


def draw_page(image, rects, font_path: str):
    from PIL import ImageDraw, ImageFont
    draw = ImageDraw.Draw(image)
    for (x0, y0, x1, y1, label) in rects:
        if x1 <= x0 or y1 <= y0:
            continue
        draw.rectangle([x0, y0, x1, y1], fill=(0, 0, 0))
        # fit the label to the box: shrink until it fits the width
        size = max(6, int((y1 - y0) * 0.8))
        font = ImageFont.truetype(font_path, size)
        while size > 6 and draw.textlength(label, font=font) > (x1 - x0):
            size -= 1
            font = ImageFont.truetype(font_path, size)
        draw.text((x0 + 1, y0), label, fill=(255, 255, 255), font=font)
    return image


def images_to_pdf(images) -> bytes:
    import img2pdf
    bufs = []
    for im in images:
        b = io.BytesIO()
        im.convert("RGB").save(b, format="PNG")
        bufs.append(b.getvalue())
    return img2pdf.convert(bufs)


def secure_pdf(data, detect_fn, dpi, langs, min_chars, font_path):
    pages = extract_boxes(data, True, dpi, langs, min_chars)
    per_page = [detect_fn(p.text) for p in pages]
    labels = build_labels([d for dets in per_page for d in dets])
    images = []
    for idx, page in enumerate(pages):
        img = page.image if page.image is not None else _render_pdf_page(data, idx, dpi)
        rects = spans_to_rects(page, per_page[idx], labels, dpi)
        draw_page(img, rects, font_path)
        images.append(img)
    all_dets = [d for dets in per_page for d in dets]
    return images_to_pdf(images), all_dets, any(p.is_ocr for p in pages), len(pages)


def secure_image(data, detect_fn, dpi, langs, font_path):
    from PIL import Image
    pages = extract_boxes(data, False, dpi, langs, 0)
    page = pages[0]
    dets = detect_fn(page.text)
    labels = build_labels(dets)
    rects = spans_to_rects(page, dets, labels, dpi)
    img = page.image
    draw_page(img, rects, font_path)
    fmt = (Image.open(io.BytesIO(data)).format or "PNG")
    out = io.BytesIO()
    img.save(out, format=fmt)
    mime = f"image/{fmt.lower()}"
    return out.getvalue(), dets, mime
