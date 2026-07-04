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


def _load_font(font_path: str, size: int):
    """Load the label font at `size`, falling back to PIL's bundled default.

    The black box (which covers the PII) is the security-critical element; the
    `{{Type_N}}` label is informational. If the configured TrueType font is
    missing (e.g. running off-image where the DejaVu path doesn't exist), never
    let that abort redaction — fall back to `load_default(size)` so the box is
    still drawn with a readable label. Requires Pillow >= 10.1 for the sized
    default (pinned floor is >= 10.4)."""
    from PIL import ImageFont
    try:
        return ImageFont.truetype(font_path, size)
    except OSError:
        return ImageFont.load_default(size=size)


def draw_page(image, rects, font_path: str):
    from PIL import ImageDraw
    draw = ImageDraw.Draw(image)
    for (x0, y0, x1, y1, label) in rects:
        if x1 <= x0 or y1 <= y0:
            continue
        draw.rectangle([x0, y0, x1, y1], fill=(0, 0, 0))
        # fit the label to the box: shrink until it fits the width
        size = max(6, int((y1 - y0) * 0.8))
        font = _load_font(font_path, size)
        while size > 6 and draw.textlength(label, font=font) > (x1 - x0):
            size -= 1
            font = _load_font(font_path, size)
        draw.text((x0 + 1, y0), label, fill=(255, 255, 255), font=font)
    return image


def images_to_pdf(images, dpi: int) -> bytes:
    """Assemble page images into a PDF using Pillow's native writer.

    Pillow (permissive/HPND) replaces img2pdf (LGPL) — one fewer copyleft
    dependency. Passing ``resolution=dpi`` stamps the correct physical page size
    so a 200-DPI render isn't blown up to img2pdf's assumed 96 DPI.
    """
    rgb = [im.convert("RGB") for im in images]
    out = io.BytesIO()
    rgb[0].save(out, format="PDF", save_all=True, append_images=rgb[1:],
                resolution=float(dpi))
    return out.getvalue()


def _ordered(dets):
    """First-appearance (byte-offset) order within one page/image."""
    return sorted(dets, key=lambda d: d.get("start", 0))


def secure_pdf(data, detect_fn, dpi, langs, min_chars, font_path):
    pages = extract_boxes(data, True, dpi, langs, min_chars)
    per_page = [detect_fn(p.text) for p in pages]
    # first-appearance numbering: page order, then byte offset within each page
    labels = build_labels([d for dets in per_page for d in _ordered(dets)])
    images = []
    for idx, page in enumerate(pages):
        img = page.image if page.image is not None else _render_pdf_page(data, idx, dpi)
        rects = spans_to_rects(page, per_page[idx], labels, dpi)
        draw_page(img, rects, font_path)
        images.append(img)
    all_dets = [d for dets in per_page for d in dets]
    return images_to_pdf(images, dpi), all_dets, any(p.is_ocr for p in pages), len(pages)


def secure_image(data, detect_fn, dpi, langs, font_path):
    from PIL import Image
    pages = extract_boxes(data, False, dpi, langs, 0)
    page = pages[0]
    dets = detect_fn(page.text)
    labels = build_labels(_ordered(dets))
    rects = spans_to_rects(page, dets, labels, dpi)
    img = page.image
    draw_page(img, rects, font_path)
    fmt = (Image.open(io.BytesIO(data)).format or "PNG")
    out = io.BytesIO()
    img.save(out, format=fmt)
    mime = f"image/{fmt.lower()}"
    return out.getvalue(), dets, mime
