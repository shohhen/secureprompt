"""Text normalization for NER — maximizes entity detection without destroying
the punctuation/case that structured PII depends on.

Empirically (2026-07-04, live GLiNER2 + XLM-R): removing INVISIBLE noise helps
(zero-width chars, format chars, weird spaces, soft/line-break hyphens,
control/PUA icon glyphs); removing VISIBLE structure hurts (stripping all
punctuation loses emails/URLs/IDs; lowercasing loses proper-noun case).

`normalize_for_ner` is offset-mapped: it returns the cleaned text plus a
`char_map` so detected spans can be mapped BACK to the original text. This is
essential — the gateway redacts the ORIGINAL prompt, so span offsets must point
into it, not into the normalized copy. All transforms are per-character
(1:1 keep/replace or delete), so the map is exact; NFC/NFKC are intentionally
excluded (not 1:1 char-mappable, and measured low-value).
"""
from __future__ import annotations

import unicodedata

# Zero-width / joiner / BOM. Removed outright (they split tokens invisibly, e.g.
# `jo​hn@x.com`). Soft hyphen (U+00AD) is category Cf, handled by the
# Cf branch below.
_ZERO_WIDTH = frozenset("​‌‍⁠﻿")
# Hyphen variants that can end a wrapped line (ASCII -, non-breaking, figure,
# en dash, hyphen). A hyphen right before a newline joins the split word.
_HYPHENS = frozenset("-‐‑‒–")

# Sentence punctuation trimmed from span EDGES (not from the input — that would
# break emails/phones). Leaves `+`, `@`, `(`, brackets, and hyphens intact.
_EDGE_PUNCT = ",.;:!?"


def normalize_for_ner(text: str) -> tuple[str, list[int]]:
    """Return `(normalized_text, char_map)` where `char_map[k]` is the index in
    `text` of the k-th character of `normalized_text`.

    Per-character transforms (offset-safe):
      * zero-width / format chars (Cf) incl. soft hyphen -> **deleted**
      * a hyphen immediately before (optional spaces then) a newline ->
        **deleted** (joins a word split across lines)
      * any Unicode space (Zs, incl. NBSP) or tab -> ASCII space
      * control / private-use / surrogate / unassigned (Cc/Co/Cs/Cn) -> space
      * newline and everything else -> kept unchanged
    """
    norm: list[str] = []
    cmap: list[int] = []
    n = len(text)
    i = 0
    while i < n:
        ch = text[i]
        cat = unicodedata.category(ch)
        if ch in _ZERO_WIDTH or cat == "Cf":
            i += 1
            continue
        if ch in _HYPHENS:
            j = i + 1
            while j < n and text[j] in " \t":
                j += 1
            if j < n and text[j] == "\n":
                i = j + 1  # drop hyphen + spaces + newline -> join
                continue
            norm.append(ch)
            cmap.append(i)
            i += 1
            continue
        if ch == "\n":
            norm.append("\n")
            cmap.append(i)
            i += 1
            continue
        if cat == "Zs" or ch == "\t":
            norm.append(" ")
            cmap.append(i)
            i += 1
            continue
        if cat in ("Cc", "Co", "Cs", "Cn"):
            norm.append(" ")
            cmap.append(i)
            i += 1
            continue
        norm.append(ch)
        cmap.append(i)
        i += 1
    return "".join(norm), cmap


def remap_span(cmap: list[int], ns: int, ne: int, orig_len: int) -> tuple[int, int]:
    """Map a `[ns, ne)` char span in the normalized text back to a `[os, oe)`
    span in the original text using `char_map`. `oe` is exclusive — just past
    the last kept character, so it covers any noise embedded inside the span."""
    if not cmap:
        return (0, 0)
    ns = max(0, min(ns, len(cmap) - 1))
    ne = max(ns + 1, min(ne, len(cmap)))
    os_ = cmap[ns]
    oe = cmap[ne - 1] + 1
    return (os_, min(oe, orig_len))


def trim_edge_punct(
    span_text: str, byte_start: int, byte_end: int
) -> tuple[str, int, int] | None:
    """Strip leading/trailing sentence punctuation from a detected span,
    adjusting byte offsets. Fixes spans like `'Алексей Смирнов,'` and
    `'+7 915 123-45-67.'`. Returns `None` if nothing remains. A leading `+`
    (phones) survives — it is not in `_EDGE_PUNCT`."""
    s, e = 0, len(span_text)
    while s < e and span_text[s] in _EDGE_PUNCT:
        s += 1
    while e > s and span_text[e - 1] in _EDGE_PUNCT:
        e -= 1
    if s == 0 and e == len(span_text):
        return (span_text, byte_start, byte_end)
    if s >= e:
        return None
    cleaned = span_text[s:e]
    lead_bytes = len(span_text[:s].encode("utf-8"))
    trail_bytes = len(span_text[e:].encode("utf-8"))
    return (cleaned, byte_start + lead_bytes, byte_end - trail_bytes)
