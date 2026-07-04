"""Placeholder labels + text redaction for secure-file. Pure — no heavy deps."""
from __future__ import annotations

import re


def title_case(entity_type: str) -> str:
    return "_".join(w.capitalize() for w in entity_type.split("_"))


def build_labels(detections: list[dict]) -> dict[tuple[str, str], str]:
    """Assign `{{Type_N}}` per (TYPE, value); same pair -> same label; per-type
    counter in first-appearance order. No mapping is persisted (one-way)."""
    labels: dict[tuple[str, str], str] = {}
    counters: dict[str, int] = {}
    for d in detections:
        typ = d["entity_type"].upper()
        val = d["text"]
        if not val:  # skip empty values so the visible sequence has no gaps
            continue
        key = (typ, val)
        if key in labels:
            continue
        counters[typ] = counters.get(typ, 0) + 1
        labels[key] = "{{%s_%d}}" % (title_case(typ), counters[typ])
    return labels


def redact_spans(text: str, spans: list[tuple[int, int, str]]) -> str:
    """Splice each ``(char_start, char_end, label)`` range over ``text``.

    Span-based (not value-match) so the ORIGINAL bytes are removed — including any
    invisible noise inside the span (NBSP, zero-width, collapsed whitespace, soft
    line breaks) that makes the cleaned detection value differ from the document
    text. Applied right-to-left so earlier offsets stay valid; caller passes
    non-overlapping detection spans.
    """
    for s, e, label in sorted(spans, key=lambda x: x[0], reverse=True):
        if 0 <= s < e <= len(text):
            text = text[:s] + label + text[e:]
    return text


def redact_text(text: str, labels: dict[tuple[str, str], str]) -> str:
    """Replace every occurrence of each value with its label in a SINGLE pass.

    A per-label loop of ``str.replace`` would let a short value processed later
    match inside a placeholder already inserted (e.g. "1" corrupting "{{Ssn_1}}").
    Building one longest-first regex alternation and substituting once avoids
    that: matched spans are consumed, so inserted placeholders are never rescanned.
    """
    by_value = {val: label for (_typ, val), label in labels.items() if val}
    if not by_value:
        return text
    values = sorted(by_value, key=len, reverse=True)  # longest first
    pattern = re.compile("|".join(re.escape(v) for v in values))
    return pattern.sub(lambda m: by_value[m.group(0)], text)
