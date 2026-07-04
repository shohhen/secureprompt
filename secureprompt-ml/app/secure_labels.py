"""Placeholder labels + text redaction for secure-file. Pure — no heavy deps."""
from __future__ import annotations


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
        key = (typ, val)
        if key in labels:
            continue
        counters[typ] = counters.get(typ, 0) + 1
        labels[key] = "{{%s_%d}}" % (title_case(typ), counters[typ])
    return labels


def redact_text(text: str, labels: dict[tuple[str, str], str]) -> str:
    """Replace every occurrence of each value with its label. Longest values
    first so a shorter value can't clobber a longer overlapping one."""
    for (_typ, val), label in sorted(labels.items(), key=lambda kv: -len(kv[0][1])):
        if val:
            text = text.replace(val, label)
    return text
