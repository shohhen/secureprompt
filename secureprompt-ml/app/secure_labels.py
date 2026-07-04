"""Placeholder labels + text redaction for secure-file. Pure — no heavy deps."""
from __future__ import annotations

import re


def title_case(entity_type: str) -> str:
    return "_".join(w.capitalize() for w in entity_type.split("_"))


# Wrapping quotes removed anywhere in the value (orgs are quoted inconsistently:
# `SECURETECH` vs `"SECURETECH"` vs `"SECURETECH" MCHJ`). Deliberately excludes
# the single/curly apostrophes ‘ ’ ' that are INSIDE Uzbek words (`O‘G‘LI`).
_WRAP_QUOTE_RE = re.compile(r'[“”"«»]')
# Leading/trailing punctuation trimmed after quote removal.
_EDGE_PUNCT = " .,;:()[]{}"
# Legal-entity forms that trail an org name (`"SECURETECH" MCHJ`).
_LEGAL_SUFFIX_RE = re.compile(r"\s+(?:mchj|mchz|ooo|ооо|aj|yoaj|xk|chp|qmj|qk)\b")
# Uzbek agglutinative case suffixes — longest first for greedy stripping. The
# same noun/name recurs with different endings (Jamiyat / Jamiyat*ga* /
# Jamiyat*ning*), which must resolve to one placeholder.
_UZ_SUFFIXES = (
    "lardagi", "larning", "lardan", "larga", "larni", "gacha",
    "ning", "dagi", "niki", "lari", "lar", "dan", "ga", "da", "ni", "si",
)


def _strip_uz_suffix(word: str) -> str:
    """Strip a trailing Uzbek case suffix, but only when >=3 chars remain (so
    short names like `Olga` keep their `-ga`)."""
    for suf in _UZ_SUFFIXES:
        if word.endswith(suf) and len(word) - len(suf) >= 3:
            return word[: -len(suf)]
    return word


def _canonical(entity_type: str, value: str) -> str:
    """Collapse surface variants of one entity to a single key: lowercase, drop
    edge quotes/punctuation, drop a trailing legal suffix (orgs), and strip a
    case suffix from the final word. Used ONLY to assign the shared label —
    redaction still targets each original surface form."""
    v = _WRAP_QUOTE_RE.sub(" ", value.lower())
    v = re.sub(r"\s+", " ", v).strip(_EDGE_PUNCT)
    if entity_type == "ORGANIZATION":
        v = _LEGAL_SUFFIX_RE.sub("", v).strip()
    parts = [p for p in v.split(" ") if p]
    if parts:
        parts[-1] = _strip_uz_suffix(parts[-1])
    return " ".join(parts).strip()


def build_labels(detections: list[dict]) -> dict[tuple[str, str], str]:
    """Map each (TYPE, surface value) -> `{{Type_N}}`. The per-type counter is
    keyed on the CANONICAL form so surface variants of one entity (quotes, legal
    suffix, Uzbek case endings) share a label; first-appearance order. Each
    original surface value is kept as a key so redaction still replaces every
    variant. No mapping is persisted (one-way)."""
    labels: dict[tuple[str, str], str] = {}
    canon_label: dict[tuple[str, str], str] = {}
    counters: dict[str, int] = {}
    for d in detections:
        typ = d["entity_type"].upper()
        val = d["text"]
        if not val:  # skip empty values so the visible sequence has no gaps
            continue
        skey = (typ, val)
        if skey in labels:
            continue
        ckey = (typ, _canonical(typ, val))
        label = canon_label.get(ckey)
        if label is None:
            counters[typ] = counters.get(typ, 0) + 1
            label = "{{%s_%d}}" % (title_case(typ), counters[typ])
            canon_label[ckey] = label
        labels[skey] = label
    return labels


def merge_overlapping_spans(detections: list[dict]) -> list[dict]:
    """Collapse overlapping SAME-TYPE detections to a single representative (the
    largest span). Different recognizers emit the same entity with different
    boundaries — `SECURETECH` vs `"SECURETECH"`, or a surname nested inside the
    full name — which would otherwise get separate placeholders and boxes.
    Cross-type overlaps (a secret inside a name) are left for redact_spans.
    Returns detections sorted by start offset (first-appearance order)."""
    by_type: dict[str, list[dict]] = {}
    for d in detections:
        by_type.setdefault(d["entity_type"].upper(), []).append(d)
    out: list[dict] = []
    for group in by_type.values():
        group = sorted(group, key=lambda d: (d.get("start", 0), -(d.get("end", 0))))
        rep = None
        cluster_end = -1
        for d in group:
            s, e = d.get("start", 0), d.get("end", 0)
            if rep is not None and s < cluster_end:  # overlaps the open cluster
                cluster_end = max(cluster_end, e)
                if (e - s) > (rep.get("end", 0) - rep.get("start", 0)):
                    rep = d  # keep the widest span as the representative
            else:
                if rep is not None:
                    out.append(rep)
                rep, cluster_end = d, e
        if rep is not None:
            out.append(rep)
    out.sort(key=lambda d: d.get("start", 0))
    return out


def redact_spans(text: str, spans: list[tuple[int, int, str]]) -> str:
    """Splice each ``(char_start, char_end, label)`` range over ``text``.

    Span-based (not value-match) so the ORIGINAL bytes are removed — including any
    invisible noise inside the span (NBSP, zero-width, collapsed whitespace, soft
    line breaks) that makes the cleaned detection value differ from the document
    text. Overlapping spans (e.g. a secret nested inside an NER span) are
    de-overlapped by greedily keeping the longest, non-overlapping set; the chosen
    spans are then spliced right-to-left so earlier offsets stay valid.
    """
    valid = [(s, e, lbl) for (s, e, lbl) in spans if 0 <= s < e <= len(text)]
    valid.sort(key=lambda x: (x[0], -x[1]))  # start asc, longer first on ties
    chosen: list[tuple[int, int, str]] = []
    last_end = -1
    for s, e, lbl in valid:
        if s >= last_end:  # non-overlapping with the previously chosen span
            chosen.append((s, e, lbl))
            last_end = e
    for s, e, lbl in sorted(chosen, key=lambda x: x[0], reverse=True):
        text = text[:s] + lbl + text[e:]
    return text


def value_repeat_spans(text: str, by_value: dict[str, str]) -> list[tuple[int, int, str]]:
    """``(char_start, char_end, label)`` for every exact occurrence of each
    detected value in ``text``.

    Detection returns one span per occurrence it *found*, but the whole-document
    NER pass often reports a value once even when it repeats (e.g. a name in both
    the body and a header). Span-only redaction would then miss the repeat, so we
    additionally cover every clean occurrence of each already-detected value.
    Combined with the exact detection spans (which cover noisy forms a plain
    string match can't), overlaps are resolved by ``redact_spans``.
    """
    out: list[tuple[int, int, str]] = []
    for value, label in by_value.items():
        if not value:
            continue
        start = 0
        while (i := text.find(value, start)) >= 0:
            out.append((i, i + len(value), label))
            start = i + len(value)
    return out


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
