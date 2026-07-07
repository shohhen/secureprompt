#!/usr/bin/env python3
r"""v6 NER data front-end: char-span JSONL -> whitespace-word BIO.

The ONE genuinely new piece for the v6 retrain. Mirrors the runtime decode
(app/detection/xlmr_ner.py) and the held-out eval (eval_heldout_xlmr.py):
whitespace `\S+` words, one BIO tag per word, so TRAINING and INFERENCE tokenize
identically. Char-span entities are aligned to words by MAXIMUM character overlap
(ties -> earliest entity by start), which maps agglutinated suffixes
("APEXBANKda") and punctuation-adjacent entities onto whole words the way the
runtime's word-level head expects.

Also loads the classification head (label2id/id2label) verbatim from a model
config.json so v6 reuses v5_cold's exact 85-class head order.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_WORD_RE = re.compile(r"\S+")


def spanjsonl_to_bio(text: str, entities: list[dict]) -> tuple[list[str], list[str]]:
    """Return (words, bio_tags) of equal length for one record.

    A word takes the label of the entity it overlaps most; a new `B-` starts
    whenever the overlapping SOURCE ENTITY changes, so two adjacent same-label
    entities split correctly. No overlap -> "O".
    """
    words = [(m.start(), m.end(), m.group()) for m in _WORD_RE.finditer(text)]
    # sort by (start, end) so equal-overlap ties resolve to the earliest entity
    ents = sorted(enumerate(entities), key=lambda kv: (kv[1]["start"], kv[1]["end"]))
    tokens: list[str] = []
    tags: list[str] = []
    prev_ei: int | None = None
    for ws, we, w in words:
        best_ei: int | None = None
        best_ov = 0
        best_label: str | None = None
        for orig_i, e in ents:
            ov = min(we, e["end"]) - max(ws, e["start"])
            if ov > best_ov:
                best_ov, best_ei, best_label = ov, orig_i, e["label"]
        tokens.append(w)
        if best_label is None:
            tags.append("O")
            prev_ei = None
        else:
            tags.append(f"I-{best_label}" if best_ei == prev_ei else f"B-{best_label}")
            prev_ei = best_ei
    return tokens, tags


def read_span_jsonl(path):
    """Yield (text, entities, lang) per JSONL row of the char-span schema."""
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        yield rec["text"], rec.get("entities", []), rec.get("lang", "")


def load_head_labels(config_json_path):
    """Read the exact (label2id, id2label) head from a model config.json — used
    to reuse v5_cold's 85-class head verbatim (order + count identical)."""
    cfg = json.loads(Path(config_json_path).read_text(encoding="utf-8"))
    id2label = {int(i): l for i, l in cfg["id2label"].items()}
    label2id = {l: i for i, l in id2label.items()}
    return label2id, id2label
