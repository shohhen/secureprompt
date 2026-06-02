#!/usr/bin/env python3
"""Dump per-label confusion for the v3 NER model on the val split.

For each true label, prints the top-K predicted labels and their token counts.
Useful for confirming collisions (e.g. SOCIAL_SECURITY_NUMBER tokens being
predicted as IDENTITY_CARD_NUMBER).

USAGE
    .venv-train/bin/python scripts/dump_v3_confusion.py \\
        --model secureprompt-ml/app/resources/multilingual_ner_v3_xlmr/model \\
        --data-dir data \\
        --focus SOCIAL_SECURITY_NUMBER IDENTITY_CARD_NUMBER TAX_IDENTIFICATION_NUMBER PINFL
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import torch
from datasets import Dataset
from transformers import AutoModelForTokenClassification, AutoTokenizer

# Reuse loaders from train script (same dir).
import sys
sys.path.insert(0, str(Path(__file__).parent))
from train_v3_ner import LANG_FILES, load_jsonl, make_align_fn  # noqa: E402


def strip_bio(tag: str) -> str:
    return tag if tag == "O" else tag.split("-", 1)[1]


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--model", type=Path, default=Path("secureprompt-ml/app/resources/multilingual_ner_v3_xlmr/model"))
    p.add_argument("--data-dir", type=Path, default=Path("data"))
    p.add_argument("--max-length", type=int, default=192)
    p.add_argument("--batch-size", type=int, default=8)
    p.add_argument("--top-k", type=int, default=5, help="Top-K predictions to show per true label")
    p.add_argument("--focus", nargs="*", default=["SOCIAL_SECURITY_NUMBER", "IDENTITY_CARD_NUMBER", "TAX_IDENTIFICATION_NUMBER", "PINFL"],
                   help="Print pairwise collision table for these labels")
    p.add_argument("--device", default=None)
    return p.parse_args()


def pick_device(arg):
    if arg:
        return arg
    if torch.cuda.is_available():
        return "cuda"
    if torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def main():
    args = parse_args()
    labels_path = args.model.parent / "labels.json"
    blob = json.loads(labels_path.read_text())
    label2id = {k: int(v) for k, v in blob["label2id"].items()}
    id2label = {int(k): v for k, v in blob["id2label"].items()}

    tokenizer = AutoTokenizer.from_pretrained(str(args.model), add_prefix_space=True)
    model = AutoModelForTokenClassification.from_pretrained(str(args.model))
    device = pick_device(args.device)
    model.to(device).eval()
    print(f"[load] model={args.model}  device={device}")

    # Load val rows for all three languages.
    rows = []
    for file_lang, tag in LANG_FILES:
        path = args.data_dir / f"val_{file_lang}_v3.jsonl"
        for r in load_jsonl(path, tag):
            rows.append(r)
    print(f"[load] val rows: {len(rows)}")

    ds = Dataset.from_dict({
        "tokens": [r.tokens for r in rows],
        "bio_tags": [r.bio_tags for r in rows],
    })
    align = make_align_fn(tokenizer, label2id, args.max_length)
    tok = ds.map(align, batched=True, remove_columns=["tokens", "bio_tags"], desc="align val")

    # confusion[true_entity][pred_entity] = token count (BIO stripped)
    confusion: dict[str, Counter] = defaultdict(Counter)

    from torch.utils.data import DataLoader
    from transformers import DataCollatorForTokenClassification
    collator = DataCollatorForTokenClassification(tokenizer)
    loader = DataLoader(tok, batch_size=args.batch_size, collate_fn=collator)

    with torch.no_grad():
        for batch in loader:
            batch = {k: v.to(device) for k, v in batch.items()}
            logits = model(**{k: v for k, v in batch.items() if k != "labels"}).logits
            preds = logits.argmax(dim=-1).cpu().numpy()
            labels = batch["labels"].cpu().numpy()
            for p_seq, l_seq in zip(preds, labels):
                for p, l in zip(p_seq, l_seq):
                    if l == -100:
                        continue
                    t_ent = strip_bio(id2label[int(l)])
                    p_ent = strip_bio(id2label[int(p)])
                    confusion[t_ent][p_ent] += 1

    # Top-K per true label, sorted by total support descending.
    print(f"\n=== Top-{args.top_k} predictions per true label (token-level, BIO stripped) ===\n")
    rows_out = sorted(confusion.items(), key=lambda kv: -sum(kv[1].values()))
    for true_ent, preds in rows_out:
        total = sum(preds.values())
        if true_ent == "O":
            continue
        top = preds.most_common(args.top_k)
        line = f"  {true_ent:<35} total={total:>6}  | " + "  ".join(
            f"{p}={c} ({c/total:.2%})" for p, c in top
        )
        print(line)

    # Focused pairwise: rows = focus labels (true), cols = all labels they leak to.
    focus = [f for f in args.focus if f in confusion]
    if focus:
        print(f"\n=== Focus: {', '.join(focus)} ===\n")
        all_pred_ents = sorted({p for f in focus for p in confusion[f]})
        # Print a compact table.
        col_w = max(12, max(len(c) for c in all_pred_ents) + 2)
        header = "true \\ pred".ljust(35) + "".join(c.ljust(col_w) for c in all_pred_ents)
        print(header)
        for f in focus:
            total = sum(confusion[f].values())
            cells = []
            for c in all_pred_ents:
                v = confusion[f].get(c, 0)
                pct = f"{v}({v/total:.0%})" if total else "0"
                cells.append(pct.ljust(col_w))
            print(f"{f:<35}" + "".join(cells))

    # Also report inbound: who predicts AS these focus labels (i.e. false positives).
    if focus:
        print(f"\n=== Inbound: which true labels get predicted AS each focus label ===\n")
        for f in focus:
            inbound = Counter()
            for true_ent, preds in confusion.items():
                if preds.get(f):
                    inbound[true_ent] += preds[f]
            total_in = sum(inbound.values())
            if not total_in:
                print(f"  {f}: never predicted")
                continue
            top = inbound.most_common(args.top_k)
            print(f"  predicted as {f} (total {total_in} tokens):")
            for true_ent, cnt in top:
                print(f"    from true={true_ent:<35} {cnt}  ({cnt/total_in:.2%})")

    out_path = args.model.parent / "confusion_dump.txt"
    print(f"\n[done] (rerun with --top-k to widen; written to console only — pipe to {out_path} if you want a file)")


if __name__ == "__main__":
    main()
