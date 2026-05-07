#!/usr/bin/env python3
"""Fine-tune `distilbert-base-multilingual-cased` on locally-synthesized
PII training data in the rubai-format schema (`original` text +
parallel `types` per whitespace token).

Used for our Uzbekistan-banking-specific synth corpus
(`data/train_{ru,uz_latin,uz_cyrillic}.jsonl`) which expanded the label
space from rubai's 5 classes to 13 (LOAN_AMOUNT, SALARY, CARD_NUMBER,
BANK_ACCOUNT, TRANSACTION_ID, PINFL, STIR, CREDIT_AGREEMENT_ID, EMAIL,
NAME, PHONE, ADDRESS, DOCUMENT_ID — all entity types tagged as `TEXT`
become `O`).

USAGE
    # Uzbek model on Latin + Cyrillic synth (10k rows, ~15 min on MPS)
    .venv-train/bin/python scripts/train_synth_ner.py \\
        --input data/train_uz_latin.jsonl data/train_uz_cyrillic.jsonl \\
        --output secureprompt-ml/app/resources/uzbek_ner_synth_v1 \\
        --epochs 3 --device mps

    # Russian model on synth Russian (5k rows, ~10 min on MPS)
    .venv-train/bin/python scripts/train_synth_ner.py \\
        --input data/train_ru.jsonl \\
        --output secureprompt-ml/app/resources/russian_ner_synth_v1 \\
        --epochs 3 --device mps

DESIGN NOTES
  * Auto-detects entity labels from the data (anything ≠ "TEXT") rather
    than hardcoding — avoids stale constants when the synth schema
    evolves. The detected label set is written to `labels.json`.
  * Trains into a fresh directory; does NOT overwrite the production
    checkpoints at `app/resources/uzbek_ner_xlmr/` or `russian_ner/`.
    The `xlmr_ner.maybe_register` auto-discovery picks up any
    `*_ner*/model/` dir, so once you A/B-test these and decide they
    win, swap dir names atomically (rename the dirs).
  * Model: distilbert-base-multilingual-cased (66M params) — same
    backbone as the production checkpoints, fits MPS comfortably.
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


def detect_labels(paths: list[Path]) -> list[str]:
    """Scan all input files once to enumerate every non-TEXT entity tag."""
    seen: set[str] = set()
    for p in paths:
        with p.open() as f:
            for line in f:
                row = json.loads(line)
                for t in row.get("types") or []:
                    if t != "TEXT":
                        seen.add(t)
    return sorted(seen)


def build_label_map(entity_labels: list[str]) -> tuple[list[str], dict[str, int]]:
    bio = ["O"]
    for ent in entity_labels:
        bio.append(f"B-{ent}")
        bio.append(f"I-{ent}")
    return bio, {l: i for i, l in enumerate(bio)}


def to_bio(types: list[str], entity_labels: set[str]) -> list[str]:
    """`TEXT` → `O`. Adjacent same-label tokens form spans (B-X / I-X)."""
    out: list[str] = []
    prev = "TEXT"
    for label in types:
        if label == "TEXT" or label not in entity_labels:
            out.append("O")
        elif label == prev:
            out.append(f"I-{label}")
        else:
            out.append(f"B-{label}")
        prev = label
    return out


def stream_rows(
    paths: list[Path],
    label_to_id: dict[str, int],
    entity_labels: set[str],
    max_rows: int | None,
) -> Iterable[dict]:
    yielded = skipped = 0
    for path in paths:
        with path.open() as f:
            for line in f:
                row = json.loads(line)
                tokens = row.get("original", "").split()
                types = row.get("types") or []
                if len(tokens) != len(types) or not tokens:
                    skipped += 1
                    continue
                bio = to_bio(types, entity_labels)
                yield {
                    "tokens": tokens,
                    "ner_tags": [label_to_id[t] for t in bio],
                }
                yielded += 1
                if max_rows is not None and yielded >= max_rows:
                    print(f"[stream] yielded={yielded:,} skipped={skipped:,} (capped)")
                    return
    print(f"[stream] yielded={yielded:,} skipped={skipped:,}")


@dataclass
class Args:
    input: list[Path]
    output: Path
    model: str
    epochs: int
    batch_size: int
    learning_rate: float
    max_rows: int | None
    val_split: float
    max_length: int
    seed: int
    device: str


def parse_args() -> Args:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", nargs="+", required=True, type=Path,
                    help="One or more rubai-format JSONL files. Concatenated into one corpus.")
    ap.add_argument("--output", required=True, type=Path,
                    help="Output dir (NOT an existing production checkpoint).")
    ap.add_argument("--model", default="distilbert-base-multilingual-cased",
                    help="Base encoder. Must be HF AutoModelForTokenClassification-compatible.")
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--learning-rate", type=float, default=2e-5)
    ap.add_argument("--max-rows", type=int, default=None)
    ap.add_argument("--val-split", type=float, default=0.05)
    ap.add_argument("--max-length", type=int, default=256)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--device", choices=("auto", "cpu", "mps", "cuda"), default="auto")
    ns = ap.parse_args()
    for p in ns.input:
        if not p.exists():
            raise SystemExit(f"input file not found: {p}")
    return Args(
        input=ns.input, output=ns.output, model=ns.model,
        epochs=ns.epochs, batch_size=ns.batch_size,
        learning_rate=ns.learning_rate, max_rows=ns.max_rows,
        val_split=ns.val_split, max_length=ns.max_length,
        seed=ns.seed, device=ns.device,
    )


def make_tokenize_and_align(tokenizer, max_length: int):
    def fn(examples):
        tokenized = tokenizer(
            examples["tokens"],
            truncation=True,
            is_split_into_words=True,
            padding=False,
            max_length=max_length,
        )
        labels_out = []
        for i in range(len(examples["tokens"])):
            word_ids = tokenized.word_ids(batch_index=i)
            tags = examples["ner_tags"][i]
            current = None
            ids: list[int] = []
            for w in word_ids:
                if w is None:
                    ids.append(-100)
                elif w != current:
                    ids.append(tags[w])
                    current = w
                else:
                    ids.append(-100)
            labels_out.append(ids)
        tokenized["labels"] = labels_out
        return tokenized
    return fn


def main() -> None:
    args = parse_args()
    random.seed(args.seed)

    import numpy as np
    import torch
    from datasets import Dataset
    from transformers import (
        AutoModelForTokenClassification,
        AutoTokenizer,
        DataCollatorForTokenClassification,
        Trainer,
        TrainingArguments,
    )
    import evaluate

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    print(f"[main] inputs: {[str(p) for p in args.input]}")
    print("[main] scanning labels …")
    entity_labels = detect_labels(args.input)
    if not entity_labels:
        raise SystemExit("no non-TEXT labels found in input — nothing to learn")
    print(f"[main] detected {len(entity_labels)} entity types: {entity_labels}")

    bio_labels, label_to_id = build_label_map(entity_labels)
    id_to_label = {i: l for l, i in label_to_id.items()}
    print(f"[main] BIO label space: {len(bio_labels)} tags")

    print("[main] streaming rows …")
    rows = list(stream_rows(
        args.input, label_to_id, set(entity_labels), args.max_rows,
    ))
    if not rows:
        raise SystemExit("no rows; check input format")
    print(f"[main] usable rows: {len(rows):,}")

    random.shuffle(rows)
    n_val = max(1, int(len(rows) * args.val_split))
    val_rows = rows[:n_val]
    train_rows = rows[n_val:]
    print(f"[main] split: train={len(train_rows):,} val={len(val_rows):,}")

    train_ds = Dataset.from_list(train_rows)
    val_ds = Dataset.from_list(val_rows)

    print(f"[main] loading {args.model} …")
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForTokenClassification.from_pretrained(
        args.model,
        num_labels=len(bio_labels),
        id2label=id_to_label,
        label2id=label_to_id,
    )

    tok_align = make_tokenize_and_align(tokenizer, args.max_length)
    train_ds = train_ds.map(tok_align, batched=True, remove_columns=train_ds.column_names)
    val_ds = val_ds.map(tok_align, batched=True, remove_columns=val_ds.column_names)

    collator = DataCollatorForTokenClassification(tokenizer)
    seqeval = evaluate.load("seqeval")

    def compute_metrics(eval_pred):
        preds, refs = eval_pred
        preds = np.argmax(preds, axis=2)
        true_labels = [
            [id_to_label[r] for r, p in zip(ref, pred) if r != -100]
            for ref, pred in zip(refs, preds)
        ]
        true_preds = [
            [id_to_label[p] for r, p in zip(ref, pred) if r != -100]
            for ref, pred in zip(refs, preds)
        ]
        results = seqeval.compute(predictions=true_preds, references=true_labels)
        out = {
            "precision": results.get("overall_precision", 0.0),
            "recall": results.get("overall_recall", 0.0),
            "f1": results.get("overall_f1", 0.0),
            "accuracy": results.get("overall_accuracy", 0.0),
        }
        for ent in entity_labels:
            stats = results.get(ent)
            if isinstance(stats, dict):
                out[f"{ent}_f1"] = stats.get("f1", 0.0)
        return out

    args.output.mkdir(parents=True, exist_ok=True)

    use_cpu = args.device == "cpu"
    use_mps = False
    if args.device == "auto":
        if torch.backends.mps.is_available() and torch.backends.mps.is_built():
            use_mps = True
        elif not torch.cuda.is_available():
            use_cpu = True
    elif args.device == "mps":
        if not (torch.backends.mps.is_available() and torch.backends.mps.is_built()):
            raise SystemExit("--device mps requested but MPS unavailable")
        use_mps = True
    elif args.device == "cuda":
        if not torch.cuda.is_available():
            raise SystemExit("--device cuda requested but CUDA unavailable")
    print(f"[main] device: cpu={use_cpu} mps={use_mps} cuda={torch.cuda.is_available()}")

    training_args = TrainingArguments(
        output_dir=str(args.output / "checkpoints"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        weight_decay=0.01,
        warmup_ratio=0.1,
        eval_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=1,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        logging_steps=25,
        report_to="none",
        seed=args.seed,
        use_cpu=use_cpu,
        use_mps_device=use_mps,
        disable_tqdm=True,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        tokenizer=tokenizer,
        data_collator=collator,
        compute_metrics=compute_metrics,
    )

    print("[main] starting training …")
    trainer.train()

    print("[main] final eval …")
    final = trainer.evaluate()
    for k, v in sorted(final.items()):
        if isinstance(v, float):
            print(f"  {k}: {v:.4f}")

    final_path = args.output / "model"
    print(f"[main] saving model → {final_path}")
    trainer.save_model(str(final_path))
    tokenizer.save_pretrained(str(final_path))

    (args.output / "final_metrics.json").write_text(
        json.dumps(
            {k: v for k, v in final.items() if isinstance(v, (int, float))},
            indent=2,
        )
    )
    (args.output / "labels.json").write_text(
        json.dumps({"labels": bio_labels, "entities": entity_labels}, indent=2)
    )
    print(f"[main] done. checkpoint at {final_path}")


if __name__ == "__main__":
    main()
