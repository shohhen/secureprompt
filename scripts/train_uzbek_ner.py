#!/usr/bin/env python3
"""Fine-tune `xlm-roberta-base` on `islomov/rubai-NER-150K-Personal` for
Uzbek/Russian PII token classification.

The rubai dataset stores token-level entity tags as a parallel array (one
label per whitespace-tokenized word). We convert that to HuggingFace's
token-classification format (BIO scheme) and fine-tune XLM-RoBERTa for a
small number of epochs. The resulting checkpoint replaces or augments
`gliner_multi_pii-v1` for Uzbek-heavy traffic.

USAGE

    # one-time: clean venv with the right deps
    python3 -m venv .venv-train
    source .venv-train/bin/activate
    pip install --upgrade pip
    pip install -r scripts/requirements-train.txt

    # smoke test (a few minutes on CPU)
    python scripts/train_uzbek_ner.py --max-rows 500 --epochs 1 --output ./tmp-smoke

    # full run (hours on CPU, ~30 min on GPU)
    python scripts/train_uzbek_ner.py --output secureprompt-ml/app/resources/uzbek_ner_xlmr

The output directory is the standard HF model dir layout — drop it into
the ML sidecar's `app/resources/` and load with
`AutoModelForTokenClassification.from_pretrained(path)`.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

# All ML deps are imported lazily inside `main()` so that running
# `--help` doesn't require torch/transformers to be installed.

DATASETS = {
    "rubai": {
        "repo": "islomov/rubai-NER-150K-Personal",
        "file": "data.jsonl",
        "format": "rubai_token",  # token-parallel labels
    },
    "russian": {
        "repo": "wolframko/russian-pii-66k",
        "file": "data/train-00000-of-00001.parquet",
        "format": "russian_span",  # character-span annotations
    },
}

# Unified label space — both datasets get mapped onto these 5 entity types
# so we can train one model architecture per dataset and the inference
# wrapper (`xlmr_ner.py`) treats them identically.
RAW_LABELS = ["NAME", "DATE", "PHONE", "ADDRESS", "DOCUMENT_ID"]

# Russian dataset labels → unified label space. Anything not listed
# (EMAIL, USERNAME, PASSWORD) is dropped at conversion time and gets
# handled by Presidio's deterministic regex recognizers further down
# the pipeline.
_RUSSIAN_LABEL_MAP = {
    "GIVENNAME": "NAME",
    "SURNAME": "NAME",
    "DATEOFBIRTH": "DATE",
    "TELEPHONENUM": "PHONE",
    "STREET": "ADDRESS",
    "BUILDINGNUM": "ADDRESS",
    "CITY": "ADDRESS",
    "ZIPCODE": "ADDRESS",
    "IDCARDNUM": "DOCUMENT_ID",
    "ACCOUNTNUM": "DOCUMENT_ID",
    "SOCIALNUM": "DOCUMENT_ID",
    "TAXNUM": "DOCUMENT_ID",
    "DRIVERLICENSENUM": "DOCUMENT_ID",
    "CREDITCARDNUMBER": "DOCUMENT_ID",
}


def build_label_map() -> tuple[list[str], dict[str, int]]:
    """Standard BIO scheme: `O`, then `B-X` / `I-X` for each rubai entity."""
    labels = ["O"]
    for ent in RAW_LABELS:
        labels.append(f"B-{ent}")
        labels.append(f"I-{ent}")
    label_to_id = {label: i for i, label in enumerate(labels)}
    return labels, label_to_id


def to_bio(types: list[str]) -> list[str]:
    """Convert rubai's flat token labels (e.g. `[NAME, NAME, TEXT, …]`) to
    BIO tags (`[B-NAME, I-NAME, O, …]`). Adjacent tokens with the same
    non-TEXT label are part of the same span; the first becomes B-, the
    rest I-.
    """
    out: list[str] = []
    prev = "TEXT"
    for label in types:
        if label == "TEXT" or label not in RAW_LABELS:
            out.append("O")
        elif label == prev:
            out.append(f"I-{label}")
        else:
            out.append(f"B-{label}")
        prev = label
    return out


def _stream_rubai(path: Path, max_rows: int | None, label_to_id: dict) -> Iterable[dict]:
    yielded = 0
    skipped = 0
    with path.open() as f:
        for line in f:
            row = json.loads(line)
            tokens = row.get("original", "").split()
            types = row.get("types") or []
            if len(tokens) != len(types) or not tokens:
                skipped += 1
                continue
            bio = to_bio(types)
            yield {
                "tokens": tokens,
                "ner_tags": [label_to_id[tag] for tag in bio],
            }
            yielded += 1
            if max_rows is not None and yielded >= max_rows:
                break
    print(f"[stream rubai] yielded={yielded:,}  skipped={skipped:,}")


def _spans_to_token_labels(text: str, spans: list) -> tuple:
    """Convert char-level span annotations to whitespace-token + parallel
    label arrays (same shape as rubai's `tokens` / `types`).

    For each whitespace token we check whether its char-range overlaps any
    privacy_mask span; the first overlapping span wins. Adjacent same-label
    tokens become I-tags through `to_bio` later.
    """
    word_spans = [(m.start(), m.end(), m.group(0)) for m in re.finditer(r"\S+", text)]
    if not word_spans:
        return [], []
    mapped = []
    for s in spans:
        lbl = _RUSSIAN_LABEL_MAP.get(s.get("label", ""))
        if lbl is None:
            continue
        try:
            mapped.append((int(s["start"]), int(s["end"]), lbl))
        except (KeyError, TypeError, ValueError):
            continue
    tokens, types = [], []
    for w_start, w_end, w_text in word_spans:
        match = "TEXT"
        for s_start, s_end, s_lbl in mapped:
            if w_start < s_end and w_end > s_start:
                match = s_lbl
                break
        tokens.append(w_text)
        types.append(match)
    return tokens, types


def _stream_russian(path: Path, max_rows: int | None, label_to_id: dict) -> Iterable[dict]:
    import pyarrow.parquet as pq
    yielded = 0
    skipped = 0
    table = pq.read_table(str(path))
    for row in table.to_pylist():
        text = row.get("source_text") or ""
        spans = row.get("privacy_mask") or []
        if not text or not spans:
            skipped += 1
            continue
        tokens, types = _spans_to_token_labels(text, spans)
        if not tokens:
            skipped += 1
            continue
        bio = to_bio(types)
        yield {
            "tokens": tokens,
            "ner_tags": [label_to_id[tag] for tag in bio],
        }
        yielded += 1
        if max_rows is not None and yielded >= max_rows:
            break
    print(f"[stream russian] yielded={yielded:,}  skipped={skipped:,}")


def stream_dataset(path: Path, max_rows: int | None, fmt: str) -> Iterable[dict]:
    _, label_to_id = build_label_map()
    if fmt == "rubai_token":
        yield from _stream_rubai(path, max_rows, label_to_id)
    elif fmt == "russian_span":
        yield from _stream_russian(path, max_rows, label_to_id)
    else:
        raise ValueError(f"unknown dataset format: {fmt}")


def download_dataset(repo: str, file: str) -> Path:
    from huggingface_hub import hf_hub_download
    p = hf_hub_download(repo_id=repo, filename=file, repo_type="dataset")
    return Path(p)


@dataclass
class Args:
    dataset: str
    model: str
    output: Path
    epochs: int
    batch_size: int
    learning_rate: float
    max_rows: int | None
    val_split: float
    max_length: int
    seed: int
    fp16: bool
    device: str


def parse_args() -> Args:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", choices=tuple(DATASETS.keys()), default="rubai",
                    help="Source dataset to fine-tune on (default: rubai = Uzbek)")
    ap.add_argument("--model", default="xlm-roberta-base",
                    help="HF model id of the base encoder (default: xlm-roberta-base)")
    ap.add_argument("--output", required=True, type=Path,
                    help="Output directory for the trained model")
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--learning-rate", type=float, default=2e-5)
    ap.add_argument("--max-rows", type=int, default=None,
                    help="Cap on rows to use (smoke testing)")
    ap.add_argument("--val-split", type=float, default=0.05)
    ap.add_argument("--max-length", type=int, default=256)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--fp16", action="store_true",
                    help="Enable mixed-precision training (CUDA only — MPS doesn't support fp16 well)")
    ap.add_argument("--device", choices=("auto", "cpu", "mps", "cuda"), default="auto",
                    help="Force a specific compute device (default: auto = MPS if available else CPU)")
    ns = ap.parse_args()
    return Args(
        dataset=ns.dataset,
        model=ns.model,
        output=ns.output,
        epochs=ns.epochs,
        batch_size=ns.batch_size,
        learning_rate=ns.learning_rate,
        max_rows=ns.max_rows,
        val_split=ns.val_split,
        max_length=ns.max_length,
        seed=ns.seed,
        fp16=ns.fp16,
        device=ns.device,
    )


def make_tokenize_and_align(tokenizer, label_to_id, max_length):
    """Return a function suitable for HF Datasets.map().

    XLM-R uses subword tokenization, so each whitespace token gets split
    into N subwords. We assign the original word's BIO label to the first
    subword and `-100` (ignore) to the rest, which is the canonical HF
    pattern for token classification.
    """
    def fn(examples):
        tokenized = tokenizer(
            examples["tokens"],
            truncation=True,
            is_split_into_words=True,
            padding=False,
            max_length=max_length,
        )
        labels_out = []
        for i, word_ids in enumerate(
            tokenized.word_ids(batch_index=j) for j in range(len(examples["tokens"]))
        ):
            tags = examples["ner_tags"][i]
            current_word = None
            label_ids = []
            for word_id in word_ids:
                if word_id is None:
                    label_ids.append(-100)
                elif word_id != current_word:
                    label_ids.append(tags[word_id])
                    current_word = word_id
                else:
                    # Subword continuation: ignore in loss.
                    label_ids.append(-100)
            labels_out.append(label_ids)
        tokenized["labels"] = labels_out
        return tokenized

    return fn


def main():
    args = parse_args()
    random.seed(args.seed)

    # Lazy ML imports (kept out of --help path).
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

    labels, label_to_id = build_label_map()
    id_to_label = {i: lab for lab, i in label_to_id.items()}

    cfg = DATASETS[args.dataset]
    print(f"[main] dataset={args.dataset} ({cfg['repo']})")
    source = download_dataset(cfg["repo"], cfg["file"])
    print(f"[main] dataset → {source} ({source.stat().st_size / 1e6:.1f} MB)")

    print(f"[main] streaming rows (max={args.max_rows or '∞'}) …")
    rows = list(stream_dataset(source, args.max_rows, cfg["format"]))
    if not rows:
        raise SystemExit("no rows after tokenization filter; check the dataset")
    print(f"[main] usable rows: {len(rows):,}")

    random.shuffle(rows)
    n_val = max(1, int(len(rows) * args.val_split))
    val_rows = rows[:n_val]
    train_rows = rows[n_val:]
    print(f"[main] split: train={len(train_rows):,}  val={len(val_rows):,}")

    train_ds = Dataset.from_list(train_rows)
    val_ds = Dataset.from_list(val_rows)

    print(f"[main] loading tokenizer + model: {args.model}")
    tokenizer = AutoTokenizer.from_pretrained(args.model, add_prefix_space=False)
    model = AutoModelForTokenClassification.from_pretrained(
        args.model,
        num_labels=len(labels),
        id2label=id_to_label,
        label2id=label_to_id,
    )

    tok_align = make_tokenize_and_align(tokenizer, label_to_id, args.max_length)
    train_ds = train_ds.map(tok_align, batched=True, remove_columns=train_ds.column_names)
    val_ds = val_ds.map(tok_align, batched=True, remove_columns=val_ds.column_names)

    collator = DataCollatorForTokenClassification(tokenizer)
    metric = evaluate.load("seqeval")

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
        results = metric.compute(predictions=true_preds, references=true_labels)
        return {
            "precision": results.get("overall_precision", 0.0),
            "recall": results.get("overall_recall", 0.0),
            "f1": results.get("overall_f1", 0.0),
            "accuracy": results.get("overall_accuracy", 0.0),
            **{
                f"{ent}_f1": results.get(ent, {}).get("f1", 0.0)
                for ent in RAW_LABELS
            },
        }

    args.output.mkdir(parents=True, exist_ok=True)

    # Device selection: HF Trainer reads `use_cpu`/`use_mps_device` from
    # TrainingArguments; we map our `--device` flag onto those here.
    use_cpu = args.device == "cpu"
    use_mps_device = False
    if args.device == "auto":
        if torch.backends.mps.is_available() and torch.backends.mps.is_built():
            use_mps_device = True
        elif not torch.cuda.is_available():
            use_cpu = True
    elif args.device == "mps":
        if not (torch.backends.mps.is_available() and torch.backends.mps.is_built()):
            raise SystemExit("--device mps requested but MPS is not available")
        use_mps_device = True
    elif args.device == "cuda":
        if not torch.cuda.is_available():
            raise SystemExit("--device cuda requested but CUDA is not available")

    print(f"[main] device: cpu={use_cpu} mps={use_mps_device} cuda={torch.cuda.is_available()}")

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
        save_total_limit=2,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        logging_steps=50,
        report_to="none",
        fp16=args.fp16,
        seed=args.seed,
        use_cpu=use_cpu,
        use_mps_device=use_mps_device,
        # Disable tqdm so the Trainer's {loss, lr, epoch} lines flush cleanly
        # to a redirected stdout instead of being mixed with `\r` progress
        # bars (which get held in the upstream grep buffer).
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

    print("[main] final eval on val split …")
    final_metrics = trainer.evaluate()
    for k, v in sorted(final_metrics.items()):
        if isinstance(v, float):
            print(f"  {k}: {v:.4f}")

    final_path = args.output / "model"
    print(f"[main] saving model → {final_path}")
    trainer.save_model(str(final_path))
    tokenizer.save_pretrained(str(final_path))

    metrics_path = args.output / "final_metrics.json"
    metrics_path.write_text(
        json.dumps(
            {k: v for k, v in final_metrics.items() if isinstance(v, (int, float))},
            indent=2,
        )
    )
    labels_path = args.output / "labels.json"
    labels_path.write_text(json.dumps({"labels": labels}, indent=2))
    print(f"[main] done. checkpoint at {final_path}")


if __name__ == "__main__":
    main()
