#!/usr/bin/env python3
"""Train a multilingual PII token classifier on the v2 synthetic dataset.

Follows data/model_training_guide.md:
  * Supervision: `denorm_types` (fine regex tokenization)
  * Languages: Russian + Uzbek Latin only (v2)
  * Validation is domain-held-out — reported separately
  * Subword alignment: project token label to every subword piece
  * Early-stop / model-select on macro-F1 over non-O labels
  * Per-language + per-label metrics in the final report

USAGE
    .venv-train/bin/python scripts/train_v2_ner.py \\
        --data-dir data \\
        --output secureprompt-ml/app/resources/pii_v2_xlmr_ru_uzlatn \\
        --model xlm-roberta-base \\
        --epochs 4 --batch-size 16 --lr 3e-5 --max-length 256

Run a smoke test on a small slice first:
    .venv-train/bin/python scripts/train_v2_ner.py --smoke --epochs 1
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np
import torch
from datasets import Dataset
from sklearn.metrics import classification_report, f1_score, precision_recall_fscore_support
from transformers import (
    AutoModelForTokenClassification,
    AutoTokenizer,
    DataCollatorForTokenClassification,
    Trainer,
    TrainingArguments,
)

# ---------------------------------------------------------------------------
# Fine regex tokenizer — must reproduce the lengths recorded in `denorm_types`.
# Per the guide: emails, IPv4, alphanumeric words with apostrophes/hyphens,
# punctuation as standalone tokens. Order matters (emails/IP before bare words).
# ---------------------------------------------------------------------------
_FINE_TOKEN_RE = re.compile(
    r"""
    [\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+        # email
    | \d{1,3}(?:\.\d{1,3}){3}              # IPv4
    | \w+(?:[’'\-]\w+)*                    # word, allowing straight/curly apostrophe + hyphen
    | [^\w\s]                              # any single punctuation char
    """,
    re.UNICODE | re.VERBOSE,
)
_EMAIL_RE = re.compile(r"^[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+$", re.UNICODE)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_UNDERSCORE_SPLIT = re.compile(r"(_)")
# Camel-case boundary: lowercase letter followed by uppercase letter (Latin or Cyrillic).
_CAMEL_SPLIT = re.compile(r"(?<=[a-zа-яё])(?=[A-ZА-ЯЁ])", re.UNICODE)


def fine_tokenize(text: str) -> list[str]:
    """Reproduces the v2 generator's fine tokenization closely enough that
    most rows have len(tokens) == len(denorm_types). Mismatched rows are
    skipped at load time, so this only needs to be best-effort."""
    out: list[str] = []
    for raw in _FINE_TOKEN_RE.findall(text):
        if _EMAIL_RE.match(raw) or _IPV4_RE.match(raw):
            out.append(raw)
            continue
        for piece in _UNDERSCORE_SPLIT.split(raw):
            if not piece:
                continue
            if piece == "_":
                out.append("_")
                continue
            for sub in _CAMEL_SPLIT.split(piece):
                if sub:
                    out.append(sub)
    return out


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
@dataclass
class Row:
    tokens: list[str]
    bio_tags: list[str]
    language: str
    domain: str


def to_bio(types: list[str]) -> list[str]:
    out: list[str] = []
    prev: str | None = None
    for t in types:
        if t == "TEXT":
            out.append("O")
            prev = None
            continue
        if t == prev:
            out.append(f"I-{t}")
        else:
            out.append(f"B-{t}")
            prev = t
    return out


def load_jsonl(path: Path, language: str) -> Iterable[Row]:
    skipped = 0
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            text = rec["original"]
            denorm = rec["denorm_types"]
            tokens = fine_tokenize(text)
            if len(tokens) != len(denorm):
                skipped += 1
                continue
            yield Row(
                tokens=tokens,
                bio_tags=to_bio(denorm),
                language=language,
                domain=rec.get("domain", ""),
            )
    if skipped:
        print(f"  [{path.name}] skipped {skipped} rows with token-length mismatch")


def load_split(data_dir: Path, split: str, smoke: bool) -> list[Row]:
    files = [
        (data_dir / f"{split}_ru_v2.jsonl", "ru"),
        (data_dir / f"{split}_uz_latin_v2.jsonl", "uz_latn"),
    ]
    rows: list[Row] = []
    for path, lang in files:
        if not path.exists():
            raise FileNotFoundError(path)
        for r in load_jsonl(path, lang):
            rows.append(r)
            if smoke and len(rows) >= 200:
                return rows
    return rows


# ---------------------------------------------------------------------------
# Subword alignment
# ---------------------------------------------------------------------------
def make_align_fn(tokenizer, label2id: dict[str, int], max_length: int):
    def _align(batch):
        enc = tokenizer(
            batch["tokens"],
            is_split_into_words=True,
            truncation=True,
            max_length=max_length,
        )
        all_labels = []
        for i, tags in enumerate(batch["bio_tags"]):
            word_ids = enc.word_ids(batch_index=i)
            labels = []
            for wid in word_ids:
                if wid is None:
                    labels.append(-100)
                else:
                    labels.append(label2id[tags[wid]])
            all_labels.append(labels)
        enc["labels"] = all_labels
        return enc

    return _align


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def build_compute_metrics(id2label: dict[int, str]):
    def _strip_bio(tag: str) -> str:
        if tag in ("O", "PAD"):
            return tag
        return tag.split("-", 1)[1]

    def compute(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        flat_pred, flat_true = [], []
        for p_seq, l_seq in zip(preds, labels):
            for p, l in zip(p_seq, l_seq):
                if l == -100:
                    continue
                flat_pred.append(_strip_bio(id2label[int(p)]))
                flat_true.append(_strip_bio(id2label[int(l)]))
        non_o_labels = sorted({lbl for lbl in flat_true if lbl != "O"})
        macro = f1_score(flat_true, flat_pred, labels=non_o_labels, average="macro", zero_division=0)
        micro = f1_score(flat_true, flat_pred, labels=non_o_labels, average="micro", zero_division=0)
        return {"non_o_macro_f1": macro, "non_o_micro_f1": micro}

    return compute


def per_language_per_label_report(trainer, datasets_by_lang, id2label):
    def _strip(tag):
        return tag if tag == "O" else tag.split("-", 1)[1]

    overall_lines: list[str] = []
    for lang, ds in datasets_by_lang.items():
        if len(ds) == 0:
            continue
        out = trainer.predict(ds)
        preds = np.argmax(out.predictions, axis=-1)
        labels = out.label_ids
        flat_pred, flat_true = [], []
        for p_seq, l_seq in zip(preds, labels):
            for p, l in zip(p_seq, l_seq):
                if l == -100:
                    continue
                flat_pred.append(_strip(id2label[int(p)]))
                flat_true.append(_strip(id2label[int(l)]))
        non_o = sorted({lbl for lbl in flat_true if lbl != "O"})
        macro = f1_score(flat_true, flat_pred, labels=non_o, average="macro", zero_division=0)
        micro = f1_score(flat_true, flat_pred, labels=non_o, average="micro", zero_division=0)
        overall_lines.append(f"\n=== Language: {lang}  (n_tokens_eval={len(flat_true)}) ===")
        overall_lines.append(f"  non-O macro F1: {macro:.4f}")
        overall_lines.append(f"  non-O micro F1: {micro:.4f}")
        overall_lines.append("\n  Per-label classification report:")
        overall_lines.append(
            classification_report(flat_true, flat_pred, labels=non_o, digits=4, zero_division=0)
        )
    return "\n".join(overall_lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--data-dir", type=Path, default=Path("data"))
    p.add_argument(
        "--output",
        type=Path,
        default=Path("secureprompt-ml/app/resources/multilingual_ner_v2_xlmr"),
    )
    p.add_argument("--model", default="xlm-roberta-base")
    p.add_argument("--max-length", type=int, default=256)
    p.add_argument("--epochs", type=int, default=4)
    p.add_argument("--batch-size", type=int, default=16)
    p.add_argument("--eval-batch-size", type=int, default=32)
    p.add_argument("--lr", type=float, default=3e-5)
    p.add_argument("--weight-decay", type=float, default=0.01)
    p.add_argument("--warmup-ratio", type=float, default=0.06)
    p.add_argument("--seed", type=int, default=13)
    p.add_argument("--device", default=None, help="cpu | mps | cuda; auto-detect if omitted")
    p.add_argument("--smoke", action="store_true", help="200-row sanity run")
    return p.parse_args()


def pick_device(arg: str | None) -> str:
    if arg:
        return arg
    if torch.cuda.is_available():
        return "cuda"
    if torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def main():
    args = parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    print(f"[load] {args.data_dir}/{{train,val}}_{{ru,uz_latin}}_v2.jsonl")
    train_rows = load_split(args.data_dir, "train", args.smoke)
    val_rows = load_split(args.data_dir, "val", args.smoke)
    print(f"  train: {len(train_rows)}  val: {len(val_rows)}")

    # Build label set from train (then ensure val labels are a subset).
    label_counter = Counter()
    for r in train_rows:
        label_counter.update(r.bio_tags)
    labels_sorted = ["O"] + sorted(lb for lb in label_counter if lb != "O")
    label2id = {lb: i for i, lb in enumerate(labels_sorted)}
    id2label = {i: lb for lb, i in label2id.items()}
    val_unknown = {t for r in val_rows for t in r.bio_tags} - set(label2id)
    if val_unknown:
        print(f"  [warn] val contains {len(val_unknown)} labels absent from train; remapping to O")
        for r in val_rows:
            r.bio_tags = [t if t in label2id else "O" for t in r.bio_tags]
    print(f"  labels: {len(labels_sorted)} (O + {len(labels_sorted)-1} entity BIO tags)")

    def to_hf(rows: list[Row]) -> Dataset:
        return Dataset.from_dict(
            {
                "tokens": [r.tokens for r in rows],
                "bio_tags": [r.bio_tags for r in rows],
                "language": [r.language for r in rows],
                "domain": [r.domain for r in rows],
            }
        )

    train_ds = to_hf(train_rows)
    val_ds = to_hf(val_rows)

    tokenizer = AutoTokenizer.from_pretrained(args.model, add_prefix_space=True)
    model = AutoModelForTokenClassification.from_pretrained(
        args.model,
        num_labels=len(labels_sorted),
        id2label=id2label,
        label2id=label2id,
    )

    align = make_align_fn(tokenizer, label2id, args.max_length)
    train_tok = train_ds.map(
        align, batched=True, remove_columns=["tokens", "bio_tags"], desc="align train"
    )
    val_tok = val_ds.map(
        align, batched=True, remove_columns=["tokens", "bio_tags"], desc="align val"
    )

    device = pick_device(args.device)
    fp16 = device == "cuda"
    print(f"[train] device={device}  fp16={fp16}")

    training_args = TrainingArguments(
        output_dir=str(args.output / "trainer"),
        use_cpu=(device == "cpu"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.eval_batch_size,
        learning_rate=args.lr,
        weight_decay=args.weight_decay,
        warmup_ratio=args.warmup_ratio,
        eval_strategy="epoch",
        save_strategy="epoch",
        logging_steps=50,
        load_best_model_at_end=True,
        metric_for_best_model="non_o_macro_f1",
        greater_is_better=True,
        save_total_limit=2,
        fp16=fp16,
        seed=args.seed,
        report_to=[],
        remove_unused_columns=False,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_tok.remove_columns(["language", "domain"]),
        eval_dataset=val_tok.remove_columns(["language", "domain"]),
        tokenizer=tokenizer,
        data_collator=DataCollatorForTokenClassification(tokenizer),
        compute_metrics=build_compute_metrics(id2label),
    )

    trainer.train()
    trainer.save_model(str(args.output / "model"))
    tokenizer.save_pretrained(str(args.output / "model"))
    (args.output / "labels.json").write_text(
        json.dumps({"id2label": id2label, "label2id": label2id}, ensure_ascii=False, indent=2)
    )

    print("\n[final eval] computing per-language + per-label report")
    val_by_lang = {
        lang: val_tok.filter(lambda x: x["language"] == lang).remove_columns(["language", "domain"])
        for lang in ("ru", "uz_latn")
    }
    report = per_language_per_label_report(trainer, val_by_lang, id2label)
    (args.output / "eval_report.txt").write_text(report)
    print(report)
    print(f"\n[done] model + labels + report saved under {args.output}")


if __name__ == "__main__":
    main()
