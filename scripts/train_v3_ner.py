#!/usr/bin/env python3
"""Continue fine-tuning the v2 PII NER model on the v3 dataset.

Differences vs scripts/train_v2_ner.py:
  * Starts from the existing fine-tuned checkpoint at
    secureprompt-ml/app/resources/multilingual_ner_v2_xlmr/model (not xlm-roberta-base)
  * Reuses the existing label2id/id2label from that model's labels.json so the
    classifier head stays aligned (no random reinit)
  * Loads v3 data, adding uz_cyrillic alongside ru + uz_latin
  * Defaults to a lower learning rate (1e-5) since we're warm-starting

Per data/model_training_guide.md:
  * Supervision: `denorm_types` (fine regex tokenization)
  * Validation is domain-held-out — reported separately per language
  * Subword alignment: project token label to every subword piece
  * Early-stop / model-select on macro-F1 over non-O labels

USAGE
    .venv-train/bin/python scripts/train_v3_ner.py \\
        --data-dir data \\
        --base-model secureprompt-ml/app/resources/multilingual_ner_v2_xlmr/model \\
        --output secureprompt-ml/app/resources/multilingual_ner_v3_xlmr \\
        --epochs 3 --batch-size 16 --lr 1e-5 --max-length 256

Smoke test:
    .venv-train/bin/python scripts/train_v3_ner.py --smoke --epochs 1
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np
import torch
from datasets import Dataset
from sklearn.metrics import classification_report, f1_score
from transformers import (
    AutoModelForTokenClassification,
    AutoTokenizer,
    DataCollatorForTokenClassification,
    Trainer,
    TrainingArguments,
)

# Fine regex tokenizer — must reproduce the lengths recorded in `denorm_types`.
_FINE_TOKEN_RE = re.compile(
    r"""
    [\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+
    | \d{1,3}(?:\.\d{1,3}){3}
    | \w+(?:[’'\-]\w+)*
    | [^\w\s]
    """,
    re.UNICODE | re.VERBOSE,
)
_EMAIL_RE = re.compile(r"^[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+$", re.UNICODE)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_UNDERSCORE_SPLIT = re.compile(r"(_)")
_CAMEL_SPLIT = re.compile(r"(?<=[a-zа-яё])(?=[A-ZА-ЯЁ])", re.UNICODE)


def fine_tokenize(text: str) -> list[str]:
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


# v3 filenames: train_ru_v3, train_uz_latin_v3, train_uz_cyrillic_v3 (+ val_*)
LANG_FILES = [
    ("ru", "ru"),
    ("uz_latin", "uz_latn"),
    ("uz_cyrillic", "uz_cyrl"),
]


def load_split(data_dir: Path, split: str, smoke: bool) -> list[Row]:
    rows: list[Row] = []
    for file_lang, tag in LANG_FILES:
        path = data_dir / f"{split}_{file_lang}_v3.jsonl"
        if not path.exists():
            raise FileNotFoundError(path)
        for r in load_jsonl(path, tag):
            rows.append(r)
            if smoke and len(rows) >= 300:
                return rows
    return rows


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


def build_compute_metrics(id2label: dict[int, str]):
    def _strip(tag: str) -> str:
        return tag if tag == "O" else tag.split("-", 1)[1]

    def compute(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
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
        return {"non_o_macro_f1": macro, "non_o_micro_f1": micro}

    return compute


def per_language_report(trainer, datasets_by_lang, id2label):
    def _strip(tag):
        return tag if tag == "O" else tag.split("-", 1)[1]

    lines: list[str] = []
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
        lines.append(f"\n=== Language: {lang}  (n_tokens_eval={len(flat_true)}) ===")
        lines.append(f"  non-O macro F1: {macro:.4f}")
        lines.append(f"  non-O micro F1: {micro:.4f}")
        lines.append("\n  Per-label classification report:")
        lines.append(classification_report(flat_true, flat_pred, labels=non_o, digits=4, zero_division=0))
    return "\n".join(lines)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--data-dir", type=Path, default=Path("data"))
    p.add_argument(
        "--base-model",
        type=Path,
        default=Path("secureprompt-ml/app/resources/multilingual_ner_v2_xlmr/model"),
        help="Path to existing fine-tuned model to continue training from.",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=Path("secureprompt-ml/app/resources/multilingual_ner_v3_xlmr"),
    )
    p.add_argument("--max-length", type=int, default=192)
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--batch-size", type=int, default=4)
    p.add_argument("--grad-accum", type=int, default=4, help="gradient accumulation steps; effective batch = batch-size * grad-accum")
    p.add_argument("--eval-batch-size", type=int, default=8)
    p.add_argument("--lr", type=float, default=1e-5)
    p.add_argument("--weight-decay", type=float, default=0.01)
    p.add_argument("--warmup-ratio", type=float, default=0.06)
    p.add_argument("--seed", type=int, default=13)
    p.add_argument("--device", default=None)
    p.add_argument("--smoke", action="store_true")
    p.add_argument("--grad-checkpoint", action="store_true", default=True, help="enable gradient checkpointing (saves memory, ~25%% slower)")
    p.add_argument("--no-grad-checkpoint", dest="grad_checkpoint", action="store_false")
    p.add_argument(
        "--drop-labels",
        nargs="*",
        default=[],
        help="Entity labels to drop from the schema (e.g. SOCIAL_SECURITY_NUMBER). "
             "Both B- and I- variants are removed; matching tokens in train/val are remapped to O. "
             "Classifier head is rebuilt with surviving labels and warm-started from the matching rows of the base model.",
    )
    return p.parse_args()


def pick_device(arg: str | None) -> str:
    if arg:
        return arg
    if torch.cuda.is_available():
        return "cuda"
    if torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def drop_labels_from_schema(
    label2id: dict[str, int],
    id2label: dict[int, str],
    drop: list[str],
) -> tuple[dict[str, int], dict[int, str], dict[int, int]]:
    """Remove B-/I- variants of dropped entities and return contiguous-id remap.

    Returns (new_label2id, new_id2label, old_id -> new_id mapping for survivors).
    """
    dropped_bio = set()
    for ent in drop:
        dropped_bio.add(f"B-{ent}")
        dropped_bio.add(f"I-{ent}")
    surviving = [(old_id, lbl) for lbl, old_id in sorted(label2id.items(), key=lambda kv: kv[1]) if lbl not in dropped_bio]
    new_label2id: dict[str, int] = {}
    new_id2label: dict[int, str] = {}
    old_to_new: dict[int, int] = {}
    for new_id, (old_id, lbl) in enumerate(surviving):
        new_label2id[lbl] = new_id
        new_id2label[new_id] = lbl
        old_to_new[old_id] = new_id
    return new_label2id, new_id2label, old_to_new


def transplant_classifier_head(model, old_to_new: dict[int, int], new_num_labels: int):
    """Copy rows of the existing token-classification head for surviving labels.

    XLM-RoBERTa exposes the head at `model.classifier` (Linear(hidden, num_labels)).
    We allocate a fresh Linear with new_num_labels and copy the rows whose old id
    survives, leaving the dropped rows discarded.
    """
    import torch.nn as nn
    old_head = model.classifier
    hidden = old_head.in_features
    new_head = nn.Linear(hidden, new_num_labels, bias=old_head.bias is not None)
    with torch.no_grad():
        for old_id, new_id in old_to_new.items():
            new_head.weight[new_id].copy_(old_head.weight[old_id])
            if old_head.bias is not None:
                new_head.bias[new_id].copy_(old_head.bias[old_id])
    model.classifier = new_head
    model.num_labels = new_num_labels
    model.config.num_labels = new_num_labels
    return model


def load_existing_labels(base_model_dir: Path) -> tuple[dict[str, int], dict[int, str]]:
    """Reuse the v2 model's labels.json so the classifier head matches exactly."""
    labels_path = base_model_dir.parent / "labels.json"
    if not labels_path.exists():
        raise FileNotFoundError(
            f"Expected labels.json next to base model at {labels_path}. "
            "The classifier head order must be reused to avoid head reinitialization."
        )
    blob = json.loads(labels_path.read_text())
    label2id = {k: int(v) for k, v in blob["label2id"].items()}
    id2label = {int(k): v for k, v in blob["id2label"].items()}
    return label2id, id2label


def main():
    args = parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    print(f"[base ] {args.base_model}")
    label2id, id2label = load_existing_labels(args.base_model)
    print(f"  reused label set: {len(label2id)} entries")

    old_to_new: dict[int, int] | None = None
    if args.drop_labels:
        print(f"[drop ] removing labels: {args.drop_labels}")
        label2id, id2label, old_to_new = drop_labels_from_schema(label2id, id2label, args.drop_labels)
        print(f"  new label set: {len(label2id)} entries (was {len(label2id) + 2 * len(args.drop_labels)})")

    print(f"[load ] {args.data_dir}/{{train,val}}_{{ru,uz_latin,uz_cyrillic}}_v3.jsonl")
    train_rows = load_split(args.data_dir, "train", args.smoke)
    val_rows = load_split(args.data_dir, "val", args.smoke)
    print(f"  train: {len(train_rows)}  val: {len(val_rows)}")

    train_label_counter = Counter(t for r in train_rows for t in r.bio_tags)
    new_in_train = set(train_label_counter) - set(label2id)
    if new_in_train:
        print(f"  [warn] {len(new_in_train)} labels seen in train but absent from base model; remapping to O: {sorted(new_in_train)}")
        for r in train_rows:
            r.bio_tags = [t if t in label2id else "O" for t in r.bio_tags]
    val_unknown = {t for r in val_rows for t in r.bio_tags} - set(label2id)
    if val_unknown:
        print(f"  [warn] {len(val_unknown)} labels in val absent from base model; remapping to O")
        for r in val_rows:
            r.bio_tags = [t if t in label2id else "O" for t in r.bio_tags]

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

    tokenizer = AutoTokenizer.from_pretrained(str(args.base_model), add_prefix_space=True)
    if old_to_new is not None:
        # Load with the ORIGINAL head shape so weights match, then transplant.
        model = AutoModelForTokenClassification.from_pretrained(str(args.base_model))
        model = transplant_classifier_head(model, old_to_new, new_num_labels=len(label2id))
        model.config.id2label = id2label
        model.config.label2id = label2id
        print(f"  transplanted classifier head: {len(old_to_new)} rows copied, head reshaped to {len(label2id)}")
    else:
        model = AutoModelForTokenClassification.from_pretrained(
            str(args.base_model),
            num_labels=len(label2id),
            id2label=id2label,
            label2id=label2id,
        )

    align = make_align_fn(tokenizer, label2id, args.max_length)
    train_tok = train_ds.map(align, batched=True, remove_columns=["tokens", "bio_tags"], desc="align train")
    val_tok = val_ds.map(align, batched=True, remove_columns=["tokens", "bio_tags"], desc="align val")

    device = pick_device(args.device)
    fp16 = device == "cuda"
    print(f"[train] device={device}  fp16={fp16}  lr={args.lr}  epochs={args.epochs}")

    training_args = TrainingArguments(
        output_dir=str(args.output / "trainer"),
        use_cpu=(device == "cpu"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.eval_batch_size,
        gradient_accumulation_steps=args.grad_accum,
        gradient_checkpointing=args.grad_checkpoint,
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

    print("\n[final eval] per-language report")
    val_by_lang = {
        lang: val_tok.filter(lambda x: x["language"] == lang).remove_columns(["language", "domain"])
        for lang in ("ru", "uz_latn", "uz_cyrl")
    }
    report = per_language_report(trainer, val_by_lang, id2label)
    (args.output / "eval_report.txt").write_text(report)
    print(report)
    print(f"\n[done] saved under {args.output}")


if __name__ == "__main__":
    main()
