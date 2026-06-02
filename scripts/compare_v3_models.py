#!/usr/bin/env python3
"""Empirical head-to-head: multilingual_ner_v3_xlmr vs multilingual_ner_v3_no_ssn_xlmr.

Both checkpoints share the same architecture and (nearly) the same label
schema — `_no_ssn` was trained with SOCIAL_SECURITY_NUMBER dropped from the
head, on the theory that the regex recognizer in the gateway handles SSNs
more reliably than the NER head (v3's SSN F1 is ~0.0 in ru/uz, see each
model's eval_report.txt). This script answers the practical question the
team needs before picking a default per the empirical-before-swap rule:

  1. Does dropping SSN measurably *help the other labels* (less head
     capacity wasted on a class it can't learn)?
  2. What exactly do we give up on SSN by dropping it from the head?

It re-uses the *exact* tokenization, BIO projection, and first-subword
alignment from scripts/train_v3_ner.py so the numbers are comparable to the
checkpoints' own eval_report.txt (same supervision, same val split).

USAGE
    .venv-train/bin/python scripts/compare_v3_models.py
    .venv-train/bin/python scripts/compare_v3_models.py --max-length 256 --batch-size 16
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import classification_report, f1_score

# Reuse the canonical data pipeline from the trainer so eval matches training.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from train_v3_ner import LANG_FILES, Row, load_jsonl  # noqa: E402

from transformers import AutoModelForTokenClassification, AutoTokenizer  # noqa: E402

RES = Path("secureprompt-ml/app/resources")
MODELS = {
    "v3": RES / "multilingual_ner_v3_xlmr",
    "v3_no_ssn": RES / "multilingual_ner_v3_no_ssn_xlmr",
}


def strip(tag: str) -> str:
    return tag if tag == "O" else tag.split("-", 1)[1]


def load_val_rows(data_dir: Path) -> dict[str, list[Row]]:
    """Validation rows grouped by language tag (ru / uz_latn / uz_cyrl)."""
    by_lang: dict[str, list[Row]] = {}
    for file_lang, tag in LANG_FILES:
        path = data_dir / f"val_{file_lang}_v3.jsonl"
        if not path.exists():
            raise FileNotFoundError(path)
        by_lang[tag] = list(load_jsonl(path, tag))
    return by_lang


def pick_device(arg: str | None) -> str:
    if arg:
        return arg
    if torch.cuda.is_available():
        return "cuda"
    if torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def predict_flat(
    model_dir: Path,
    rows_by_lang: dict[str, list[Row]],
    max_length: int,
    batch_size: int,
    device: str,
) -> dict[str, tuple[list[str], list[str]]]:
    """Run one checkpoint over every language; return (gold, pred) entity-type
    sequences per language, aligned on first-subword positions only.

    Gold tags absent from this model's label space (e.g. SSN for the _no_ssn
    head) are remapped to O — exactly how train_v3_ner treats `val_unknown`,
    so the comparison stays fair to how each model was actually trained.
    """
    tok = AutoTokenizer.from_pretrained(str(model_dir / "model"), add_prefix_space=True)
    model = AutoModelForTokenClassification.from_pretrained(str(model_dir / "model"))
    model.eval().to(device)
    id2label = {int(i): l for i, l in model.config.id2label.items()}
    label_space = set(id2label.values())

    out: dict[str, tuple[list[str], list[str]]] = {}
    for lang, rows in rows_by_lang.items():
        flat_pred: list[str] = []
        flat_true: list[str] = []
        for start in range(0, len(rows), batch_size):
            batch = rows[start : start + batch_size]
            enc = tok(
                [r.tokens for r in batch],
                is_split_into_words=True,
                truncation=True,
                max_length=max_length,
                padding=True,
                return_tensors="pt",
            ).to(device)
            with torch.no_grad():
                logits = model(**enc).logits
            preds = logits.argmax(dim=-1).cpu().numpy()
            for i, r in enumerate(batch):
                word_ids = enc.word_ids(batch_index=i)
                seen: set[int] = set()
                for tok_idx, wid in enumerate(word_ids):
                    if wid is None or wid in seen:
                        continue
                    seen.add(wid)
                    gold = r.bio_tags[wid]
                    if gold not in label_space:
                        gold = "O"  # SSN for _no_ssn → O (regex owns it downstream)
                    flat_true.append(strip(gold))
                    flat_pred.append(strip(id2label[int(preds[i][tok_idx])]))
        out[lang] = (flat_true, flat_pred)
    return out


def macro_micro(true: list[str], pred: list[str], labels: list[str]) -> tuple[float, float]:
    macro = f1_score(true, pred, labels=labels, average="macro", zero_division=0)
    micro = f1_score(true, pred, labels=labels, average="micro", zero_division=0)
    return macro, micro


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, default=Path("data"))
    ap.add_argument("--max-length", type=int, default=256)
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--device", default=None)
    ap.add_argument("--report-dir", type=Path, default=Path("scripts"))
    args = ap.parse_args()

    for name, d in MODELS.items():
        if not (d / "model").exists():
            print(f"[error] missing model dir: {d/'model'}", file=sys.stderr)
            return 1

    device = pick_device(args.device)
    print(f"[device] {device}")
    rows_by_lang = load_val_rows(args.data_dir)
    for lang, rows in rows_by_lang.items():
        print(f"  val {lang}: {len(rows)} rows")

    results = {
        name: predict_flat(d, rows_by_lang, args.max_length, args.batch_size, device)
        for name, d in MODELS.items()
    }

    lines: list[str] = []

    def emit(s: str = "") -> None:
        print(s)
        lines.append(s)

    emit("\n" + "=" * 72)
    emit("HEAD-TO-HEAD: v3 vs v3_no_ssn  (non-O F1 over each model's own labels)")
    emit("=" * 72)
    emit(f"{'lang':<10}{'v3 macro':>10}{'v3 micro':>10}{'nossn macro':>13}{'nossn micro':>13}")
    for lang in rows_by_lang:
        t_v3, p_v3 = results["v3"][lang]
        t_ns, p_ns = results["v3_no_ssn"][lang]
        non_o_v3 = sorted({l for l in t_v3 if l != "O"})
        non_o_ns = sorted({l for l in t_ns if l != "O"})
        ma_v3, mi_v3 = macro_micro(t_v3, p_v3, non_o_v3)
        ma_ns, mi_ns = macro_micro(t_ns, p_ns, non_o_ns)
        emit(f"{lang:<10}{ma_v3:>10.4f}{mi_v3:>10.4f}{ma_ns:>13.4f}{mi_ns:>13.4f}")

    # Apples-to-apples: restrict BOTH models to the shared label set (i.e.
    # exclude SSN entirely). This isolates the real question — did freeing
    # the head from SSN improve everything else? — from the SSN bookkeeping.
    emit("\n" + "-" * 72)
    emit("SHARED-LABELS (SSN excluded from scoring for both) — did dropping SSN help the rest?")
    emit("-" * 72)
    emit(f"{'lang':<10}{'v3 macro':>10}{'v3 micro':>10}{'nossn macro':>13}{'nossn micro':>13}")
    for lang in rows_by_lang:
        t_v3, p_v3 = results["v3"][lang]
        t_ns, p_ns = results["v3_no_ssn"][lang]
        shared = sorted(
            {l for l in t_v3 if l not in ("O", "SOCIAL_SECURITY_NUMBER")}
            & {l for l in t_ns if l != "O"}
        )
        ma_v3, mi_v3 = macro_micro(t_v3, p_v3, shared)
        ma_ns, mi_ns = macro_micro(t_ns, p_ns, shared)
        emit(f"{lang:<10}{ma_v3:>10.4f}{mi_v3:>10.4f}{ma_ns:>13.4f}{mi_ns:>13.4f}")

    # What v3 actually buys on SSN (the thing _no_ssn gives up at the head).
    emit("\n" + "-" * 72)
    emit("SSN at the NER head (v3 only; _no_ssn defers SSN to the gateway regex)")
    emit("-" * 72)
    for lang in rows_by_lang:
        t_v3, p_v3 = results["v3"][lang]
        support = sum(1 for l in t_v3 if l == "SOCIAL_SECURITY_NUMBER")
        if support == 0:
            emit(f"  {lang}: no SSN tokens in val")
            continue
        f1 = f1_score(t_v3, p_v3, labels=["SOCIAL_SECURITY_NUMBER"], average="micro", zero_division=0)
        emit(f"  {lang}: SSN support={support}  v3 SSN F1={f1:.4f}")

    # Full per-label report per model+language (audit trail).
    emit("\n" + "=" * 72)
    emit("FULL PER-LABEL REPORTS")
    emit("=" * 72)
    for name in MODELS:
        for lang in rows_by_lang:
            t, p = results[name][lang]
            non_o = sorted({l for l in t if l != "O"})
            emit(f"\n--- {name} / {lang}  (n_tokens={len(t)}) ---")
            emit(classification_report(t, p, labels=non_o, digits=4, zero_division=0))

    report_path = args.report_dir / "compare_v3_models_report.txt"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    emit(f"\n[done] wrote {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
