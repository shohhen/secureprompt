#!/usr/bin/env python3
"""Extract deterministic PII artifacts from `islomov/rubai-NER-150K-Personal`.

Outputs two files under `secureprompt-ml/app/resources/`:
  * `uzbek_names.txt`           — top-N single-token NAME values, one per line
  * `uzbek_document_id_patterns.json` — regex patterns inferred from DOCUMENT_ID

The ML sidecar (`ner.py`) loads these at startup as Presidio recognizers so
the Uzbek/Russian gap GLiNER currently has (see CV screenshot where
"Shohjahon" caught but "Rustamov" scored below threshold) gets covered by a
deterministic backup.

Dataset is fetched once via `huggingface_hub`; skip re-downloading by
re-running the script idempotently.
"""

from __future__ import annotations

import argparse
import json
import re
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path


DATASET_REPO = "islomov/rubai-NER-150K-Personal"
DATASET_FILE = "data.jsonl"


def download() -> Path:
    from huggingface_hub import hf_hub_download
    path = hf_hub_download(repo_id=DATASET_REPO, filename=DATASET_FILE, repo_type="dataset")
    return Path(path)


def normalize_name(tok: str) -> str:
    """Strip trailing punctuation and collapse case-insensitive variants."""
    # Unicode-safe strip of common sentence punctuation.
    tok = tok.strip(".,;:!?()[]{}\"'«»„“”—–-")
    return tok


def abstract_pattern(token: str) -> str:
    """Turn a concrete DOCUMENT_ID / PHONE token into a character-class regex.

    `AB3875021` → `[A-Z]{2}\\d{7}`, `9 7 046 24 19` → kept as-is (space-separated).
    We abstract only where the character class is obvious; digits, uppercase
    letters, lowercase letters. Anything else becomes an escaped literal.
    """
    out = []
    i = 0
    while i < len(token):
        c = token[i]
        if c.isdigit():
            j = i
            while j < len(token) and token[j].isdigit():
                j += 1
            out.append(rf"\d{{{j - i}}}")
            i = j
        elif c.isalpha() and c.isascii() and c.isupper():
            j = i
            while j < len(token) and token[j].isascii() and token[j].isalpha() and token[j].isupper():
                j += 1
            out.append(rf"[A-Z]{{{j - i}}}")
            i = j
        elif c.isalpha() and c.isascii() and c.islower():
            j = i
            while j < len(token) and token[j].isascii() and token[j].isalpha() and token[j].islower():
                j += 1
            out.append(rf"[a-z]{{{j - i}}}")
            i = j
        else:
            # Escape whatever it is (space, dash, Cyrillic letter, etc.)
            out.append(re.escape(c))
            i += 1
    return "".join(out)


def run(output_dir: Path, top_names: int, top_doc_patterns: int) -> None:
    source = download()
    print(f"[extract] dataset → {source} ({source.stat().st_size / 1024 / 1024:.1f} MB)")

    name_counts: Counter[str] = Counter()
    # Multi-token NAME spans (e.g. "Sardor Rustamov") for reference — not used
    # in the gazetteer because Presidio's deny_list matches single tokens.
    name_bigram_counts: Counter[str] = Counter()
    doc_id_counts: Counter[str] = Counter()
    doc_id_pattern_counts: Counter[str] = Counter()
    phone_counts: Counter[str] = Counter()
    per_domain: dict[str, int] = defaultdict(int)
    rows_with_name = 0
    rows_total = 0

    with source.open() as f:
        for raw in f:
            rows_total += 1
            row = json.loads(raw)
            per_domain[row.get("domain", "unknown")] += 1
            types = row.get("types") or []
            tokens = row.get("original", "").split()
            if len(tokens) != len(types):
                continue  # skip malformed rows (tokenization mismatch)

            has_name = False
            # Walk adjacent runs of equal labels so we can also capture
            # multi-token NAME spans like "Sardor Rustamov" as bigrams.
            i = 0
            while i < len(types):
                label = types[i]
                j = i
                while j < len(types) and types[j] == label:
                    j += 1
                span_tokens = tokens[i:j]
                if label == "NAME":
                    has_name = True
                    for tok in span_tokens:
                        clean = normalize_name(tok)
                        if clean and len(clean) >= 3:
                            name_counts[clean] += 1
                    if len(span_tokens) >= 2:
                        phrase = " ".join(normalize_name(t) for t in span_tokens)
                        if all(p for p in phrase.split()):
                            name_bigram_counts[phrase] += 1
                elif label == "DOCUMENT_ID":
                    for tok in span_tokens:
                        clean = tok.strip(".,;:)")
                        if clean:
                            doc_id_counts[clean] += 1
                            doc_id_pattern_counts[abstract_pattern(clean)] += 1
                elif label == "PHONE":
                    phrase = " ".join(span_tokens).strip(".,;:)")
                    if phrase:
                        phone_counts[phrase] += 1
                i = j
            if has_name:
                rows_with_name += 1

    print(f"[extract] rows_total={rows_total:,}  rows_with_name={rows_with_name:,}")
    print(f"[extract] unique_name_tokens={len(name_counts):,}  unique_bigrams={len(name_bigram_counts):,}")
    print(f"[extract] unique_doc_ids={len(doc_id_counts):,}  unique_doc_id_patterns={len(doc_id_pattern_counts):,}")
    print(f"[extract] unique_phone_strings={len(phone_counts):,}")

    # ----------------------------------------------------------------- names
    output_dir.mkdir(parents=True, exist_ok=True)
    names_path = output_dir / "uzbek_names.txt"
    top = name_counts.most_common(top_names)
    with names_path.open("w") as f:
        f.write("# Top Uzbek/Russian PII name tokens mined from "
                f"{DATASET_REPO}.\n")
        f.write(f"# Rows scanned: {rows_total:,}. Unique tokens: {len(name_counts):,}.\n")
        f.write(f"# Kept top {len(top)} by frequency; one token per line.\n")
        for tok, _count in top:
            f.write(tok + "\n")
    print(f"[extract] wrote {names_path} ({len(top):,} entries)")

    # -------------------------------------------------------- document ids
    doc_patterns_path = output_dir / "uzbek_document_id_patterns.json"
    top_patterns = doc_id_pattern_counts.most_common(top_doc_patterns)
    patterns = [
        {
            "regex": rf"\b{pat}\b",
            "count": count,
            "example": next(
                (ex for ex in doc_id_counts if abstract_pattern(ex) == pat),
                None,
            ),
        }
        for pat, count in top_patterns
        if count >= 3  # drop one-offs
    ]
    with doc_patterns_path.open("w") as f:
        json.dump(
            {
                "source": DATASET_REPO,
                "rows_scanned": rows_total,
                "patterns": patterns,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
    print(f"[extract] wrote {doc_patterns_path} ({len(patterns)} patterns)")

    # ----------------------------------------------------------- stats dump
    stats_path = output_dir / "_extraction_stats.json"
    with stats_path.open("w") as f:
        json.dump(
            {
                "rows_total": rows_total,
                "rows_with_name": rows_with_name,
                "unique_name_tokens": len(name_counts),
                "unique_doc_ids": len(doc_id_counts),
                "unique_doc_id_patterns": len(doc_id_pattern_counts),
                "unique_phones": len(phone_counts),
                "top_name_tokens": name_counts.most_common(20),
                "top_name_bigrams": name_bigram_counts.most_common(20),
                "top_doc_id_patterns": doc_id_pattern_counts.most_common(20),
                "top_phone_strings": phone_counts.most_common(20),
                "rows_per_domain": sorted(
                    per_domain.items(), key=lambda kv: -kv[1]
                ),
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
    print(f"[extract] wrote {stats_path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out",
        default=str(Path(__file__).resolve().parent.parent / "secureprompt-ml" / "app" / "resources"),
        help="Output directory for gazetteer + pattern JSON.",
    )
    ap.add_argument("--top-names", type=int, default=5000)
    ap.add_argument("--top-doc-patterns", type=int, default=40)
    args = ap.parse_args()
    run(Path(args.out), args.top_names, args.top_doc_patterns)
