#!/usr/bin/env python3
"""Retrain-v6 data augmentation (WS2 durable quality).

Generates span-format samples matching `data/*.jsonl`
(`{text, lang, entities:[{label,start,end,value}]}`) that target the residual
gaps the v5_cold model misses:

  1. résumé/document-style — a name header followed by dense technical prose
     (the model tags the header name `O` in this out-of-distribution layout).
  2. under-represented local ORGANIZATIONS (universities, local companies).
  3. standalone / low-context PERSON names (header position, no sentence).
  4. HARD NEGATIVES — cities -> ADDRESS (not PERSON), tech/library terms -> O
     (so `Ташкент`, `Eloquent ORM`, `Kafka` stop being tagged PERSON/ORG).

Offsets are character offsets (Python `len`), matching the dataset. Output:
`data/aug_v6_{ru,uz_latin,uz_cyrillic}.jsonl`. Deterministic (seeded).

Usage: python scripts/augment_v6.py --per-category 220 --out-dir data
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

# ── curated pools, per language variant ─────────────────────────────────────
NAMES = {
    "ru": [("Иван", "Петров"), ("Рахматилла", "Эркинов"), ("Ирина", "Павлова"),
           ("Дмитрий", "Соколов"), ("Акмал", "Каримов"), ("Нилуфар", "Юсупова"),
           ("Сергей", "Волков"), ("Малика", "Рахимова"), ("Жамшид", "Қодиров"),
           ("Олег", "Морозов"), ("Азиза", "Тошева"), ("Виктория", "Ким")],
    "uz_latn": [("Akmal", "Karimov"), ("Rahmatilla", "Erkinov"), ("Nilufar", "Yusupova"),
                ("Jamshid", "Qodirov"), ("Sardor", "Aliyev"), ("Dilnoza", "Tosheva"),
                ("Bekzod", "Rahimov"), ("Gulnora", "Ismoilova"), ("Sherzod", "Usmonov"),
                ("Kamola", "Saidova"), ("Ozod", "Yo'ldoshev"), ("Zarina", "Nazarova")],
    "uz_cyrl": [("Акмал", "Каримов"), ("Раҳматилла", "Эркинов"), ("Нилуфар", "Юсупова"),
                ("Жамшид", "Қодиров"), ("Сардор", "Алиев"), ("Дилноза", "Тошева"),
                ("Бекзод", "Раҳимов"), ("Гулнора", "Исмоилова"), ("Шерзод", "Усмонов"),
                ("Камола", "Саидова"), ("Озод", "Йўлдошев"), ("Зарина", "Назарова")],
}
ORGS = {
    "ru": ["Университет Новый Узбекистан", "Ташкентский государственный университет",
           "Yandex Uzbekistan", "AmoCRM", "OY Startech", "Smart Software",
           "Uztelecom", "Milliy Dastur", "Инха университет в Ташкенте", "EPAM Uzbekistan"],
    "uz_latn": ["Yangi Oʻzbekiston universiteti", "Toshkent axborot texnologiyalari universiteti",
                "Yandex Uzbekistan", "AmoCRM", "OY Startech", "Smart Software",
                "Uztelecom", "Milliy Dastur", "Inha universiteti", "EPAM Uzbekistan"],
    "uz_cyrl": ["Янги Ўзбекистон университети", "Тошкент ахборот технологиялари университети",
                "Yandex Uzbekistan", "AmoCRM", "OY Startech", "Smart Software",
                "Uztelecom", "Milliy Dastur", "Инха университети", "EPAM Uzbekistan"],
}
CITIES = {
    "ru": ["Ташкент", "Самарканд", "Бухара", "Андижан", "Наманган", "Фергана", "Москва"],
    "uz_latn": ["Toshkent", "Samarqand", "Buxoro", "Andijon", "Namangan", "Fargʻona", "Nukus"],
    "uz_cyrl": ["Тошкент", "Самарқанд", "Бухоро", "Андижон", "Наманган", "Фарғона", "Нукус"],
}
# tech/library terms — these must be learned as O (never PERSON/ORG)
TECH = ["Go", "Python", "C++", "PHP", "Java", "Kafka", "Postgres", "Redis", "MongoDB",
        "Docker", "Kubernetes", "gRPC", "REST API", "GraphQL", "Terraform", "GitLab CI",
        "GORM", "Eloquent ORM", "RabbitMQ", "ClickHouse", "Elasticsearch", "Nginx"]
JOBS = {
    "ru": ["Бэкенд-разработчик", "Инженер-программист", "Технический руководитель",
           "Backend разработчик", "Data-инженер", "DevOps-инженер"],
    "uz_latn": ["Backend dasturchi", "Dasturiy injener", "Texnik rahbar",
                "Data injener", "DevOps injener"],
    "uz_cyrl": ["Бэкенд дастурчи", "Дастурий инженер", "Техник раҳбар",
                "Дата инженер", "DevOps инженер"],
}
COUNTRY = {"ru": "Узбекистан", "uz_latn": "Oʻzbekiston", "uz_cyrl": "Ўзбекистон"}

# localized connective phrases: (worked_at, studied_at, lives_in, uses, name_is)
PHRASES = {
    "ru": dict(worked="работал в", studied="учился в", lives="живёт в",
               uses="использует", proj="проектировал микросервисы на",
               name_is="меня зовут", intro="разработчик"),
    "uz_latn": dict(worked="ishlagan", studied="oʻqigan", lives="yashaydi",
                    uses="ishlatadi", proj="mikroservislarni yozgan",
                    name_is="mening ismim", intro="dasturchi"),
    "uz_cyrl": dict(worked="ишлаган", studied="ўқиган", lives="яшайди",
                    uses="ишлатади", proj="микросервисларни ёзган",
                    name_is="менинг исмим", intro="дастурчи"),
}


def _build(parts: list[tuple[str, str | None]]) -> dict:
    """parts: list of (chunk_text, label|None). Returns {text, entities} with
    correct character offsets by construction."""
    text = ""
    ents = []
    for chunk, label in parts:
        start = len(text)
        text += chunk
        if label:
            ents.append({"label": label, "start": start, "end": start + len(chunk),
                         "value": chunk})
    return {"text": text, "entities": ents}


def gen_resume_header(rng, lang):
    g, s = rng.choice(NAMES[lang])
    return _build([(f"{g} {s}", "PERSON"), ("\n", None),
                   (rng.choice(CITIES[lang]), "ADDRESS"), (f", {COUNTRY[lang]}", None)])


def gen_resume_bio(rng, lang):
    g, s = rng.choice(NAMES[lang])
    p = PHRASES[lang]
    org = rng.choice(ORGS[lang])
    t1, t2, t3 = rng.sample(TECH, 3)
    # name header + dense technical bio; org labelled, tech terms left O
    return _build([(f"{g} {s}", "PERSON"), (" — ", None),
                   (rng.choice(JOBS[lang]), None), (f". {p['worked'].capitalize()} ", None),
                   (org, "ORGANIZATION"),
                   (f", {p['uses']} {t1}, {t2}, {t3}.", None)])


def gen_standalone_name(rng, lang):
    g, s = rng.choice(NAMES[lang])
    style = rng.random()
    if style < 0.5:
        return _build([(f"{g} {s}", "PERSON")])
    p = PHRASES[lang]
    return _build([(f"{p['name_is'].capitalize()} ", None), (f"{g} {s}", "PERSON"),
                   (f", {p['intro']}.", None)])


def gen_org_context(rng, lang):
    org = rng.choice(ORGS[lang])
    p = PHRASES[lang]
    verb = rng.choice([p["worked"], p["studied"]])
    return _build([(f"{verb.capitalize()} ", None), (org, "ORGANIZATION"), (".", None)])


def gen_hardneg_city(rng, lang):
    p = PHRASES[lang]
    return _build([(f"{p['lives'].capitalize()} ", None),
                   (rng.choice(CITIES[lang]), "ADDRESS"), (".", None)])


def gen_hardneg_tech(rng, lang):
    """Tech terms alongside a real name: only PERSON labelled, tech stays O."""
    g, s = rng.choice(NAMES[lang])
    p = PHRASES[lang]
    t1, t2 = rng.sample(TECH, 2)
    return _build([(f"{g} {s}", "PERSON"), (f" {p['uses']} {t1} ", None),
                   ("va" if lang != "ru" else "и", None), (f" {t2}.", None)])


CATEGORIES = [gen_resume_header, gen_resume_bio, gen_standalone_name,
              gen_org_context, gen_hardneg_city, gen_hardneg_tech]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-category", type=int, default=220,
                    help="samples per category per language")
    ap.add_argument("--out-dir", type=Path, default=Path("data"))
    ap.add_argument("--seed", type=int, default=13)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    totals = {}
    for lang in ("ru", "uz_latn", "uz_cyrl"):
        rng = random.Random(f"{args.seed}:{lang}")  # str seed -> deterministic
        rows = []
        for gen in CATEGORIES:
            for _ in range(args.per_category):
                rec = gen(rng, lang)
                rec["lang"] = "ru" if lang == "ru" else ("uz" if False else lang)
                rows.append(rec)
        rng.shuffle(rows)
        out = args.out_dir / f"aug_v6_{lang}.jsonl"
        with out.open("w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps({"text": r["text"], "lang": r["lang"],
                                    "entities": r["entities"]}, ensure_ascii=False) + "\n")
        totals[lang] = len(rows)
        print(f"[aug] {out}  ({len(rows)} samples)")
    print("total:", sum(totals.values()))


if __name__ == "__main__":
    main()
