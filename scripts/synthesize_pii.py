#!/usr/bin/env python3
"""Generate synthetic Russian / Uzbek-Latin / Uzbek-Cyrillic PII data via
the local `claude` CLI (Claude Code), in the wolframko/russian-pii-66k
schema (char-span annotations) so it slots straight into
`train_uzbek_ner.py`.

This variant uses `claude --print` (Option B of the synthesis plan) so
the tokens come off the user's existing Claude Code session quota
instead of a separate Anthropic API key. No `anthropic` SDK dependency.

USAGE
    nohup python scripts/synthesize_pii.py \\
        --total 20000 --concurrency 6 \\
        --output data/synthetic_pii.jsonl \\
        > /tmp/synth.log 2>&1 &

The script is **resumable**: rerunning with the same --output continues
from the last full record. Killing it mid-batch loses ≤ batch-size rows.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

MODEL = "claude-haiku-4-5-20251001"

LANGUAGES = ["ru", "uz-lat", "uz-cyr"]

LANGUAGE_HINTS = {
    "ru": {
        "name": "Russian",
        "script": "Cyrillic",
        "native_names": "Russian (Иванов, Петрова, Алексей, Мария)",
        "address_hint": "Russian streets and cities (ул. Тверская, г. Москва)",
        "phone_format": "+7 (XXX) XXX-XX-XX",
    },
    "uz-lat": {
        "name": "Uzbek (Latin script)",
        "script": "Latin",
        "native_names": "Uzbek Latin (Alisher Qodirov, Dilshod Rustamov, Madina)",
        "address_hint": "Uzbek streets (Mustaqillik ko'chasi, Toshkent shahri)",
        "phone_format": "+998 XX XXX XX XX",
    },
    "uz-cyr": {
        "name": "Uzbek (Cyrillic script)",
        "script": "Cyrillic with Uzbek letters ў ғ қ ҳ",
        "native_names": "Uzbek Cyrillic (Алишер Қодиров, Дилшод Рустамов, Мадина)",
        "address_hint": "Uzbek Cyrillic streets (Мустақиллик кўчаси, Тошкент шаҳри)",
        "phone_format": "+998 XX XXX XX XX",
    },
}

SCENARIOS = [
    "business email between colleagues about a project",
    "HR letter (offer, NDA, employment contract clause)",
    "invoice / receipt with line items and totals",
    "customer support ticket with a refund request",
    "bank statement excerpt or transfer notification",
    "travel booking confirmation (flight, hotel)",
    "medical appointment reminder or prescription",
    "real estate listing or rental contract clause",
    "internal memo about a policy change",
    "support-call transcript fragment",
    "shipping notification or delivery slip",
    "school admission letter or grade report",
]

ALLOWED_LABELS = (
    "GIVENNAME", "SURNAME", "ORGANIZATION",
    "STREET", "BUILDINGNUM", "CITY", "ZIPCODE",
    "EMAIL", "TELEPHONENUM", "USERNAME",
    "DATE", "DATEOFBIRTH",
    "IDCARDNUM", "ACCOUNTNUM", "CREDITCARDNUMBER",
    "SOCIALNUM", "TAXNUM", "DRIVERLICENSENUM",
)

SYSTEM_PROMPT = """You generate synthetic PII training data for a privacy
gateway. You produce realistic short documents (3-6 sentences) with
several PII entities embedded, and you list each entity's exact value
and label. The script computes character offsets later — you do NOT
emit offsets.

OUTPUT FORMAT — JSON array of records. Each record:
{
  "source_text": "<the document text>",
  "entities": [
    {"label": "<LABEL>", "value": "<exact substring of source_text>"},
    ...
  ]
}

RULES
1. `value` MUST be a verbatim substring of `source_text` — copy it,
   character-for-character including any punctuation that is part of
   the entity. Don't paraphrase. Don't add quotes.
2. Use only labels from this allowed set: GIVENNAME, SURNAME, ORGANIZATION,
   STREET, BUILDINGNUM, CITY, ZIPCODE, EMAIL, TELEPHONENUM, USERNAME,
   DATE, DATEOFBIRTH, IDCARDNUM, ACCOUNTNUM, CREDITCARDNUMBER, SOCIALNUM,
   TAXNUM, DRIVERLICENSENUM.
3. GIVENNAME = first name only, SURNAME = family name only. Tag them
   as separate entries.
4. ORGANIZATION = company / bank / school / government body name.
5. DATE = event/deadline/issue date. DATEOFBIRTH ONLY for actual
   birthdays.
6. If the same value appears multiple times in the text, list it once;
   the script will mark every occurrence.
7. Output ONLY the raw JSON array. No markdown fences. No commentary.

REALISM
- Mix native-language names with the requested foreign cameos.
- Address details should look natively-formatted for the language.
- Phone numbers use the format hint provided. Plausible but invented.
- Vary length, register, and structure across records.
"""

USER_TEMPLATE = """Generate {batch_size} records.

Language: {language_name} ({script})
Scenario: {scenario}
Native names: {native_names}
Address style: {address_hint}
Phone format: {phone_format}
Foreign-name cameos: {foreign_cameos}

Return a JSON array of exactly {batch_size} record objects. No prose,
no markdown fences — just the array."""

FOREIGN_NAME_POOL = [
    "Jordan", "Maya", "Bob Chen", "Sarah Miller", "Hiroshi Tanaka",
    "Liam Walker", "Aisha Khan", "Pedro Silva", "Anna Schneider",
    "Olivia Brown", "Wei Zhang", "Ahmed Hassan", "James O'Connor",
    "Zoe Martin", "Kim Park", "Lucas Rossi", "Greta Müller",
    "Sofia Ivanov-Smith",
]


@dataclass
class Args:
    total: int
    concurrency: int
    batch_size: int
    output: Path
    seed: int
    timeout: int
    max_budget_usd: float


def parse_args() -> Args:
    ap = argparse.ArgumentParser()
    ap.add_argument("--total", type=int, default=20_000)
    ap.add_argument("--concurrency", type=int, default=6,
                    help="Parallel `claude` subprocesses. CLI startup is heavy; 4-8 is the sweet spot.")
    ap.add_argument("--batch-size", type=int, default=10,
                    help="Records per claude call. 10 keeps the JSON array small and parseable.")
    ap.add_argument("--output", type=Path, default=Path("data/synthetic_pii.jsonl"))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--timeout", type=int, default=120,
                    help="Per-call wall-clock cap (seconds).")
    ap.add_argument("--max-budget-usd", type=float, default=0.10,
                    help="Per-call dollar cap, passed to `claude --max-budget-usd`.")
    a = ap.parse_args()
    return Args(
        total=a.total,
        concurrency=a.concurrency,
        batch_size=a.batch_size,
        output=a.output,
        seed=a.seed,
        timeout=a.timeout,
        max_budget_usd=a.max_budget_usd,
    )


def existing_count(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open() as f:
        return sum(1 for _ in f)


def normalize_record(rec: dict) -> Optional[dict]:
    """Take Haiku's `{source_text, entities: [{label,value}]}` shape and
    convert to the wolframko `{source_text, privacy_mask: [{start,end,label,value}]}`
    schema by computing offsets via `text.find()` over every occurrence
    of each value. Returns None if the record is malformed or contains
    no resolvable entities.
    """
    if not isinstance(rec, dict):
        return None
    text = rec.get("source_text")
    entities = rec.get("entities")
    if not isinstance(text, str) or not text:
        return None
    if not isinstance(entities, list):
        return None

    spans: list[dict] = []
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        label = ent.get("label")
        value = ent.get("value")
        if label not in ALLOWED_LABELS:
            continue
        if not isinstance(value, str) or not value:
            continue
        # Mark every occurrence of `value` in `text`.
        cursor = 0
        added = False
        while True:
            idx = text.find(value, cursor)
            if idx < 0:
                break
            spans.append({
                "start": idx,
                "end": idx + len(value),
                "label": label,
                "value": value,
            })
            cursor = idx + len(value)
            added = True
        if not added:
            # Value wasn't actually in the text — model paraphrased.
            # Skip silently.
            continue

    if not spans:
        return None
    # Sort by start for stable training-set behavior.
    spans.sort(key=lambda s: (s["start"], s["end"]))
    return {
        "source_text": text,
        "privacy_mask": spans,
    }


def make_user_prompt(rng: random.Random, batch_size: int) -> tuple[str, str]:
    language = rng.choice(LANGUAGES)
    hints = LANGUAGE_HINTS[language]
    scenario = rng.choice(SCENARIOS)
    cameos = (
        ", ".join(rng.sample(FOREIGN_NAME_POOL, k=rng.randint(1, 2)))
        if rng.random() < 0.30
        else "(none)"
    )
    return language, USER_TEMPLATE.format(
        batch_size=batch_size,
        language_name=hints["name"],
        script=hints["script"],
        scenario=scenario,
        native_names=hints["native_names"],
        address_hint=hints["address_hint"],
        phone_format=hints["phone_format"],
        foreign_cameos=cameos,
    )


def parse_batch(content: str) -> list[dict]:
    """Robustly parse the model's response. Strips markdown fences and
    leading prose if Haiku ignored the 'no prose' rule."""
    s = content.strip()
    # Drop ```json ... ``` if present
    if s.startswith("```"):
        s = re.sub(r"^```(?:json)?\s*", "", s)
        s = re.sub(r"\s*```$", "", s)
    # If the model added a leading sentence, find the first `[`
    bracket = s.find("[")
    if bracket > 0:
        s = s[bracket:]
    # Strip trailing junk after the array
    if not s.endswith("]"):
        last = s.rfind("]")
        if last > 0:
            s = s[: last + 1]
    data = json.loads(s)
    if not isinstance(data, list):
        raise ValueError("expected JSON array at top level")
    return data


async def run_claude(prompt: str, system: str, model: str, timeout: int, max_budget: float) -> str:
    """Invoke `claude --print --bare --model ...` once with the given user
    prompt and append-system-prompt. Returns the assistant text."""
    # NOTE: deliberately *not* using `--bare` here. `--bare` forces
    # Anthropic auth via ANTHROPIC_API_KEY only and disables OAuth /
    # keychain reads — which would defeat the whole point of running
    # this off the user's existing `claude` login. Trade-off: each call
    # initialises CLAUDE.md / hooks / skills, which adds startup cost
    # but keeps tokens on the Claude Code subscription quota.
    cmd = [
        "claude",
        "--print",
        "--no-session-persistence",
        "--model", model,
        "--max-budget-usd", str(max_budget),
        "--output-format", "json",
        "--append-system-prompt", system,
        prompt,
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError(f"claude CLI timed out after {timeout}s")
    if proc.returncode != 0:
        err_text = stderr.decode("utf-8", errors="replace")[:500]
        out_head = stdout.decode("utf-8", errors="replace")[:500]
        raise RuntimeError(
            f"claude CLI exit={proc.returncode} stderr={err_text!r} stdout={out_head!r}"
        )
    out_text = stdout.decode("utf-8", errors="replace")
    # `--output-format json` wraps the assistant message in a JSON envelope.
    try:
        envelope = json.loads(out_text)
        # Most envelopes look like {"result": "<text>"} or have a "messages" list.
        if isinstance(envelope, dict):
            if isinstance(envelope.get("result"), str):
                return envelope["result"]
            if isinstance(envelope.get("response"), str):
                return envelope["response"]
            # Newer envelopes: {"type":"result","subtype":"success","result":"..."}
            for k in ("text", "content"):
                if isinstance(envelope.get(k), str):
                    return envelope[k]
        # Fallback: assume stdout was already the text
    except json.JSONDecodeError:
        pass
    return out_text


async def generate_batch(rng, batch_size, model, timeout, max_budget):
    language, user = make_user_prompt(rng, batch_size)
    text = await run_claude(user, SYSTEM_PROMPT, model, timeout, max_budget)
    try:
        records = parse_batch(text)
    except Exception as e:
        print(
            f"[debug] parse failed ({e}); raw response head={text[:300]!r}",
            file=sys.stderr,
        )
        return []
    out = []
    dropped = 0
    for rec in records:
        normalized = normalize_record(rec)
        if normalized is None:
            dropped += 1
            continue
        normalized["language"] = language
        out.append(normalized)
    if dropped and len(out) == 0:
        print(
            f"[debug] all {len(records)} records dropped during normalize; "
            f"raw_head={text[:200]!r}",
            file=sys.stderr,
        )
    return out


async def worker(name, rng, queue, out_lock, out_fh, stats, args):
    while True:
        try:
            batch_request = await queue.get()
        except asyncio.CancelledError:
            return
        if batch_request is None:
            queue.task_done()
            return
        try:
            records = await generate_batch(
                rng, batch_request, MODEL, args.timeout, args.max_budget_usd,
            )
        except Exception as e:
            stats["errors"] += 1
            print(f"[{name}] batch failed: {e}", file=sys.stderr)
            queue.task_done()
            continue
        async with out_lock:
            for rec in records:
                out_fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            out_fh.flush()
            stats["written"] += len(records)
            if stats["written"] % 100 == 0 or stats["written"] >= stats["target"]:
                elapsed = time.time() - stats["start"]
                rate = stats["written"] / elapsed if elapsed > 0 else 0
                eta_sec = (stats["target"] - stats["written"]) / rate if rate > 0 else 0
                print(
                    f"[progress] {stats['written']:,}/{stats['target']:,}"
                    f"  ({rate:.1f} rec/s, errors={stats['errors']}, eta={eta_sec/60:.1f}min)",
                    file=sys.stderr,
                )
        queue.task_done()


async def main_async(args: Args):
    args.output.parent.mkdir(parents=True, exist_ok=True)
    already = existing_count(args.output)
    remaining = max(0, args.total - already)
    if remaining == 0:
        print(f"[done] {already:,} records already exist at {args.output}")
        return
    print(
        f"[start] target={args.total:,} existing={already:,} remaining={remaining:,}"
        f"  model={MODEL} concurrency={args.concurrency} batch_size={args.batch_size}",
        file=sys.stderr,
    )

    rng = random.Random(args.seed + already)

    queue: asyncio.Queue = asyncio.Queue()
    n_batches = (remaining + args.batch_size - 1) // args.batch_size
    for _ in range(n_batches):
        queue.put_nowait(args.batch_size)
    for _ in range(args.concurrency):
        queue.put_nowait(None)

    stats = {
        "written": 0,
        "errors": 0,
        "target": remaining,
        "start": time.time(),
    }
    with args.output.open("a", buffering=1) as out_fh:
        out_lock = asyncio.Lock()
        workers = [
            asyncio.create_task(
                worker(f"w{i}", rng, queue, out_lock, out_fh, stats, args)
            )
            for i in range(args.concurrency)
        ]
        await queue.join()
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
    elapsed = time.time() - stats["start"]
    print(
        f"[done] wrote {stats['written']:,} records in {elapsed/60:.1f} min "
        f"(errors={stats['errors']}). Total in {args.output}: {existing_count(args.output):,}",
        file=sys.stderr,
    )


def main():
    args = parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
