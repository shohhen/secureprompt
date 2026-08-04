#!/usr/bin/env python3
"""WS1-7 Task 27 R1 — count what the credential-header anchor accepts and rejects.

Task 27's residuals were parked because "every round added a heuristic to a
substring gate and each heuristic traded one direction for the other. These
need frequency evidence from `data/realdoc_raw/`, not a sixth guess."

`data/realdoc_raw/` answers that question with n = 0: the Uzbek/Russian
document corpus contains no HTTP headers at all, so it cannot decide a
credential-header gate in either direction. That is a real result and it is
reported as one. This tool therefore also measures a SECOND, explicitly
labelled population — developer text, which is where `Authorization:` actually
occurs and which is what a developer pastes into an LLM gateway.

Mirrors `secureprompt-api/src/detection/registry.rs`:
`is_non_fold_connector`, `strip_credential_header_connectors`,
`CREDENTIAL_HEADER_SUFFIXES`, `SHELL_HEADER_FLAGS` and
`preceded_by_auth_header_label`. Cross-checked against the live Rust detector
by `--verify-with`, which reads a JSONL of `{snippet, redacted}` pairs produced
from `DetectorRegistry::detect` and asserts the mirror agrees on every one.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

NEEDLES = ("Bearer ", "Basic ")
LOOKBACK_BYTES = 48
CONNECTORS = set(" \t\r\"'`*")
SUFFIXES = ("proxy-authorization:", "proxy-authorization=", "authorization:", "authorization=")
SHELL_HEADER_FLAGS = ("-H", "--header", "--header=")
STRUCTURAL_OPENERS = "{[,:"

# The R1 proposal, verbatim from the plan: "prefix must end at a line start, or
# in `{ [ , =`". A line start is read on the RAW window, because that is the
# only place the information survives -- the connector stripper has already
# deleted the indentation by the time the prefix exists.
LINE_START = re.compile(r"(?:^|\n)[ \t]*(?:-[ \t]+)?[\"'`*]*$")


def strip_connectors(window: str) -> str:
    """Mirror of `strip_credential_header_connectors`."""
    cleaned = []
    for i, ch in enumerate(window):
        if ch == "\n":
            after = window[i + 1:]
            if after.startswith(" ") or after.startswith("\t"):
                continue
            cleaned.clear()
            continue
        if ch in CONNECTORS:
            continue
        cleaned.append(ch)
    return "".join(cleaned)


def gate(content: str, needle_start: int):
    """Mirror of `preceded_by_auth_header_label`, plus the R1 proposal.

    Returns `(accepted_today, accepted_under_proposal, prefix, suffix)`.
    """
    data = content.encode("utf-8")
    start = max(0, len(content[:needle_start].encode("utf-8")) - LOOKBACK_BYTES)
    raw = data[start:len(content[:needle_start].encode("utf-8"))].decode("utf-8", "ignore")
    cleaned = strip_connectors(raw)
    for suffix in SUFFIXES:
        if len(cleaned) < len(suffix):
            continue
        split = len(cleaned) - len(suffix)
        if cleaned[split:].lower() != suffix:
            continue
        prefix = cleaned[:split]
        today = (
            prefix == ""
            or prefix.endswith(tuple(STRUCTURAL_OPENERS))
            or any(prefix.endswith(f) for f in SHELL_HEADER_FLAGS)
        )
        # The proposal is ADDITIVE: everything accepted today stays accepted,
        # plus a header name that begins its own line (optionally after a YAML
        # sequence marker), plus `=` as a structural opener.
        name_at = raw.lower().rfind(suffix)
        line_start = name_at >= 0 and bool(LINE_START.search(raw[:name_at]))
        yaml_dash = line_start and bool(re.search(r"(?:^|\n)[ \t]*-[ \t]+[\"'`*]*$", raw[:name_at]))
        equals = prefix.endswith("=")
        proposed = today or line_start or equals
        return today, proposed, prefix, suffix, line_start, yaml_dash, equals
    return None, None, None, None, False, False, False


def occurrences(text: str):
    for needle in NEEDLES:
        at = text.find(needle)
        while at != -1:
            yield needle, at
            at = text.find(needle, at + 1)


def scan_file(path: str):
    try:
        text = open(path, "r", encoding="utf-8").read()
    except (UnicodeDecodeError, OSError):
        return
    for needle, at in occurrences(text):
        today, proposed, prefix, suffix, line_start, yaml_dash, equals = gate(text, at)
        line_no = text.count("\n", 0, at) + 1
        line = text[text.rfind("\n", 0, at) + 1: text.find("\n", at) if text.find("\n", at) != -1 else len(text)]
        yield {
            "path": path, "line": line_no, "needle": needle,
            "labelled": today is not None,
            "accepted_today": today, "accepted_proposed": proposed,
            "prefix": prefix, "suffix": suffix,
            "by_line_start": line_start, "by_yaml_dash": yaml_dash, "by_equals": equals,
            "context": line.strip()[:160],
        }


# `artifacts` holds this tool's own output, which quotes every occurrence it
# found; scanning it would count each occurrence twice and grow without bound.
SKIP_DIRS = {".git", "target", "node_modules", "trivy-reports", ".venv", ".venv-train",
             "sbom", "dist", "build", "__pycache__", ".worktrees", "artifacts"}
TEXT_EXT = {".md", ".yml", ".yaml", ".json", ".sh", ".py", ".ts", ".tsx", ".js",
            ".jsx", ".http", ".toml", ".env", ".txt", ".rs"}


def walk(roots, skip_paths=()):
    skip_paths = {os.path.abspath(p) for p in skip_paths}
    for root in roots:
        if os.path.isfile(root):
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in sorted(filenames):
                full = os.path.join(dirpath, fn)
                if os.path.abspath(full) in skip_paths:
                    continue
                if os.path.splitext(fn)[1] in TEXT_EXT:
                    yield full


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("roots", nargs="+")
    ap.add_argument("--exclude", action="append", default=[],
                    help="file to leave out (fixtures written to make a point are circular)")
    ap.add_argument("--json")
    ap.add_argument("--verify-with", help="JSONL of {snippet,label_only} from the Rust detector")
    args = ap.parse_args(argv)

    if args.verify_with:
        bad = 0
        n = 0
        for line in open(args.verify_with, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            case = json.loads(line)
            n += 1
            at = case["snippet"].find(case.get("needle", "Bearer "))
            today = gate(case["snippet"], at)[0]
            mirror_accepts = bool(today)
            if mirror_accepts != case["rust_accepts"]:
                bad += 1
                print(f"MIRROR DISAGREES: {case['snippet']!r} mirror={mirror_accepts} "
                      f"rust={case['rust_accepts']}")
        print(f"mirror cross-check: {n - bad}/{n} agree with the Rust detector")
        return 1 if bad else 0

    rows = [r for path in walk(args.roots, args.exclude) for r in scan_file(path)]
    labelled = [r for r in rows if r["labelled"]]
    accepted = [r for r in labelled if r["accepted_today"]]
    rejected = [r for r in labelled if not r["accepted_today"]]
    flips = [r for r in rejected if r["accepted_proposed"]]

    print(f"needle occurrences                     : {len(rows)}")
    print(f"  with an Authorization-family label   : {len(labelled)}")
    print(f"    accepted by the anchor today       : {len(accepted)}")
    print(f"    REJECTED today (label-only, leaks) : {len(rejected)}")
    print(f"      newly accepted by the proposal   : {len(flips)}")
    print(f"  no label at all (bare needle, prose) : {len(rows) - len(labelled)}")

    from collections import Counter
    print("\nrejected prefixes, by frequency:")
    for prefix, count in Counter(r["prefix"] for r in rejected).most_common(20):
        print(f"  {count:4d}  {prefix!r}")

    print("\nflips by clause: "
          f"line-start {sum(1 for r in flips if r['by_line_start'])}"
          f" (of which YAML `- ` {sum(1 for r in flips if r['by_yaml_dash'])})"
          f", `=` {sum(1 for r in flips if r['by_equals'] and not r['by_line_start'])}")
    print("\nevery occurrence the proposal would flip:")
    for r in flips:
        print(f"  {r['path']}:{r['line']}  prefix={r['prefix']!r}\n      {r['context']}")

    if args.json:
        # Only the rows a reader can act on: every occurrence the gate
        # REJECTS (each is a value shipping in the clear) and every flip. The
        # 400-odd accepted ones are summarised by their count.
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"rejected_rows": rejected, "flipped_rows": flips, "counts": {
                "needles": len(rows), "labelled": len(labelled),
                "accepted_today": len(accepted), "rejected_today": len(rejected),
                "flipped_by_proposal": len(flips)}}, fh, ensure_ascii=False, indent=2)
        print(f"\nartifact -> {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
