#!/usr/bin/env node
/**
 * WS6-3 — regenerate the scaffolded catalogues from `en.json`.
 *
 * Adds every key `en` has, seeded with `TODO(<locale>): <english source>` so a
 * translator sees what they are translating and the parity test can count what
 * is outstanding. Values that are already translated are preserved: running
 * this after adding an English string only appends the new keys.
 *
 *   node scripts/i18n-scaffold.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../src/i18n/messages");
const SCAFFOLDED = ["uz-Latn", "uz-Cyrl"];

const read = (locale) => JSON.parse(fs.readFileSync(path.join(DIR, `${locale}.json`), "utf8"));

/** Walk `en`, keeping any existing translation that is not a TODO placeholder. */
function merge(source, existing, locale) {
  if (typeof source === "string") {
    const kept = typeof existing === "string" ? existing : undefined;
    if (kept && !kept.startsWith(`TODO(${locale}):`)) return kept;
    return `TODO(${locale}): ${source}`;
  }
  const out = {};
  for (const [key, value] of Object.entries(source)) {
    out[key] = merge(value, existing?.[key], locale);
  }
  return out;
}

const en = read("en");
for (const locale of SCAFFOLDED) {
  const file = path.join(DIR, `${locale}.json`);
  const existing = fs.existsSync(file) ? read(locale) : {};
  fs.writeFileSync(file, `${JSON.stringify(merge(en, existing, locale), null, 2)}\n`);
  console.log(`wrote ${locale}.json`);
}
