import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "@formatjs/icu-messageformat-parser";

/**
 * Every shipped message must PARSE as ICU.
 *
 * The gap this closes: `i18n-key-parity` proves a key exists in every locale,
 * and the hardcoded-string guard proves a string is not inlined in a component.
 * Neither reads the VALUE. So a message could be present, translated, and
 * unrenderable — which is what shipped:
 *
 *   "Forwarded upstream — PII replaced with {'{{'}Class_N{'}}'} placeholders."
 *
 * That is JSX brace-escaping. ICU reads `{'{{'}` as an argument named `'{{'`,
 * rejects it, and next-intl renders the literal key plus `(INVALID_MESSAGE)` in
 * the UI — on the audit page, in front of whoever is reviewing a request.
 *
 * In ICU a single-quoted run is literal text and needs no surrounding braces:
 * `'{{'Class_N'}}'`.
 */

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MESSAGES_DIR = path.resolve(HERE, "../../src/i18n/messages");

function flatten(value: unknown, prefix = ""): Array<[string, string]> {
  if (typeof value === "string") return [[prefix, value]];
  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).flatMap(([k, v]) =>
      flatten(v, prefix ? `${prefix}.${k}` : k),
    );
  }
  return [];
}

const locales = fs
  .readdirSync(MESSAGES_DIR)
  .filter((f) => f.endsWith(".json"))
  .map((f) => f.replace(/\.json$/, ""));

describe("i18n guard: every message parses as ICU", () => {
  it("finds the locale files at all", () => {
    // Positive control: an empty locale list would make every test below pass
    // vacuously.
    expect(locales.length).toBeGreaterThanOrEqual(2);
  });

  it.each(locales)("%s", (locale) => {
    const raw = JSON.parse(
      fs.readFileSync(path.join(MESSAGES_DIR, `${locale}.json`), "utf8"),
    ) as unknown;
    const entries = flatten(raw);
    expect(entries.length).toBeGreaterThan(50);

    const broken: string[] = [];
    for (const [key, message] of entries) {
      try {
        parse(message);
      } catch (e) {
        broken.push(`${key}\n    ${message}\n    ${(e as Error).message}`);
      }
    }
    expect(broken, `unparseable ICU messages in ${locale}:\n  ${broken.join("\n  ")}`).toEqual(
      [],
    );
  });

  it("MUST DIFFER — the JSX brace form this shipped with is genuinely rejected", () => {
    // Without this the suite above could be passing because `parse` accepts
    // everything. It does not: this is the exact string that reached the audit
    // page as "(INVALID_MESSAGE)".
    expect(() => parse("PII replaced with {'{{'}Class_N{'}}'} placeholders.")).toThrow();
    // ...and the ICU form it was corrected to is accepted.
    expect(() => parse("PII replaced with '{{'Class_N'}}' placeholders.")).not.toThrow();
  });
});
