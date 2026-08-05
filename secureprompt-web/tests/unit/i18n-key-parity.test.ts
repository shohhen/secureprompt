/**
 * WS6-3 — key parity between locales, and the no-silent-fallback rule.
 *
 * The locale list is read from `@/i18n/config`, not restated here: adding a
 * fifth locale to the config makes this file demand a message catalogue for it
 * on the next run.  The catalogues themselves are read off disk so the test
 * subject is the shipped JSON, not a copy of it.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createTranslator } from "next-intl";
import { describe, expect, it } from "vitest";
import { DEFAULT_LOCALE, LOCALES, SOURCE_LOCALE, type Locale } from "@/i18n/config";
import { getMessageFallback, onIntlError } from "@/i18n/error-policy";

const WEB_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const MESSAGES_DIR = path.join(WEB_ROOT, "src/i18n/messages");

/**
 * Locales whose catalogue is deliberately incomplete, with the reason and the
 * date the waiver was taken.  WS6-3 ships "Russian first, Uzbek second": the
 * framework carries all four locales, `ru` is complete, and the two Uzbek
 * catalogues are scaffolds pending a native reviewer.  Baselined rather than
 * left red so this gate is meaningful on the day it is added.
 */
const INCOMPLETE_LOCALES: Record<string, { since: string; reason: string }> = {
  "uz-Latn": {
    since: "2026-08-05",
    reason:
      "WS6-3 ships RU complete and UZ scaffolded; uz-Latn copy awaits a native reviewer (WS6-3-FU1).",
  },
  "uz-Cyrl": {
    since: "2026-08-05",
    reason:
      "WS6-3 ships RU complete and UZ scaffolded; uz-Cyrl copy awaits a native reviewer (WS6-3-FU1).",
  },
};

/**
 * Russian strings still carrying a marked TODO.  Security copy is not
 * machine-translated silently: anything unresolved is written as
 * `TODO(ru): <english source>` and counted here.  The ceiling only moves down.
 */
const RU_TODO_CEILING = { max: 0, since: "2026-08-05" };

type Catalogue = Record<string, unknown>;

function readCatalogue(locale: Locale): Catalogue {
  const file = path.join(MESSAGES_DIR, `${locale}.json`);
  return JSON.parse(fs.readFileSync(file, "utf8")) as Catalogue;
}

function flatten(value: unknown, prefix = "", out = new Map<string, string>()): Map<string, string> {
  if (typeof value === "string") {
    out.set(prefix, value);
    return out;
  }
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Catalogue)) {
      flatten(v, prefix ? `${prefix}.${k}` : k, out);
    }
  }
  return out;
}

const todoMarker = (locale: Locale) => new RegExp(`^TODO\\(${locale}\\):\\s*\\S`);

describe("i18n catalogues", () => {
  it("premise: the config declares the locales WS6-3 promised", () => {
    expect(LOCALES).toEqual(["en", "ru", "uz-Latn", "uz-Cyrl"]);
    expect(SOURCE_LOCALE).toBe("en");
    expect(DEFAULT_LOCALE).toBe("ru");
  });

  it("every configured locale has a catalogue on disk", () => {
    for (const locale of LOCALES) {
      const file = path.join(MESSAGES_DIR, `${locale}.json`);
      expect(fs.existsSync(file), `missing catalogue for ${locale}: ${file}`).toBe(true);
    }
  });

  it("premise: the English catalogue is not trivially small", () => {
    // Guards against a parity pass over two nearly-empty files.
    expect(flatten(readCatalogue(SOURCE_LOCALE)).size).toBeGreaterThan(200);
  });

  it("ru has exactly the keys en has — no missing, no orphans", () => {
    const en = [...flatten(readCatalogue("en")).keys()].sort();
    const ru = [...flatten(readCatalogue("ru")).keys()].sort();

    const missing = en.filter((k) => !ru.includes(k));
    const orphan = ru.filter((k) => !en.includes(k));

    expect(missing, `keys in en but not ru:\n  ${missing.join("\n  ")}`).toEqual([]);
    expect(orphan, `keys in ru but not en:\n  ${orphan.join("\n  ")}`).toEqual([]);
  });

  it("no ru value is empty or whitespace", () => {
    const empty = [...flatten(readCatalogue("ru")).entries()]
      .filter(([, v]) => v.trim() === "")
      .map(([k]) => k);
    expect(empty, `empty ru values:\n  ${empty.join("\n  ")}`).toEqual([]);
  });

  it("ru carries no more marked TODOs than the dated ceiling allows", () => {
    const marker = todoMarker("ru");
    const todos = [...flatten(readCatalogue("ru")).entries()]
      .filter(([, v]) => marker.test(v))
      .map(([k, v]) => `${k} => ${v}`);
    expect(
      todos.length,
      `ru TODO ceiling is ${RU_TODO_CEILING.max} (set ${RU_TODO_CEILING.since}); found ${todos.length}:\n  ${todos.join("\n  ")}`,
    ).toBeLessThanOrEqual(RU_TODO_CEILING.max);
  });

  it("scaffolded locales may lag but may never invent keys en does not have", () => {
    const en = new Set(flatten(readCatalogue("en")).keys());
    for (const locale of LOCALES) {
      const orphan = [...flatten(readCatalogue(locale)).keys()].filter((k) => !en.has(k));
      expect(orphan, `keys in ${locale} but not en:\n  ${orphan.join("\n  ")}`).toEqual([]);
      if (!INCOMPLETE_LOCALES[locale]) continue;
      // Waived locales must still be declared incomplete on purpose, with a date.
      expect(INCOMPLETE_LOCALES[locale].since).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(INCOMPLETE_LOCALES[locale].reason.length).toBeGreaterThan(20);
    }
  });

  it("a missing key throws instead of silently falling back", () => {
    const t = createTranslator({
      locale: "ru",
      messages: { nav: { usage: "Использование" } },
      onError: onIntlError,
      getMessageFallback,
    });

    expect(t("nav.usage")).toBe("Использование");
    // Positive control above proves the translator works; this must differ.
    expect(() => t("nav.doesNotExist" as never)).toThrow(/MISSING_MESSAGE/i);
  });
});
