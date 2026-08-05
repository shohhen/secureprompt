/**
 * WS6-3 — locale set for the console.
 *
 * Why four locales and not three
 * ------------------------------
 * Uzbek is written in two scripts and the product cannot paper over that.
 * `uz-Latn` and `uz-Cyrl` are separate BCP-47 locales here, not one `uz`,
 * because:
 *
 *   1. The detection engine already treats ru / uz-latn / uz-cyrl as three
 *      distinct populations, and the WS5 leakboard reports them independently.
 *      A single `uz` in the console would make the UI the only place in the
 *      product where the two scripts are conflated, and it could not be mapped
 *      onto the engine's language routing without inventing a mapping.
 *   2. There is no lossless runtime transliteration for UI copy. The oʻ/gʻ
 *      apostrophe conventions, loanwords and proper nouns all need a human
 *      decision, so "one catalogue plus a transliterator" would ship wrong
 *      copy rather than untranslated copy — the worse failure.
 *   3. Uzbekistan's Latin transition is still incomplete in practice, so the
 *      banks this is sold to run both scripts side by side. Splitting later
 *      would mean re-keying every message and migrating every stored user
 *      preference; splitting now costs one extra JSON file.
 *
 * `en` stays as the source locale that translators work from.
 */
export const LOCALES = ["en", "ru", "uz-Latn", "uz-Cyrl"] as const;

export type Locale = (typeof LOCALES)[number];

/** The locale copy is authored in; every other catalogue is keyed against it. */
export const SOURCE_LOCALE: Locale = "en";

/**
 * What an operator gets with no stored preference and no usable
 * `Accept-Language`. Russian, not English: the console is sold to banks and
 * regulated enterprises in Uzbekistan whose operators read Russian, and
 * WS6-3 is "Russian first". An `en-*` browser still gets English through
 * `negotiateLocale` below.
 */
export const DEFAULT_LOCALE: Locale = "ru";

/** Cookie holding the operator's explicit choice. Read in `request.ts`. */
export const LOCALE_COOKIE = "sp_locale";

/** One year; the choice is a durable preference, not a session detail. */
export const LOCALE_COOKIE_MAX_AGE = 60 * 60 * 24 * 365;

/** Endonyms — a locale switcher that lists locales in English is useless. */
export const LOCALE_LABELS: Record<Locale, string> = {
  en: "English",
  ru: "Русский",
  "uz-Latn": "Oʻzbekcha",
  "uz-Cyrl": "Ўзбекча",
};

export function isLocale(value: unknown): value is Locale {
  return typeof value === "string" && (LOCALES as readonly string[]).includes(value);
}

/**
 * Parse an `Accept-Language` header into tags ordered by descending q-value.
 * Malformed entries are dropped rather than throwing — this runs on every
 * request and a bad header must not 500 the console.
 */
function acceptLanguageTags(header: string): string[] {
  return header
    .split(",")
    .map((part) => {
      const [tag, ...params] = part.trim().split(";");
      const q = params
        .map((p) => p.trim())
        .find((p) => p.startsWith("q="))
        ?.slice(2);
      const quality = q === undefined ? 1 : Number.parseFloat(q);
      return { tag: tag.trim(), quality: Number.isFinite(quality) ? quality : 0 };
    })
    .filter((entry) => entry.tag.length > 0 && entry.quality > 0)
    .sort((a, b) => b.quality - a.quality)
    .map((entry) => entry.tag);
}

/**
 * Map one `Accept-Language` tag onto a supported locale.
 *
 * The Uzbek cases are the interesting ones: a bare `uz` carries no script, and
 * Uzbekistan's official script is Latin, so `uz` resolves to `uz-Latn`. A tag
 * that names Cyrillic explicitly (`uz-Cyrl`, `uz-Cyrl-UZ`) resolves to
 * `uz-Cyrl`.
 */
function matchTag(tag: string): Locale | null {
  const lower = tag.toLowerCase();
  for (const locale of LOCALES) {
    if (locale.toLowerCase() === lower) return locale;
  }
  if (lower === "uz" || lower.startsWith("uz-latn") || lower === "uz-uz") return "uz-Latn";
  if (lower.startsWith("uz-cyrl")) return "uz-Cyrl";
  const base = lower.split("-")[0];
  for (const locale of LOCALES) {
    if (locale.toLowerCase().split("-")[0] === base) return locale;
  }
  return null;
}

/**
 * Resolve the active locale: an explicit stored choice wins over the browser,
 * and the browser wins over the default.
 */
export function negotiateLocale(
  cookieValue: string | undefined | null,
  acceptLanguage: string | undefined | null,
): Locale {
  if (isLocale(cookieValue)) return cookieValue;
  if (acceptLanguage) {
    for (const tag of acceptLanguageTags(acceptLanguage)) {
      const match = matchTag(tag);
      if (match) return match;
    }
  }
  return DEFAULT_LOCALE;
}

/**
 * Value for `<html lang>`. BCP-47 script subtags are legal there, so the
 * locale identifier is used verbatim; screen readers and `:lang()` selectors
 * both accept `uz-Latn` / `uz-Cyrl`.
 */
export function htmlLang(locale: Locale): string {
  return locale;
}
