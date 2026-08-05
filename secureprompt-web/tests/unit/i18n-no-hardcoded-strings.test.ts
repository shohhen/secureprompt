/**
 * WS6-3 — guard: no user-visible string may bypass the translation layer.
 *
 * `scanConsole()` walks `src/app` and `src/components` on disk and parses each
 * `.tsx` with the TypeScript AST, so this test's subject is the console as it
 * actually is right now — a component added in a later commit is scanned
 * without anyone editing this file.
 */
import { describe, expect, it } from "vitest";
import {
  RULE_JSX_TEXT,
  RULE_PROSE,
  RULE_TOAST,
  RULE_VISIBLE_ATTR,
  formatViolations,
  scanConsole,
  scanSource,
  scannedFiles,
} from "../i18n/scan-hardcoded";

describe("i18n guard: hardcoded user-visible strings", () => {
  it("has a non-empty subject (premise: the scanner really sees the console)", () => {
    const files = scannedFiles();
    // If this ever collapses to 0 the guard below passes vacuously.
    expect(files.length).toBeGreaterThan(50);
    expect(files.some((f) => f.endsWith("src/components/layout/sidebar.tsx"))).toBe(true);
  });

  it("positive control: flags a hardcoded string the translation layer never sees", () => {
    const sample = `
      export function Widget() {
        return (
          <div>
            <p>Rotate this key immediately</p>
            <input placeholder="Search requests" />
            <Field label="Local time" />
            <button onClick={() => toast.error("Could not revoke the session")}>x</button>
          </div>
        );
      }
    `;
    const rules = scanSource("synthetic.tsx", sample).map((v) => v.rule);
    expect(rules).toContain(RULE_JSX_TEXT);
    expect(rules).toContain(RULE_VISIBLE_ATTR);
    expect(rules).toContain(RULE_TOAST);
  });

  it("positive control: flags prose passed to a prop nobody has allow-listed", () => {
    const sample = `
      export function Widget() {
        return <SomeNewCard blurb="Every request is scanned before it leaves" />;
      }
    `;
    const rules = scanSource("synthetic.tsx", sample).map((v) => v.rule);
    expect(rules).toContain(RULE_PROSE);
  });

  it("negative control: does not flag translated calls, tokens, or class names", () => {
    const sample = `
      export function Widget() {
        const t = useTranslations("widget");
        return (
          <div className="flex items-center gap-2 text-sm" variant="outline" href="/usage">
            <p>{t("rotateKey")}</p>
            <input placeholder={t("searchPlaceholder")} />
            <span>{"\\u00b7"}</span>
            <button onClick={() => toast.error(t("revokeFailed"))}>{t("close")}</button>
          </div>
        );
      }
    `;
    expect(scanSource("synthetic.tsx", sample)).toEqual([]);
  });

  it("an i18n-exempt comment with a reason silences a violation, and only that one", () => {
    const exempted = `
      export function Widget() {
        // i18n-exempt: product name, identical in every locale
        return <p>SecurePrompt</p>;
      }
    `;
    expect(scanSource("synthetic.tsx", exempted)).toEqual([]);

    const bareComment = `
      export function Widget() {
        // i18n-exempt
        return <p>SecurePrompt</p>;
      }
    `;
    // A marker without a reason must NOT silence anything.
    expect(scanSource("synthetic.tsx", bareComment)).toHaveLength(1);
  });

  it("the console has no untranslated user-visible strings", () => {
    const violations = scanConsole();
    expect(
      violations,
      `\n${violations.length} user-visible string(s) never reach the translation layer:\n${formatViolations(
        violations,
      )}\n`,
    ).toEqual([]);
  });
});
