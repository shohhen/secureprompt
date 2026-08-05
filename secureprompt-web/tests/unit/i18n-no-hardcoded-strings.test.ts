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
  RULE_ERROR_PROSE,
  RULE_JSX_EXPR,
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

  it("positive control: flags a literal rendered from a JSX expression", () => {
    // The shape that slipped past the first version of this guard: the copy is
    // inside a ternary, so it is never a JsxText node.
    const sample = `
      export function Widget() {
        return <Button>{submitting ? "Signing in…" : "Sign in"}</Button>;
      }
    `;
    const found = scanSource("synthetic.tsx", sample);
    expect(found.map((v) => v.rule)).toContain(RULE_JSX_EXPR);
    expect(found.map((v) => v.text).sort()).toEqual(["Sign in", "Signing in…"]);
  });

  it("negative control: a config token in a JSX expression is not copy", () => {
    const sample = `
      export function Widget() {
        return <span>{new Date(v).toLocaleDateString(undefined, { month: "short" })}</span>;
      }
    `;
    expect(scanSource("synthetic.tsx", sample)).toEqual([]);
  });

  it("positive control: flags user-facing prose baked into an Error, in a .ts file", () => {
    // file-scan-api.ts holds failure copy no component ever declares, so a
    // scanner that only reads .tsx cannot see it.
    const sample = `
      export function submitError(status: number) {
        if (status === 503) return new FileScanError("Model still loading — try again in a moment.");
        return new FileScanError(codeFor(status));
      }
    `;
    const found = scanSource("synthetic.ts", sample);
    expect(found.map((v) => v.rule)).toEqual([RULE_ERROR_PROSE]);
    expect(found[0].text).toContain("Model still loading");
  });

  it("scans .ts as well as .tsx", () => {
    const files = scannedFiles();
    expect(files.some((f) => f.endsWith("file-scan/file-scan-api.ts"))).toBe(true);
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
