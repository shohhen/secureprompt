/**
 * WS6-3 — the untranslated-string scanner.
 *
 * The failure mode this exists to catch is a *new* user-visible string that
 * never reaches the translation layer.  A test that checks "the strings I
 * remembered to extract" cannot see that string, so this scanner derives its
 * subject from the source of truth at runtime instead of from a list:
 *
 *   - the file set comes from walking `src/app` and `src/components` on disk,
 *     so a component added tomorrow is covered without editing this file;
 *   - the strings come from the TypeScript AST (JSX text nodes, JSX attribute
 *     literals, toast calls), not from a regex over remembered phrases;
 *   - the "is this prose?" rule (RULE_PROSE below) fires on *any* attribute of
 *     *any* element, including props of components that do not exist yet.
 *
 * Escaping the guard is deliberate and local: an `i18n-exempt: <reason>`
 * comment on the offending line or the line above it.  Exemptions therefore
 * live at the call site and a new string is never exempt by default.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const WEB_ROOT = path.resolve(HERE, "../..");

/** Roots walked on disk.  Directories, not files — new files self-enrol. */
export const SCANNED_ROOTS = ["src/app", "src/components"] as const;

export interface Violation {
  /** Path relative to `secureprompt-web/`. */
  file: string;
  line: number;
  /** Which rule fired — see RULE_* constants. */
  rule: string;
  text: string;
}

export const RULE_JSX_TEXT = "jsx-text";
export const RULE_VISIBLE_ATTR = "visible-attr";
export const RULE_PROSE = "prose-attr";
export const RULE_TOAST = "toast-literal";

/**
 * Attribute names that render to the user by definition.  This is the
 * HTML/ARIA vocabulary plus the render-prop names this codebase uses; it is a
 * list of *attribute names*, never of strings.  RULE_PROSE below is the part
 * that generalises to props nobody has written yet.
 */
const USER_VISIBLE_ATTRS = new Set([
  "alt",
  "aria-label",
  "aria-description",
  "aria-placeholder",
  "aria-roledescription",
  "aria-valuetext",
  "placeholder",
  "title",
  "label",
  "emptyMessage",
  "heading",
  "subtitle",
  "caption",
  "legend",
  "summary",
]);

/**
 * Attributes whose values are machine tokens, never prose.  Only consulted by
 * RULE_PROSE; a name here still gets checked by RULE_VISIBLE_ATTR if it is
 * also user-visible (no name is in both sets).
 */
const NEVER_PROSE_ATTRS = new Set([
  "className",
  "class",
  "style",
  "href",
  "src",
  "srcSet",
  "id",
  "key",
  "type",
  "name",
  "role",
  "htmlFor",
  "variant",
  "size",
  "align",
  "side",
  "orientation",
  "dir",
  "viewBox",
  "d",
  "fill",
  "stroke",
  "xmlns",
  "method",
  "action",
  "target",
  "rel",
  "accept",
  "autoComplete",
  "inputMode",
  "pattern",
  "as",
  "position",
  "layout",
  "dataKey",
  "stackId",
  "fillOpacity",
  "strokeDasharray",
  "labelKey",
  "messageKey",
  "locale",
  "value",
  "defaultValue",
]);

const TOAST_METHODS = new Set([
  "success",
  "error",
  "info",
  "warning",
  "loading",
  "message",
  "custom",
]);

const HAS_LETTER = /\p{L}/u;
/** Two or more whitespace-separated words, each carrying a letter. */
const LOOKS_LIKE_PROSE = /\p{L}[\p{L}'’]*\s+\p{L}/u;

/** Recursively list `.tsx` files under a root, ignoring nothing. */
function walkTsx(absRoot: string, out: string[] = []): string[] {
  if (!fs.existsSync(absRoot)) return out;
  for (const entry of fs.readdirSync(absRoot, { withFileTypes: true })) {
    const abs = path.join(absRoot, entry.name);
    if (entry.isDirectory()) walkTsx(abs, out);
    else if (entry.isFile() && abs.endsWith(".tsx")) out.push(abs);
  }
  return out;
}

/** Every `.tsx` under the scanned roots, sorted for stable output. */
export function scannedFiles(): string[] {
  const files: string[] = [];
  for (const root of SCANNED_ROOTS) walkTsx(path.join(WEB_ROOT, root), files);
  return files.sort();
}

function attrName(attr: ts.JsxAttribute): string {
  return attr.name.getText();
}

/** The literal text of an attribute value, or null if it is not a plain literal. */
function literalOf(init: ts.Node | undefined): string | null {
  if (!init) return null;
  if (ts.isStringLiteral(init)) return init.text;
  if (ts.isNoSubstitutionTemplateLiteral(init)) return init.text;
  if (ts.isJsxExpression(init) && init.expression) return literalOf(init.expression);
  return null;
}

function isExempt(lines: string[], lineIndex: number): boolean {
  const marker = /i18n-exempt:\s*\S/;
  if (marker.test(lines[lineIndex] ?? "")) return true;
  if (marker.test(lines[lineIndex - 1] ?? "")) return true;
  return false;
}

/** Scan one file's source text.  Exported so tests can feed it a synthetic file. */
export function scanSource(relPath: string, source: string): Violation[] {
  const sf = ts.createSourceFile(relPath, source, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TSX);
  const lines = source.split("\n");
  const found: Violation[] = [];

  const record = (node: ts.Node, rule: string, text: string) => {
    const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
    if (isExempt(lines, line)) return;
    found.push({ file: relPath, line: line + 1, rule, text: text.trim() });
  };

  const visit = (node: ts.Node): void => {
    if (ts.isJsxText(node)) {
      const text = node.text.trim();
      if (text && HAS_LETTER.test(text)) record(node, RULE_JSX_TEXT, text);
    }

    if (ts.isJsxAttribute(node)) {
      const name = attrName(node);
      const value = literalOf(node.initializer);
      if (value !== null && HAS_LETTER.test(value)) {
        if (USER_VISIBLE_ATTRS.has(name)) {
          record(node, RULE_VISIBLE_ATTR, `${name}="${value}"`);
        } else if (!NEVER_PROSE_ATTRS.has(name) && LOOKS_LIKE_PROSE.test(value)) {
          record(node, RULE_PROSE, `${name}="${value}"`);
        }
      }
    }

    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const obj = node.expression.expression.getText(sf);
      const method = node.expression.name.getText(sf);
      if (obj === "toast" && TOAST_METHODS.has(method)) {
        const value = literalOf(node.arguments[0]);
        if (value !== null && HAS_LETTER.test(value)) {
          record(node, RULE_TOAST, `toast.${method}("${value}")`);
        }
      }
    }

    ts.forEachChild(node, visit);
  };

  visit(sf);
  return found;
}

/** Scan the whole console.  Returns every violation, sorted by file then line. */
export function scanConsole(): Violation[] {
  const out: Violation[] = [];
  for (const abs of scannedFiles()) {
    const rel = path.relative(WEB_ROOT, abs);
    out.push(...scanSource(rel, fs.readFileSync(abs, "utf8")));
  }
  return out;
}

export function formatViolations(violations: Violation[]): string {
  const byFile = new Map<string, Violation[]>();
  for (const v of violations) {
    const list = byFile.get(v.file) ?? [];
    list.push(v);
    byFile.set(v.file, list);
  }
  const chunks: string[] = [];
  for (const [file, list] of [...byFile.entries()].sort()) {
    chunks.push(`  ${file}`);
    for (const v of list) chunks.push(`    :${v.line} [${v.rule}] ${v.text}`);
  }
  return chunks.join("\n");
}
