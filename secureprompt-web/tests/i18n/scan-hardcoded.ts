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
/** `{cond ? "Sign in" : "Signing in…"}` — a literal rendered as a JSX child. */
export const RULE_JSX_EXPR = "jsx-expression-literal";
/** `new FileScanError("Model still loading — try again in a moment.")`. */
export const RULE_ERROR_PROSE = "error-prose";
/** `z.string().min(1, "Name is required")` — rendered by <FormMessage>. */
export const RULE_VALIDATION = "validation-prose";
/** `window.confirm("Revoke key…? This cannot be undone.")` — destructive copy. */
export const RULE_DIALOG = "browser-dialog-prose";

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

/**
 * Schema validators whose message argument is rendered to the user verbatim by
 * <FormMessage>. A message that is a catalogue key rather than English prose
 * passes, because keys are single tokens and the prose rule needs a phrase.
 */
const VALIDATION_METHODS = new Set([
  "min",
  "max",
  "email",
  "url",
  "uuid",
  "regex",
  "refine",
  "length",
  "nonempty",
  "int",
  "positive",
  "startsWith",
  "endsWith",
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

/**
 * Browser dialogs. Destructive-action confirmations live here and are read at
 * the exact moment a mistake becomes irreversible, so they must be translated.
 */
const DIALOG_FNS = new Set(["confirm", "alert", "prompt"]);

const HAS_LETTER = /\p{L}/u;
/** Two or more whitespace-separated words, each carrying a letter. */
const LOOKS_LIKE_PROSE = /\p{L}[\p{L}'’]*\s+\p{L}/u;
/**
 * Shape of a literal a user could plausibly read: a phrase, or a word that
 * starts capitalised. Deliberately excludes lowercase single tokens, which is
 * what config values look like (`"outline"`, `"yyyy-MM-dd"`, `"numeric"`).
 */
const LOOKS_USER_FACING = /^\p{Lu}|\p{L}\s+\p{L}|…$/u;

/** Recursively list source files under a root, ignoring nothing. */
function walkSource(absRoot: string, out: string[] = []): string[] {
  if (!fs.existsSync(absRoot)) return out;
  for (const entry of fs.readdirSync(absRoot, { withFileTypes: true })) {
    const abs = path.join(absRoot, entry.name);
    if (entry.isDirectory()) walkSource(abs, out);
    else if (entry.isFile() && (abs.endsWith(".tsx") || abs.endsWith(".ts"))) out.push(abs);
  }
  return out;
}

/**
 * Every `.ts`/`.tsx` under the scanned roots, sorted for stable output.
 *
 * `.ts` is included because the file-scan failure copy lives in
 * `file-scan-api.ts`, not in a component — a scanner that only reads `.tsx`
 * cannot see it, which is precisely the invisible failure this guards against.
 */
export function scannedFiles(): string[] {
  const files: string[] = [];
  for (const root of SCANNED_ROOTS) walkSource(path.join(WEB_ROOT, root), files);
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
  // `aria-label={`${label} token usage`}` — the interpolations are data, but
  // the fixed parts are copy, so join them and judge that.
  if (ts.isTemplateExpression(init)) {
    return [init.head.text, ...init.templateSpans.map((s) => s.literal.text)].join(" ");
  }
  return null;
}

/**
 * True when `node` is rendered as a JSX child rather than sitting in an
 * attribute — i.e. a user reads it. Walks up to the nearest JsxExpression and
 * checks that the expression is a child position.
 */
function insideJsxChildExpression(node: ts.Node): boolean {
  for (let cur = node.parent; cur; cur = cur.parent) {
    if (ts.isJsxAttribute(cur)) return false;
    if (ts.isJsxExpression(cur)) {
      const owner = cur.parent;
      return (
        !!owner &&
        (ts.isJsxElement(owner) || ts.isJsxFragment(owner) || ts.isJsxSelfClosingElement(owner))
      );
    }
    if (ts.isJsxElement(cur) || ts.isJsxFragment(cur)) return false;
  }
  return false;
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

    if (
      (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) &&
      HAS_LETTER.test(node.text) &&
      LOOKS_USER_FACING.test(node.text) &&
      insideJsxChildExpression(node)
    ) {
      record(node, RULE_JSX_EXPR, node.text);
    }

    // `new SomeError("prose")` — user-facing failure copy that never reaches a
    // component, so no JSX rule would ever see it.
    if (ts.isNewExpression(node) && /Error$/.test(node.expression.getText(sf))) {
      const value = literalOf(node.arguments?.[0]);
      if (value !== null && LOOKS_LIKE_PROSE.test(value)) {
        record(node, RULE_ERROR_PROSE, `new ${node.expression.getText(sf)}("${value}")`);
      }
    }

    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
      const fn = node.expression.text;
      if (DIALOG_FNS.has(fn)) {
        const value = literalOf(node.arguments[0]);
        if (value !== null && LOOKS_LIKE_PROSE.test(value)) {
          record(node, RULE_DIALOG, `${fn}("${value}")`);
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

      if (DIALOG_FNS.has(method) && obj === "window") {
        const value = literalOf(node.arguments[0]);
        if (value !== null && LOOKS_LIKE_PROSE.test(value)) {
          record(node, RULE_DIALOG, `window.${method}("${value}")`);
        }
      }

      if (VALIDATION_METHODS.has(method)) {
        for (const arg of node.arguments) {
          const value = literalOf(arg);
          if (value !== null && LOOKS_LIKE_PROSE.test(value)) {
            record(node, RULE_VALIDATION, `.${method}(…, "${value}")`);
          }
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

// ── Message-key usage ────────────────────────────────────────────────────────

export interface KeyUse {
  file: string;
  line: number;
  /** Fully-qualified key path, e.g. "secureMode.masterTitle". */
  key: string;
}

/**
 * Every `t("…")` call in the console, resolved to a full key path.
 *
 * Resolution is per file: a `const x = useTranslations("ns")` (or the awaited
 * `getTranslations("ns")`) binds `x` to `ns`, and any later `x("k")` becomes
 * `ns.k`. A translator created with no namespace binds to the root, so its
 * argument is already a full path.
 *
 * Template-literal arguments (`t(\`level_${opt}\`)`) are deliberately skipped:
 * they cannot be resolved statically, and guessing would put keys nobody uses
 * into the parity check.
 */
export function scanKeyUses(relPath: string, source: string): KeyUse[] {
  const sf = ts.createSourceFile(relPath, source, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TSX);
  const uses: KeyUse[] = [];

  const unwrap = (n: ts.Expression): ts.Expression =>
    ts.isAwaitExpression(n) ? unwrap(n.expression) : n;

  const namespaceFromDeclaration = (node: ts.Node): [string, string] | null => {
    if (!ts.isVariableDeclaration(node) || !node.initializer || !ts.isIdentifier(node.name)) {
      return null;
    }
    const init = unwrap(node.initializer);
    if (!ts.isCallExpression(init) || !ts.isIdentifier(init.expression)) return null;
    const fn = init.expression.text;
    if (fn !== "useTranslations" && fn !== "getTranslations") return null;
    const arg = init.arguments[0];
    return [node.name.text, arg && ts.isStringLiteral(arg) ? arg.text : ""];
  };

  const introducesScope = (node: ts.Node): boolean =>
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node);

  /**
   * Scoped on purpose: a file may declare `const t = useTranslations("a")` in
   * one component and `const t = useTranslations("b")` in another, and a flat
   * map would attribute the first component's keys to the second namespace.
   */
  const walk = (node: ts.Node, inherited: Map<string, string>): void => {
    const scope = introducesScope(node) ? new Map(inherited) : inherited;

    // Bind every translator declared directly in this scope before reading
    // any call, so declaration order inside the scope does not matter.
    const bindLocal = (n: ts.Node): void => {
      const found = namespaceFromDeclaration(n);
      if (found) scope.set(found[0], found[1]);
      if (!introducesScope(n)) ts.forEachChild(n, bindLocal);
    };
    if (introducesScope(node) || ts.isSourceFile(node)) {
      ts.forEachChild(node, bindLocal);
    }

    if (ts.isCallExpression(node)) {
      const callee = ts.isPropertyAccessExpression(node.expression)
        ? node.expression.expression // t.rich("k"), t.has("k")
        : node.expression;
      if (ts.isIdentifier(callee) && scope.has(callee.text)) {
        const arg = node.arguments[0];
        if (arg && ts.isStringLiteral(arg)) {
          const ns = scope.get(callee.text)!;
          const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
          uses.push({ file: relPath, line: line + 1, key: ns ? `${ns}.${arg.text}` : arg.text });
        }
      }
    }

    ts.forEachChild(node, (child) => walk(child, scope));
  };

  walk(sf, new Map());
  return uses;
}

/** Every statically-resolvable message key the console asks for. */
export function scanConsoleKeyUses(): KeyUse[] {
  const out: KeyUse[] = [];
  for (const abs of scannedFiles()) {
    const rel = path.relative(WEB_ROOT, abs);
    out.push(...scanKeyUses(rel, fs.readFileSync(abs, "utf8")));
  }
  return out;
}
