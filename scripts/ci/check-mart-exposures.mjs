#!/usr/bin/env node
// check-mart-exposures.mjs — CI gate: every MART_EXPOSURES constant on a
// dashboard page must be declared in secureprompt-analytics/models/marts/exposures.yml.
//
// Steps:
//   1. Parse exposures.yml → build Set of mart names from `depends_on: - ref('...')`.
//   2. Glob secureprompt-web/src/app/(dashboard)/**/page.tsx.
//   3. Extract MART_EXPOSURES = [...] from each page file.
//   4. Fail (exit 1) if any page references a mart not in the exposures set.

import { readFileSync, readdirSync, statSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..");

// ── 1. Parse exposures.yml ────────────────────────────────────────────────────

const exposuresPath = join(
  repoRoot,
  "secureprompt-analytics",
  "models",
  "marts",
  "exposures.yml"
);

let exposuresText;
try {
  exposuresText = readFileSync(exposuresPath, "utf8");
} catch (e) {
  console.error(`ERROR: Could not read ${exposuresPath}: ${e.message}`);
  process.exit(1);
}

// Extract mart names from `ref('mart_xxx')` lines in the YAML.
const refPattern = /ref\('([^']+)'\)/g;
const declaredMarts = new Set();
let m;
while ((m = refPattern.exec(exposuresText)) !== null) {
  declaredMarts.add(m[1]);
}

if (declaredMarts.size === 0) {
  console.error("ERROR: No mart refs found in exposures.yml — file may be malformed.");
  process.exit(1);
}

console.log(`Declared marts in exposures.yml: ${[...declaredMarts].join(", ")}`);

// ── 2. Glob dashboard pages ───────────────────────────────────────────────────

function findPageFiles(dir) {
  const results = [];
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return results;
  }
  for (const entry of entries) {
    const full = join(dir, entry);
    let stat;
    try {
      stat = statSync(full);
    } catch {
      continue;
    }
    if (stat.isDirectory()) {
      results.push(...findPageFiles(full));
    } else if (entry === "page.tsx") {
      results.push(full);
    }
  }
  return results;
}

// Note: parentheses in "(dashboard)" are valid on the filesystem.
const dashboardDir = join(
  repoRoot,
  "secureprompt-web",
  "src",
  "app",
  "(dashboard)"
);

let pageFiles;
try {
  pageFiles = findPageFiles(dashboardDir);
} catch (e) {
  console.error(`ERROR: Could not glob dashboard pages under ${dashboardDir}: ${e.message}`);
  process.exit(1);
}

if (pageFiles.length === 0) {
  console.warn(`WARNING: No page.tsx files found under ${dashboardDir} — skipping check`);
  process.exit(0);
}

console.log(`Found ${pageFiles.length} dashboard page(s): ${pageFiles.map(f => f.replace(repoRoot + "/", "")).join(", ")}`);

// ── 3. Extract MART_EXPOSURES from each page ──────────────────────────────────

// Matches: export const MART_EXPOSURES = ["mart_foo", "mart_bar"] as const ...
// Handles multi-line arrays via a loose match on the constant block.
const martExposuresPattern =
  /export\s+const\s+MART_EXPOSURES\s*=\s*\[([^\]]*)\]/;

let errors = 0;

for (const pageFile of pageFiles) {
  const content = readFileSync(pageFile, "utf8");
  const match = martExposuresPattern.exec(content);
  if (!match) {
    console.warn(
      `WARNING: ${pageFile.replace(repoRoot + "/", "")} has no MART_EXPOSURES export — skipping`
    );
    continue;
  }

  // Extract quoted mart names from the array literal.
  const arrayContent = match[1];
  const namePattern = /["']([^"']+)["']/g;
  const pageMarts = [];
  let nm;
  while ((nm = namePattern.exec(arrayContent)) !== null) {
    pageMarts.push(nm[1]);
  }

  const shortPath = pageFile.replace(repoRoot + "/", "");
  console.log(`  ${shortPath}: MART_EXPOSURES = [${pageMarts.join(", ")}]`);

  for (const mart of pageMarts) {
    if (!declaredMarts.has(mart)) {
      console.error(
        `ERROR: ${shortPath} references mart "${mart}" which is NOT declared in exposures.yml`
      );
      errors++;
    }
  }
}

if (errors > 0) {
  console.error(`\ncheck-mart-exposures: FAILED — ${errors} undeclared mart reference(s)`);
  process.exit(1);
}

console.log("\ncheck-mart-exposures: OK — all MART_EXPOSURES declared in exposures.yml");
