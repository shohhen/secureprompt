/**
 * WS6-4 — generate `openapi.json` from `openapi.yaml`.
 *
 * Two files described the API and they had drifted: `POST /v1/auth/register`
 * existed in the JSON and not in the YAML (measured on `main` @ `fb5e1df`).
 * That is not a cosmetic split — the two files have different readers:
 *
 *   * the YAML is what `openapi-typescript` generates the dashboard's client
 *     from (`pnpm --filter secureprompt-web codegen`);
 *   * the JSON is what the gateway itself serves, `include_str!`d into
 *     `secureprompt-api/src/http/mod.rs::openapi_json` and read by
 *     `tests/openapi_router_contract.rs`.
 *
 * So a drift meant the served document and the generated client described
 * different APIs. The YAML is now the only authored file and the JSON is
 * generated from it; `openapi_router_contract::the_served_json_and_the_
 * authored_yaml_describe_the_same_paths` fails if anyone edits the JSON by
 * hand.
 *
 * Deterministic by construction: js-yaml preserves document order into the
 * JS object, and `JSON.stringify(_, null, 2)` preserves insertion order, so
 * the same YAML always produces byte-identical JSON. That is what lets the
 * CI job assert `git diff --exit-code` on the result.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { load } from "js-yaml";

const here = dirname(fileURLToPath(import.meta.url));
const specDir = resolve(here, "../../secureprompt-schemas/openapi/v1");
const yamlPath = resolve(specDir, "openapi.yaml");
const jsonPath = resolve(specDir, "openapi.json");

const doc = load(readFileSync(yamlPath, "utf8"));

// Assert the premise before writing. `load` returns `undefined` for an empty
// file and a bare string for a malformed one; either would silently produce a
// JSON document the gateway would then serve as its API description.
if (!doc || typeof doc !== "object" || !doc.paths) {
  throw new Error(`${yamlPath} did not parse into an OpenAPI document`);
}
const pathCount = Object.keys(doc.paths).length;
if (pathCount < 30) {
  throw new Error(
    `${yamlPath} yielded only ${pathCount} paths — refusing to overwrite ` +
      `openapi.json with what is almost certainly a truncated parse`,
  );
}

writeFileSync(jsonPath, `${JSON.stringify(doc, null, 2)}\n`, "utf8");
process.stdout.write(
  `openapi.json regenerated from openapi.yaml (${pathCount} paths)\n`,
);
