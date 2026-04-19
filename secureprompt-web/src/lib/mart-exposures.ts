/**
 * Phase 5 / Plan 05-03 — MART_EXPOSURES registry.
 *
 * Each dashboard page that reads from a dbt mart must declare which marts it
 * uses here. The CI gate `scripts/ci/check-mart-exposures.mjs` reads each
 * page's `MART_EXPOSURES` constant and verifies every mart name appears in
 * `secureprompt-analytics/models/marts/exposures.yml`.
 *
 * Rule: if you add a new mart to a page, also add an exposure in exposures.yml.
 */

/** All valid mart table names (must match dbt model names). */
export type MartName =
  | "mart_usage_daily"
  | "mart_cost_by_model"
  | "mart_policy_violations"
  | "mart_latency_pctiles";

/**
 * Centralised registry used by unit tests and the CI gate.
 * Each entry pairs the page route with the marts it reads.
 */
export const MART_EXPOSURES_REGISTRY: Record<string, MartName[]> = {
  usage: ["mart_usage_daily"],
  cost: ["mart_cost_by_model"],
  policy: ["mart_policy_violations"],
  latency: ["mart_latency_pctiles"],
};
