/**
 * Narrow, named re-exports from the openapi-typescript codegen output.
 *
 * Callers should always import schema types from here (`@/types/api`), not
 * from `@/types/api.gen`. That lets later plans extend this file with
 * additional re-exports without breaking existing imports.
 *
 * WS6-4 — `BudgetResponse` and `PutBudgetRequest` used to be hand-written
 * INTERFACES in this file, which is the exact failure the codegen exists to
 * prevent: `BudgetResponse` was missing `updated_at`, which the handler has
 * always returned. Everything here is now an alias onto `api.gen.ts`.
 */
import type { components, paths } from "./api.gen";

export type { paths };

export type TokenRequest = components["schemas"]["TokenRequest"];
export type TokenResponse = components["schemas"]["TokenResponse"];
export type RefreshRequest = components["schemas"]["RefreshRequest"];
export type ApiErrorEnvelope = components["schemas"]["ApiError"];

// Analytics mart row types
export type UsageDailyRow = components["schemas"]["UsageDailyRow"];
export type CostByModelRow = components["schemas"]["CostByModelRow"];
export type PolicyViolationsRow = components["schemas"]["PolicyViolationsRow"];
export type LatencyPctilesRow = components["schemas"]["LatencyPctilesRow"];
export type LatencyPctilesHourlyRow =
  components["schemas"]["LatencyPctilesHourlyRow"];
export type LatencyPctilesResponse =
  components["schemas"]["LatencyPctilesResponse"];

// Workspace budgets
export type BudgetBehavior = components["schemas"]["BudgetBehavior"];
export type BudgetResponse = components["schemas"]["BudgetResponse"];
export type PutBudgetRequest = components["schemas"]["PutBudgetRequest"];
