/**
 * Narrow, named re-exports from the openapi-typescript codegen output.
 *
 * Callers should always import schema types from here (`@/types/api`), not
 * from `@/types/api.gen`. That lets Plans 03/04/05 extend this file with
 * additional re-exports without breaking existing imports.
 */
import type { components, paths } from "./api.gen";

export type { paths };

export type TokenRequest = components["schemas"]["TokenRequest"];
export type TokenResponse = components["schemas"]["TokenResponse"];
export type RefreshRequest = components["schemas"]["RefreshRequest"];
export type ApiErrorEnvelope = components["schemas"]["ApiError"];

// Phase 5 / Plan 05-03 — analytics mart row types
export type UsageDailyRow = components["schemas"]["UsageDailyRow"];
export type CostByModelRow = components["schemas"]["CostByModelRow"];
export type PolicyViolationsRow = components["schemas"]["PolicyViolationsRow"];
export type LatencyPctilesRow = components["schemas"]["LatencyPctilesRow"];

// Phase 5 / Plan 05-05 — workspace budget types
export type BudgetBehavior = "block" | "warn" | "flag";

export interface BudgetResponse {
  daily_token_limit: number | null;
  monthly_token_limit: number | null;
  behavior: BudgetBehavior;
  daily_used: number;
  monthly_used: number;
}

export interface PutBudgetRequest {
  daily_token_limit?: number | null;
  monthly_token_limit?: number | null;
  behavior: BudgetBehavior;
}
