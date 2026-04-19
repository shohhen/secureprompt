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
