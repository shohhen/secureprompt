/**
 * Role-based capability checks for the dashboard UI.
 *
 * Mirrors `UserRole::can_write` / `can_read_all_audit` in the Rust
 * backend (see secureprompt-api/src/http/middleware/jwt_auth.rs). Source
 * of truth is the backend — these helpers exist only to keep mutating
 * controls (add buttons, edit forms) from rendering for users who would
 * just hit a 403 on submit.
 */
import type { AppRole } from "@/types/next-auth";

const WRITE_ROLES: AppRole[] = ["owner", "admin"];
const ALL_AUDIT_ROLES: AppRole[] = ["owner", "admin", "developer"];

/** True for roles allowed to create/edit/delete shared workspace
 *  resources: API keys, providers, policy rules, secure_mode, budgets,
 *  members. */
export function canWrite(role: AppRole | null | undefined): boolean {
  return !!role && WRITE_ROLES.includes(role);
}

/** True for roles allowed to view *all* audit rows (vs. only their own).
 *  Employee/Viewer must self-filter. */
export function canReadAllAudit(role: AppRole | null | undefined): boolean {
  return !!role && ALL_AUDIT_ROLES.includes(role);
}
