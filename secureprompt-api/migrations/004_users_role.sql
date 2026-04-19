-- Phase 5 / Plan 05-01 — User role column for dashboard RBAC (AUTH-07).
--
-- Role model (minimal, per CONTEXT D-09):
--   admin  — full CRUD on keys/providers/policy-rules/budgets; invite users.
--   member — CRUD on policy-rules; read analytics; no key/provider/user ops.
--   viewer — read-only across dashboard views.
--
-- Backfill note (per RESEARCH Open Q3 + VALIDATION): the migration intentionally
-- defaults all existing users to 'viewer'. Operators are responsible for
-- promoting at least one admin per workspace after this migration runs (manual
-- step, documented in the on-prem deploy guide). No auto-admin promotion here.

ALTER TABLE users
    ADD COLUMN role TEXT NOT NULL DEFAULT 'viewer'
    CHECK (role IN ('admin','member','viewer'));
