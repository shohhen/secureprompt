-- 006 (WS2-3): mark request_events rows that were answered with the
-- deterministic Rust detection floor alone.
--
-- The ML sidecar owns most free-text detection. When it produces no coverage
-- for a request — unconfigured, disabled, circuit breaker OPEN, or every
-- chunk call failing — a workspace whose `sidecar_unavailable` policy is
-- `degrade_with_alert` still gets an answer, but only whatever the
-- deterministic Rust recognisers (PINFL, STIR, MFO, passport, Uzcard, Humo,
-- cards, emails, addresses) caught. Those requests are not equivalent to
-- normally-served ones and an auditor needs to be able to select exactly
-- them after an incident rather than intersecting sidecar uptime with
-- request timestamps.
--
-- Bool with DEFAULT false so every historical row reads as "not degraded",
-- which is the correct interpretation: before WS2-3 the gateway had no
-- concept of coverage loss. NOTE to migration authors: the worker splits this
-- file on raw semicolons after stripping line comments, so do not put a bare
-- ; inside a parenthetical comment.

ALTER TABLE request_events
    ADD COLUMN IF NOT EXISTS floor_only Bool DEFAULT false;
