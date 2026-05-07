-- 011: Self-reported device MAC for the audit log.
--
-- Populated by the Electron desktop wrapper, which reads the local
-- machine's NIC MAC via `os.networkInterfaces()` and injects it as
-- `X-SecurePrompt-Device-MAC` on every outbound HTTP request. Web
-- (browser) sessions don't have access to this — the column stays NULL
-- for them, which the dashboard renders as "—".
--
-- Limitations (documented here so future readers don't mistake this for
-- a security boundary):
--   * Self-reported. A user can spoof or strip the header. Treat it as
--     an audit aid, not authentication.
--   * One MAC per user — last-write-wins. A user with multiple devices
--     will only show the most-recently-registered one in audit detail.
--     Per-session MAC tracking would need a separate table; out of scope
--     for this iteration.
--   * Updates on every authenticated /v1/me/profile call, so the value
--     refreshes whenever the user opens the dashboard from a new device.

ALTER TABLE users ADD COLUMN IF NOT EXISTS device_mac TEXT;
