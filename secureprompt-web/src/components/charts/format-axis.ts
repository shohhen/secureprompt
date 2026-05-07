/**
 * Shared axis-tick formatters for the analytics charts.
 *
 * The API serves dates as UTC `YYYY-MM-DD` strings (mart-grain) and hourly
 * timestamps as ISO-Z strings. Recharts otherwise renders the raw string,
 * which is both ugly (`2026-04-30`) and easy to mistake for a build hash
 * at small font sizes. Centralizing the formatters keeps every chart in
 * sync with the API's UTC contract.
 */

const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

/** `2026-04-30` → `Apr 30`. Falls through unchanged on unrecognized input. */
export function formatDayTick(v: unknown): string {
  if (typeof v !== "string") return String(v ?? "");
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(v);
  if (!m) return v;
  const month = MONTHS[Number(m[2]) - 1] ?? "";
  return `${month} ${Number(m[3])}`;
}

/** `2026-04-30T13:00:00Z` → `Apr 30 13:00`. */
export function formatHourTick(v: unknown): string {
  if (typeof v !== "string") return String(v ?? "");
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return v;
  const month = MONTHS[d.getUTCMonth()];
  const day = d.getUTCDate();
  const hh = String(d.getUTCHours()).padStart(2, "0");
  return `${month} ${day} ${hh}:00`;
}
