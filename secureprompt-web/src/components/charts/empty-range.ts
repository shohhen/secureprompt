/**
 * Build a dataset covering every day (or every hour) between `from` and `to`,
 * with each numeric series field set to zero.
 *
 * Used when the API returns no rows — synthesizing a zero-valued series lets
 * the chart render its axes, grid, legend, and date ticks instead of a bare
 * "no data" message.
 *
 * **Why UTC throughout:** The API stores timestamps in UTC and returns
 * `usage_date` as a UTC calendar date. Previously this helper used
 * `parseISO` + `eachDayOfInterval` from `date-fns`, both of which interpret
 * naked `YYYY-MM-DD` strings as **local-time** dates. Around midnight UTC
 * that produced off-by-one labels (or duplicate days) for callers in
 * non-UTC zones. We now construct dates explicitly in UTC and format from
 * UTC components so the synthetic empty range aligns byte-for-byte with
 * what the API would return.
 */

const ISO_DAY = (d: Date): string =>
  `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}-${String(d.getUTCDate()).padStart(2, "0")}`;

const ISO_HOUR = (d: Date): string =>
  `${ISO_DAY(d)}T${String(d.getUTCHours()).padStart(2, "0")}:00:00Z`;

function parseUtcDay(s: string): Date | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  if (!m) return null;
  const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
  return Number.isNaN(d.getTime()) ? null : d;
}

export function emptyDailySeries(
  from: string,
  to: string,
  fields: string[],
): Record<string, string | number>[] {
  const start = parseUtcDay(from);
  const end = parseUtcDay(to);
  if (!start || !end || end < start) return [];

  const out: Record<string, string | number>[] = [];
  for (
    let d = new Date(start.getTime());
    d.getTime() <= end.getTime();
    d.setUTCDate(d.getUTCDate() + 1)
  ) {
    const row: Record<string, string | number> = { date: ISO_DAY(d) };
    for (const f of fields) row[f] = 0;
    out.push(row);
  }
  return out;
}

/**
 * Build a zero-valued series with hourly buckets between `from` 00:00 UTC
 * and `to` 23:00 UTC inclusive. Output `bucket_ts` is an ISO-Z timestamp
 * matching what the API returns when called with `bucket=hour`.
 */
export function emptyHourlySeries(
  from: string,
  to: string,
  fields: string[],
): Record<string, string | number>[] {
  const start = parseUtcDay(from);
  const end = parseUtcDay(to);
  if (!start || !end || end < start) return [];

  // Cap at 31 days so we don't render thousands of empty rows when the
  // user picks a wide range with bucket=hour. The API enforces the same
  // limit; this just keeps the empty-state honest.
  const spanDays = Math.floor((end.getTime() - start.getTime()) / 86_400_000);
  if (spanDays > 31) return [];

  const out: Record<string, string | number>[] = [];
  const cursor = new Date(start.getTime());
  const stop = new Date(end.getTime());
  stop.setUTCHours(23);

  while (cursor.getTime() <= stop.getTime()) {
    const row: Record<string, string | number> = { bucket_ts: ISO_HOUR(cursor) };
    for (const f of fields) row[f] = 0;
    out.push(row);
    cursor.setUTCHours(cursor.getUTCHours() + 1);
  }
  return out;
}
