// Client helpers for the dashboard file-scan page.
//
// These call the ML sidecar's ASYNC endpoints through the same-origin proxy
// (/api/proxy/ml/...). The sync endpoints (/v1/scan-file, /v1/secure-file) hold
// one HTTP connection open for the whole per-segment NER pass, which on large
// docs runs for minutes and blows the Next.js proxy's undici headersTimeout
// (300s) -> UND_ERR_HEADERS_TIMEOUT -> 502 at the browser. The async flow
// returns 202 immediately and we poll a cheap status endpoint, so no single
// request is held open long enough to time out at any layer (undici, GCLB,
// Cloudflare).

const ML = "/api/proxy/ml/v1";

// Client-side ceiling on how long we keep polling a single job. Generous: a
// large multi-page document can take several minutes of CPU-bound inference.
const DEFAULT_MAX_WAIT_MS = 20 * 60 * 1000;
const DEFAULT_POLL_INTERVAL_MS = 1500;

export interface ScanEntity {
  text: string;
  label: string;
  score: number;
}

export interface ScanResult {
  pii_found: boolean;
  secrets_found: boolean;
  injection_detected: boolean;
  entities: ScanEntity[];
  redacted_text: string | null;
  token_map?: Record<string, string>;
}

export interface SecuredFile {
  blob: Blob;
  contentDisposition: string | null;
  summaryHeader: string | null;
}

export interface PollOptions {
  pollIntervalMs?: number;
  maxWaitMs?: number;
  signal?: AbortSignal;
}

/** An error carrying a user-facing message and, when known, the HTTP status. */
export class FileScanError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = "FileScanError";
    this.status = status;
  }
}

function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError());
    const t = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        reject(abortError());
      },
      { once: true },
    );
  });
}

function abortError(): FileScanError {
  return new FileScanError("Cancelled.");
}

/** Map a non-OK submit response to a friendly, action-specific message. */
function submitError(status: number, kind: "scan" | "secure"): FileScanError {
  if (status === 413) return new FileScanError("File too large (max 15 MB).", status);
  if (status === 415)
    return new FileScanError("Unsupported file type for securing.", status);
  if (status === 429)
    return new FileScanError(
      kind === "scan"
        ? "Too many scans in progress — try again in a moment."
        : "Too many secure jobs in progress — try again in a moment.",
      status,
    );
  if (status === 503)
    return new FileScanError("Model still loading — try again in a moment.", status);
  if (status === 401)
    return new FileScanError("Session expired — reload the page.", status);
  return new FileScanError(
    `${kind === "scan" ? "Scan" : "Securing"} failed (HTTP ${status}).`,
    status,
  );
}

/** Map a background-task error string to a friendly message. */
function taskError(kind: "scan" | "secure", detail?: string | null): FileScanError {
  if (detail && /unsupported file type/i.test(detail))
    return new FileScanError("Unsupported file type for securing.");
  return new FileScanError(
    kind === "scan"
      ? "Scan failed while processing the document."
      : "Securing failed while processing the document.",
  );
}

async function submit(path: string, file: File | Blob, signal?: AbortSignal): Promise<string> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(path, { method: "POST", body: form, signal });
  if (!res.ok) {
    throw submitError(res.status, path.includes("secure-file") ? "secure" : "scan");
  }
  const { task_id } = (await res.json()) as { task_id: string };
  return task_id;
}

interface TaskStatus {
  status: "running" | "done" | "error";
  result?: ScanResult | null;
  error?: string | null;
}

/**
 * Poll a task-status endpoint until it reports done/error or we exceed
 * maxWaitMs. Returns the terminal status body on "done"; throws on "error",
 * timeout, or an unexpected HTTP status from the status endpoint.
 */
async function pollUntilDone(
  statusUrl: string,
  kind: "scan" | "secure",
  opts: PollOptions,
): Promise<TaskStatus> {
  const interval = opts.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const maxWait = opts.maxWaitMs ?? DEFAULT_MAX_WAIT_MS;
  const started = Date.now();

  for (;;) {
    const res = await fetch(statusUrl, { signal: opts.signal });
    if (!res.ok) {
      if (res.status === 404)
        throw new FileScanError("The job expired — please try again.", 404);
      if (res.status === 401)
        throw new FileScanError("Session expired — reload the page.", 401);
      throw new FileScanError(
        `${kind === "scan" ? "Scan" : "Securing"} failed (HTTP ${res.status}).`,
        res.status,
      );
    }
    const body = (await res.json()) as TaskStatus;
    if (body.status === "done") return body;
    if (body.status === "error") throw taskError(kind, body.error);
    if (Date.now() - started >= maxWait) {
      throw new FileScanError(
        `${kind === "scan" ? "Scan" : "Securing"} timed out — the document may be very large.`,
      );
    }
    await delay(interval, opts.signal);
  }
}

/** Scan a file for PII/secrets/injection via the async ML endpoint. */
export async function scanFile(file: File | Blob, opts: PollOptions = {}): Promise<ScanResult> {
  const taskId = await submit(`${ML}/scan-file/async`, file, opts.signal);
  const terminal = await pollUntilDone(`${ML}/scan-file/tasks/${taskId}`, "scan", opts);
  if (!terminal.result) {
    throw new FileScanError("Scan finished but returned no result.");
  }
  return terminal.result;
}

/** Redact a file in place and return the secured blob via the async ML flow. */
export async function secureFile(
  file: File | Blob,
  opts: PollOptions = {},
): Promise<SecuredFile> {
  const taskId = await submit(`${ML}/secure-file/async`, file, opts.signal);
  await pollUntilDone(`${ML}/secure-file/tasks/${taskId}`, "secure", opts);

  const res = await fetch(`${ML}/secure-file/tasks/${taskId}/download`, {
    signal: opts.signal,
  });
  if (!res.ok) throw submitError(res.status, "secure");
  return {
    blob: await res.blob(),
    contentDisposition: res.headers.get("Content-Disposition"),
    summaryHeader: res.headers.get("X-Secure-Summary"),
  };
}
