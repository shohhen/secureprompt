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

/**
 * Codes, not sentences. This module runs outside React, so it cannot resolve a
 * message itself; baking English in here is exactly how failure copy ends up
 * untranslatable. `file-scan-form.tsx` maps the code onto the `fileScan`
 * catalogue at render time.
 */
export type FileScanErrorCode =
  | "cancelled"
  | "fileTooLarge"
  | "unsupportedType"
  | "tooManyScans"
  | "tooManySecures"
  | "modelLoading"
  | "sessionExpired"
  | "jobExpired"
  | "scanFailed"
  | "secureFailed"
  | "scanTimedOut"
  | "secureTimedOut"
  | "noResult";

/** An error carrying a message *key* and, when known, the HTTP status. */
export class FileScanError extends Error {
  code: FileScanErrorCode;
  status?: number;
  constructor(code: FileScanErrorCode, status?: number) {
    super(code);
    this.name = "FileScanError";
    this.code = code;
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
  return new FileScanError("cancelled");
}

/** Map a non-OK submit response to an action-specific message code. */
function submitError(status: number, kind: "scan" | "secure"): FileScanError {
  if (status === 413) return new FileScanError("fileTooLarge", status);
  if (status === 415) return new FileScanError("unsupportedType", status);
  if (status === 429)
    return new FileScanError(kind === "scan" ? "tooManyScans" : "tooManySecures", status);
  if (status === 503) return new FileScanError("modelLoading", status);
  if (status === 401) return new FileScanError("sessionExpired", status);
  return new FileScanError(kind === "scan" ? "scanFailed" : "secureFailed", status);
}

/** Map a background-task error string to a message code. */
function taskError(kind: "scan" | "secure", detail?: string | null): FileScanError {
  // The sidecar's detail string is English and not ours to localise; it is
  // matched, not displayed.
  if (detail && /unsupported file type/i.test(detail))
    return new FileScanError("unsupportedType");
  return new FileScanError(kind === "scan" ? "scanFailed" : "secureFailed");
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
      if (res.status === 404) throw new FileScanError("jobExpired", 404);
      if (res.status === 401) throw new FileScanError("sessionExpired", 401);
      throw new FileScanError(
        kind === "scan" ? "scanFailed" : "secureFailed",
        res.status,
      );
    }
    const body = (await res.json()) as TaskStatus;
    if (body.status === "done") return body;
    if (body.status === "error") throw taskError(kind, body.error);
    if (Date.now() - started >= maxWait) {
      throw new FileScanError(kind === "scan" ? "scanTimedOut" : "secureTimedOut");
    }
    await delay(interval, opts.signal);
  }
}

/** Scan a file for PII/secrets/injection via the async ML endpoint. */
export async function scanFile(file: File | Blob, opts: PollOptions = {}): Promise<ScanResult> {
  const taskId = await submit(`${ML}/scan-file/async`, file, opts.signal);
  const terminal = await pollUntilDone(`${ML}/scan-file/tasks/${taskId}`, "scan", opts);
  if (!terminal.result) {
    throw new FileScanError("noResult");
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
