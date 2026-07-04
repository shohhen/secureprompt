"use client";

import { useState, useRef } from "react";

interface ScanResult {
  pii_found: boolean;
  secrets_found: boolean;
  injection_detected: boolean;
  entities: Array<{ text: string; label: string; score: number }>;
  redacted_text: string | null;
}

interface SecureSummary {
  entities_count: number;
  types: Record<string, number>;
  pages: number;
  ocr_used: boolean;
  output_filename: string;
}

export function FileScanForm() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [securing, setSecuring] = useState(false);
  const [secured, setSecured] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const busy = scanning || securing;

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    const file = fileRef.current?.files?.[0];
    if (!file) return;

    setScanning(true);
    setError(null);
    setResult(null);
    setSecured(null);

    try {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch("/api/proxy/ml/v1/scan-file", {
        method: "POST",
        body: form,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setResult(await res.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setScanning(false);
    }
  }

  async function handleSecure() {
    const file = fileRef.current?.files?.[0];
    if (!file) {
      setError("Choose a file first.");
      return;
    }

    setSecuring(true);
    setError(null);
    setSecured(null);

    try {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch("/api/proxy/ml/v1/secure-file", {
        method: "POST",
        body: form,
      });
      if (!res.ok) throw new Error(secureErrorMessage(res.status));

      // Stream the redacted file straight to a browser download.
      const blob = await res.blob();
      const filename = filenameFromDisposition(
        res.headers.get("Content-Disposition"),
        defaultSecuredName(file.name),
      );
      triggerDownload(blob, filename);
      setSecured(secureConfirmation(res.headers.get("X-Secure-Summary"), filename));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Securing failed");
    } finally {
      setSecuring(false);
    }
  }

  return (
    <div className="space-y-6">
      <form onSubmit={handleScan} className="rounded-lg border p-6 space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1" htmlFor="file-input">
            Select a file
          </label>
          <input
            id="file-input"
            ref={fileRef}
            type="file"
            accept=".txt,.md,.csv,.pdf,.docx,.doc,.xlsx,.png,.jpg,.jpeg,.gif,.bmp,.tiff"
            className="block w-full text-sm text-muted-foreground file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-medium file:bg-primary file:text-primary-foreground hover:file:bg-primary/90"
          />
          <p className="text-xs text-muted-foreground mt-1">
            Scan reads .txt, .pdf, .docx. Secure &amp; download also supports images and .xlsx (max 15 MB).
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <button
            type="submit"
            disabled={busy}
            className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {scanning ? "Scanning…" : "Scan File"}
          </button>
          <button
            type="button"
            onClick={handleSecure}
            disabled={busy}
            className="rounded-md border border-primary px-4 py-2 text-sm font-medium text-primary hover:bg-primary/10 disabled:opacity-50"
          >
            {securing ? "Securing…" : "Secure & Download"}
          </button>
        </div>
        <p className="text-xs text-muted-foreground">
          Securing redacts PII &amp; secrets in place, covering each value with a
          labelled black box, and returns the file in its original format. The
          redaction is one-way — the original text is removed, not hidden.
        </p>
      </form>

      {error && (
        <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4 text-sm text-destructive">
          {error}
        </div>
      )}

      {secured && (
        <div className="rounded-lg border border-green-600/40 bg-green-600/10 p-4 text-sm text-green-700 dark:text-green-400">
          {secured}
        </div>
      )}

      {result && (
        <div className="rounded-lg border p-6 space-y-4">
          <h2 className="font-semibold">Scan Results</h2>
          <div className="grid grid-cols-3 gap-4">
            <Flag label="PII Found" active={result.pii_found} />
            <Flag label="Secrets Found" active={result.secrets_found} />
            <Flag label="Injection Detected" active={result.injection_detected} />
          </div>
          {result.entities.length > 0 && (
            <div>
              <p className="text-sm font-medium mb-2">
                Detected Entities{" "}
                <span className="text-muted-foreground font-normal">
                  ({result.entities.length} occurrence
                  {result.entities.length === 1 ? "" : "s"})
                </span>
              </p>
              <div className="flex flex-wrap gap-2">
                {dedupeEntities(result.entities).map((e) => (
                  <span
                    key={`${e.label}|${e.text}`}
                    className="rounded-full bg-muted px-3 py-1 text-xs"
                    title={`max score: ${e.score.toFixed(2)}${
                      e.count > 1 ? ` · ${e.count} occurrences` : ""
                    }`}
                  >
                    <span className="font-medium">{e.label}</span>: {e.text}
                    {e.count > 1 && (
                      <span className="ml-1 text-muted-foreground">
                        ×{e.count}
                      </span>
                    )}
                  </span>
                ))}
              </div>
            </div>
          )}
          {result.redacted_text && (
            <div>
              <p className="text-sm font-medium mb-2">Redacted Preview</p>
              <pre className="rounded bg-muted p-3 text-xs whitespace-pre-wrap max-h-48 overflow-auto">
                {result.redacted_text}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function secureErrorMessage(status: number): string {
  if (status === 413) return "File too large (max 15 MB).";
  if (status === 415) return "Unsupported file type for securing.";
  if (status === 503) return "Model still loading — try again in a moment.";
  return `Securing failed (HTTP ${status}).`;
}

function filenameFromDisposition(cd: string | null, fallback: string): string {
  if (!cd) return fallback;
  // RFC 5987 UTF-8 form (non-ASCII names) takes precedence, then the plain form.
  const star = /filename\*=UTF-8''([^;]+)/i.exec(cd);
  if (star) {
    try {
      return decodeURIComponent(star[1].trim());
    } catch {
      return star[1].trim();
    }
  }
  const plain = /filename="?([^";]+)"?/i.exec(cd);
  return plain ? plain[1].trim() : fallback;
}

function defaultSecuredName(name: string): string {
  const dot = name.lastIndexOf(".");
  const stem = dot > 0 ? name.slice(0, dot) : name;
  const ext = dot > 0 ? name.slice(dot) : "";
  return `${stem}-secured${ext}`;
}

function secureConfirmation(summaryHeader: string | null, filename: string): string {
  let detail = "";
  if (summaryHeader) {
    try {
      const s = JSON.parse(summaryHeader) as SecureSummary;
      const n = s.entities_count;
      detail =
        ` — ${n} ${n === 1 ? "entity" : "entities"} redacted` +
        (s.pages ? ` across ${s.pages} page${s.pages === 1 ? "" : "s"}` : "") +
        (s.ocr_used ? " (OCR)" : "");
    } catch {
      /* header malformed — fall back to a plain confirmation */
    }
  }
  return `✓ Secured${detail}. Downloaded ${filename}.`;
}

function triggerDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

type RawEntity = ScanResult["entities"][number];

interface DedupedEntity {
  label: string;
  text: string;
  count: number;
  score: number;
}

function dedupeEntities(entities: RawEntity[]): DedupedEntity[] {
  const byKey = new Map<string, DedupedEntity>();
  for (const e of entities) {
    const key = `${e.label}|${e.text}`;
    const existing = byKey.get(key);
    if (existing) {
      existing.count += 1;
      if (e.score > existing.score) existing.score = e.score;
    } else {
      byKey.set(key, { label: e.label, text: e.text, count: 1, score: e.score });
    }
  }
  return Array.from(byKey.values()).sort((a, b) => {
    if (a.label !== b.label) return a.label.localeCompare(b.label);
    return b.count - a.count;
  });
}

function Flag({ label, active }: { label: string; active: boolean }) {
  return (
    <div className="rounded-md border p-3 text-center">
      <p className="text-xs text-muted-foreground mb-1">{label}</p>
      <span
        className={`text-sm font-semibold ${active ? "text-destructive" : "text-green-600 dark:text-green-400"}`}
      >
        {active ? "Yes" : "No"}
      </span>
    </div>
  );
}
