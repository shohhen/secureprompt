"use client";

import { useState, useRef } from "react";

interface ScanResult {
  pii_found: boolean;
  secrets_found: boolean;
  injection_detected: boolean;
  entities: Array<{ text: string; label: string; score: number }>;
  redacted_text: string | null;
}

export function FileScanForm() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const file = fileRef.current?.files?.[0];
    if (!file) return;

    setLoading(true);
    setError(null);
    setResult(null);

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
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <form onSubmit={handleSubmit} className="rounded-lg border p-6 space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1" htmlFor="file-input">
            Select file to scan
          </label>
          <input
            id="file-input"
            ref={fileRef}
            type="file"
            accept=".txt,.pdf,.docx,.doc"
            className="block w-full text-sm text-muted-foreground file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-medium file:bg-primary file:text-primary-foreground hover:file:bg-primary/90"
          />
          <p className="text-xs text-muted-foreground mt-1">Supported: .txt, .pdf, .docx</p>
        </div>
        <button
          type="submit"
          disabled={loading}
          className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {loading ? "Scanning…" : "Scan File"}
        </button>
      </form>

      {error && (
        <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4 text-sm text-destructive">
          {error}
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
              <p className="text-sm font-medium mb-2">Detected Entities</p>
              <div className="flex flex-wrap gap-2">
                {result.entities.map((e, i) => (
                  <span
                    key={i}
                    className="rounded-full bg-muted px-3 py-1 text-xs"
                    title={`score: ${e.score.toFixed(2)}`}
                  >
                    <span className="font-medium">{e.label}</span>: {e.text}
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
