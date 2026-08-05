"use client";

import { useState, useRef } from "react";
import { useTranslations } from "next-intl";
import {
  FileScanError,
  scanFile,
  secureFile,
  type ScanResult,
} from "./file-scan-api";

interface SecureSummary {
  entities_count: number;
  types: Record<string, number>;
  pages: number;
  ocr_used: boolean;
  output_filename: string;
}

export function FileScanForm() {
  const t = useTranslations("fileScan");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [securing, setSecuring] = useState(false);
  const [secured, setSecured] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const busy = scanning || securing;

  /**
   * FileScanError carries a catalogue key; anything else is unexpected and
   * falls back to the action's generic failure copy.
   */
  function messageFor(err: unknown, fallback: "scanFailed" | "secureFailed"): string {
    if (err instanceof FileScanError) {
      return err.status
        ? t(`error.${err.code}`, { status: err.status })
        : t(`error.${err.code}`, { status: "" });
    }
    return t(`error.${fallback}`, { status: "" });
  }

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    const file = fileRef.current?.files?.[0];
    if (!file) return;

    setScanning(true);
    setError(null);
    setResult(null);
    setSecured(null);

    try {
      setResult(await scanFile(file));
    } catch (err) {
      setError(messageFor(err, "scanFailed"));
    } finally {
      setScanning(false);
    }
  }

  async function handleSecure() {
    const file = fileRef.current?.files?.[0];
    if (!file) {
      setError(t("chooseFileFirst"));
      return;
    }

    setSecuring(true);
    setError(null);
    setSecured(null);

    try {
      const { blob, contentDisposition, summaryHeader } = await secureFile(file);
      // Stream the redacted file straight to a browser download.
      const filename = filenameFromDisposition(
        contentDisposition,
        defaultSecuredName(file.name),
      );
      triggerDownload(blob, filename);
      setSecured(secureConfirmation(t, summaryHeader, filename));
    } catch (err) {
      setError(messageFor(err, "secureFailed"));
    } finally {
      setSecuring(false);
    }
  }

  return (
    <div className="space-y-6">
      <form onSubmit={handleScan} className="rounded-lg border p-6 space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1" htmlFor="file-input">
            {t("selectFile")}
          </label>
          <input
            id="file-input"
            ref={fileRef}
            type="file"
            accept=".txt,.md,.csv,.pdf,.docx,.doc,.xlsx,.png,.jpg,.jpeg,.gif,.bmp,.tiff"
            className="block w-full text-sm text-muted-foreground file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-medium file:bg-primary file:text-primary-foreground hover:file:bg-primary/90"
          />
          <p className="text-xs text-muted-foreground mt-1">
            {t("acceptedFormats")}
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <button
            type="submit"
            disabled={busy}
            className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {scanning ? t("scanning") : t("scanFile")}
          </button>
          <button
            type="button"
            onClick={handleSecure}
            disabled={busy}
            className="rounded-md border border-primary px-4 py-2 text-sm font-medium text-primary hover:bg-primary/10 disabled:opacity-50"
          >
            {securing ? t("securing") : t("secureAndDownload")}
          </button>
        </div>
        <p className="text-xs text-muted-foreground">
          {t("secureExplainer")}
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
          <h2 className="font-semibold">{t("resultsTitle")}</h2>
          <div className="grid grid-cols-3 gap-4">
            <Flag label={t("piiFound")} active={result.pii_found} />
            <Flag label={t("secretsFound")} active={result.secrets_found} />
            <Flag label={t("injectionDetected")} active={result.injection_detected} />
          </div>
          {result.entities.length > 0 && (
            <div>
              <p className="text-sm font-medium mb-2">
                {t("detectedEntities")}{" "}
                <span className="text-muted-foreground font-normal">
                  {t("occurrenceCount", { count: result.entities.length })}
                </span>
              </p>
              <div className="flex flex-wrap gap-2">
                {dedupeEntities(result.entities).map((e) => (
                  <span
                    key={`${e.label}|${e.text}`}
                    className="rounded-full bg-muted px-3 py-1 text-xs"
                    title={
                      e.count > 1
                        ? t("entityTitleRepeated", {
                            score: e.score.toFixed(2),
                            count: e.count,
                          })
                        : t("entityTitle", { score: e.score.toFixed(2) })
                    }
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
              <p className="text-sm font-medium mb-2">{t("redactedPreview")}</p>
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

/**
 * Built from ICU messages rather than string concatenation: Russian needs
 * one/few/many for both the entity and page counts, which no amount of
 * `n === 1 ? "" : "s"` can express.
 */
function secureConfirmation(
  t: ReturnType<typeof useTranslations<"fileScan">>,
  summaryHeader: string | null,
  filename: string,
): string {
  if (summaryHeader) {
    try {
      const s = JSON.parse(summaryHeader) as SecureSummary;
      return t("securedWithDetail", {
        filename,
        count: s.entities_count,
        pages: s.pages ?? 0,
        ocr: s.ocr_used ? "yes" : "no",
      });
    } catch {
      /* header malformed — fall back to a plain confirmation */
    }
  }
  return t("secured", { filename });
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

/** `label` arrives already translated from the caller. */
function Flag({ label, active }: { label: string; active: boolean }) {
  const t = useTranslations("common");
  return (
    <div className="rounded-md border p-3 text-center">
      <p className="text-xs text-muted-foreground mb-1">{label}</p>
      <span
        className={`text-sm font-semibold ${active ? "text-destructive" : "text-green-600 dark:text-green-400"}`}
      >
        {active ? t("yes") : t("no")}
      </span>
    </div>
  );
}
