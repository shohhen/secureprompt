/**
 * TDD — dashboard file-scan uses the ML sidecar's ASYNC endpoints
 * (submit -> poll -> [download]) instead of the synchronous ones.
 *
 * The sync endpoints hold one HTTP connection open for the entire (minutes-long,
 * per-segment) NER pass; on large docs that exceeds undici's 300s headersTimeout
 * in the Next.js proxy -> UND_ERR_HEADERS_TIMEOUT -> 502 at the browser.
 * The async flow returns 202 instantly and polls, so no single request is held
 * open long enough to time out at any layer.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
// WS6-3: FileScanError carries a catalogue key rather than an English
// sentence, so these assert the classification directly instead of
// regex-matching wording that now lives in src/i18n/messages/*.json.

import {
  scanFile,
  secureFile,
  FileScanError,
} from "@/app/(dashboard)/file-scan/file-scan-api";

const FAST = { pollIntervalMs: 0 };

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function file(name = "doc.txt"): File {
  return new File(["hello"], name, { type: "text/plain" });
}

describe("scanFile — async submit + poll", () => {
  beforeEach(() => vi.stubGlobal("fetch", vi.fn()));
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("submits to /scan-file/async then polls the tasks endpoint until done", async () => {
    const result = {
      pii_found: true,
      secrets_found: false,
      injection_detected: false,
      entities: [{ text: "Aziz", label: "PERSON", score: 0.9 }],
      redacted_text: "{{Person_1}}",
      file_size_bytes: 5,
      preview_truncated: false,
      token_map: { "{{Person_1}}": "Aziz" },
    };
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonResponse({ task_id: "abc" }, 202))
      .mockResolvedValueOnce(jsonResponse({ status: "running", result: null, error: null }))
      .mockResolvedValueOnce(jsonResponse({ status: "done", result, error: null }));

    const out = await scanFile(file(), FAST);

    expect(out.pii_found).toBe(true);
    expect(out.entities).toHaveLength(1);
    expect(out.redacted_text).toBe("{{Person_1}}");

    const calls = vi.mocked(fetch).mock.calls;
    expect(String(calls[0][0])).toBe("/api/proxy/ml/v1/scan-file/async");
    expect((calls[0][1] as RequestInit).method).toBe("POST");
    expect(String(calls[1][0])).toBe("/api/proxy/ml/v1/scan-file/tasks/abc");
  });

  it("returns the result when the task is already done on the first poll", async () => {
    const result = {
      pii_found: false,
      secrets_found: false,
      injection_detected: false,
      entities: [],
      redacted_text: null,
      file_size_bytes: 5,
      preview_truncated: false,
      token_map: {},
    };
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonResponse({ task_id: "t1" }, 202))
      .mockResolvedValueOnce(jsonResponse({ status: "done", result, error: null }));

    const out = await scanFile(file(), FAST);
    expect(out.pii_found).toBe(false);
  });

  it("throws a size-specific FileScanError on a 413 submit", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      jsonResponse({ detail: "file too large (max 15728640 bytes)" }, 413),
    );
    const err: unknown = await scanFile(file(), FAST).catch((e) => e);
    expect(err).toBeInstanceOf(FileScanError);
    expect((err as FileScanError).status).toBe(413);
    expect((err as FileScanError).code).toBe("fileTooLarge");
  });

  it("maps a 429 submit to a 'too many' message", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      jsonResponse({ detail: "too many concurrent scans" }, 429),
    );
    const err = (await scanFile(file(), FAST).catch((e) => e)) as FileScanError;
    expect(err.status).toBe(429);
    expect(err.code).toBe("tooManyScans");
  });

  it("maps a 503 submit to a 'still loading' message", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse({ detail: "loading" }, 503));
    const err = (await scanFile(file(), FAST).catch((e) => e)) as FileScanError;
    expect(err.status).toBe(503);
    expect(err.code).toBe("modelLoading");
  });

  it("throws when the polled task reports status=error", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonResponse({ task_id: "e1" }, 202))
      .mockResolvedValueOnce(
        jsonResponse({ status: "error", result: null, error: "boom" }),
      );
    const err = (await scanFile(file(), FAST).catch((e) => e)) as FileScanError;
    expect(err).toBeInstanceOf(FileScanError);
    expect(err.code).toBe("scanFailed");
  });

  it("times out (throws) if the task never leaves running before maxWaitMs", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonResponse({ task_id: "slow" }, 202))
      .mockResolvedValue(jsonResponse({ status: "running", result: null, error: null }));
    const err = (await scanFile(file(), { pollIntervalMs: 0, maxWaitMs: 0 }).catch(
      (e) => e,
    )) as FileScanError;
    expect(err).toBeInstanceOf(FileScanError);
    expect(err.code).toBe("scanTimedOut");
  });
});

describe("secureFile — async submit + poll + download", () => {
  beforeEach(() => vi.stubGlobal("fetch", vi.fn()));
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("submits, polls to done, then downloads the blob + headers", async () => {
    const summary = JSON.stringify({
      entities_count: 4,
      types: { PERSON: 1 },
      pages: 0,
      ocr_used: false,
      output_mime: "text/plain",
      output_filename: "doc-secured.txt",
    });
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonResponse({ task_id: "s1" }, 202))
      .mockResolvedValueOnce(jsonResponse({ status: "running", summary: null, error: null }))
      .mockResolvedValueOnce(
        jsonResponse({ status: "done", summary: JSON.parse(summary), error: null }),
      )
      .mockResolvedValueOnce(
        new Response(new Blob(["redacted"]), {
          status: 200,
          headers: {
            "content-type": "text/plain",
            "content-disposition": 'attachment; filename="doc-secured.txt"',
            "x-secure-summary": summary,
          },
        }),
      );

    const out = await secureFile(file(), FAST);

    expect(await out.blob.text()).toBe("redacted");
    expect(out.contentDisposition).toContain("doc-secured.txt");
    expect(out.summaryHeader).toBe(summary);

    const calls = vi.mocked(fetch).mock.calls.map((c) => String(c[0]));
    expect(calls[0]).toBe("/api/proxy/ml/v1/secure-file/async");
    expect(calls[1]).toBe("/api/proxy/ml/v1/secure-file/tasks/s1");
    expect(calls[calls.length - 1]).toBe(
      "/api/proxy/ml/v1/secure-file/tasks/s1/download",
    );
  });

  it("throws a friendly message when securing errors (unsupported type)", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonResponse({ task_id: "u1" }, 202))
      .mockResolvedValueOnce(
        jsonResponse({ status: "error", summary: null, error: "unsupported file type" }),
      );
    const err = (await secureFile(file("x.exe"), FAST).catch((e) => e)) as FileScanError;
    expect(err).toBeInstanceOf(FileScanError);
    expect(err.code).toBe("unsupportedType");
  });
});
