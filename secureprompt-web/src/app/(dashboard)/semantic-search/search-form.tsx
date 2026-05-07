"use client";

import { useState } from "react";
import { useSession } from "next-auth/react";

interface RagMatch {
  rule_id: string;
  score: number;
}

interface RagResult {
  matches: RagMatch[];
  is_match: boolean;
}

export function SearchForm() {
  const { data: session } = useSession();
  const [text, setText] = useState("");
  const [result, setResult] = useState<RagResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!text.trim()) return;
    if (!session?.workspaceId) {
      setError("No active workspace — sign in again.");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch("/api/proxy/ml/v1/rag-check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, workspace_id: session.workspaceId }),
      });
      if (!res.ok) {
        const body = await res.text().catch(() => "");
        throw new Error(body ? `${res.status}: ${body.slice(0, 200)}` : `HTTP ${res.status}`);
      }
      setResult(await res.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Search failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <form onSubmit={handleSubmit} className="rounded-lg border p-6 space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1" htmlFor="prompt-input">
            Prompt text
          </label>
          <textarea
            id="prompt-input"
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={4}
            placeholder="Enter a prompt to check against indexed policy rules…"
            className="w-full rounded-md border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </div>
        <button
          type="submit"
          disabled={loading || !text.trim()}
          className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {loading ? "Searching…" : "Check Prompt"}
        </button>
      </form>

      {error && (
        <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4 text-sm text-destructive">
          {error}
        </div>
      )}

      {result && (
        <div className="rounded-lg border p-6 space-y-4">
          <div className="flex items-center gap-3">
            <h2 className="font-semibold">Results</h2>
            <span
              className={`rounded-full px-3 py-1 text-xs font-medium ${
                result.is_match
                  ? "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400"
                  : "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400"
              }`}
            >
              {result.is_match ? "Policy Match" : "No Match"}
            </span>
          </div>

          {result.matches.length > 0 ? (
            <div className="rounded-md border divide-y">
              {result.matches.map((m) => (
                <div key={m.rule_id} className="flex items-center justify-between px-4 py-3">
                  <span className="font-mono text-xs text-muted-foreground">{m.rule_id}</span>
                  <span className="text-sm font-medium">
                    {(m.score * 100).toFixed(1)}% match
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No policy rules matched.</p>
          )}
        </div>
      )}
    </div>
  );
}
