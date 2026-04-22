"use client";

import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";

interface AuditEntry {
  id: string;
  created_at: string;
  model: string;
  violation_type: string | null;
  action_taken: string;
  prompt_preview: string;
}

interface Props {
  workspaceId: string;
}

export function AuditTable({ workspaceId }: Props) {
  const { data, isLoading, error } = useQuery<AuditEntry[]>({
    queryKey: ["audit", workspaceId],
    queryFn: () => apiFetch("/v1/requests?has_violation=true&limit=100"),
  });

  if (isLoading) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (error) return <p className="text-sm text-destructive">Failed to load audit log.</p>;
  if (!data?.length) return <p className="text-sm text-muted-foreground">No violations recorded.</p>;

  return (
    <div className="rounded-md border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b bg-muted/50">
            <th className="px-4 py-3 text-left font-medium">Time</th>
            <th className="px-4 py-3 text-left font-medium">Model</th>
            <th className="px-4 py-3 text-left font-medium">Violation</th>
            <th className="px-4 py-3 text-left font-medium">Action</th>
            <th className="px-4 py-3 text-left font-medium">Prompt Preview</th>
          </tr>
        </thead>
        <tbody>
          {data.map((entry) => (
            <tr key={entry.id} className="border-b last:border-0">
              <td className="px-4 py-3 text-muted-foreground whitespace-nowrap">
                {new Date(entry.created_at).toLocaleString()}
              </td>
              <td className="px-4 py-3 font-mono text-xs">{entry.model}</td>
              <td className="px-4 py-3">
                {entry.violation_type ? (
                  <span className="rounded bg-red-100 px-2 py-0.5 text-xs text-red-800 dark:bg-red-900/30 dark:text-red-400">
                    {entry.violation_type}
                  </span>
                ) : (
                  <span className="text-muted-foreground">—</span>
                )}
              </td>
              <td className="px-4 py-3">
                <span className="rounded bg-yellow-100 px-2 py-0.5 text-xs text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400">
                  {entry.action_taken}
                </span>
              </td>
              <td className="px-4 py-3 text-muted-foreground max-w-xs truncate">
                {entry.prompt_preview}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
