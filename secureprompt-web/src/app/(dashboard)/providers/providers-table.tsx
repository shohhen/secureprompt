"use client";

import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";

interface Provider {
  id: string;
  name: string;
  provider_type: string;
  has_credential: boolean;
  last_rotated_at: string;
  created_at: string;
}

interface Props {
  workspaceId: string;
}

export function ProvidersTable({ workspaceId }: Props) {
  const { data, isLoading, error } = useQuery<Provider[]>({
    queryKey: ["providers", workspaceId],
    queryFn: () => apiFetch("/v1/providers"),
  });

  if (isLoading) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (error) return <p className="text-sm text-destructive">Failed to load providers.</p>;
  if (!data?.length) return <p className="text-sm text-muted-foreground">No providers configured yet.</p>;

  return (
    <div className="rounded-md border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b bg-muted/50">
            <th className="px-4 py-3 text-left font-medium">Name</th>
            <th className="px-4 py-3 text-left font-medium">Type</th>
            <th className="px-4 py-3 text-left font-medium">Credential</th>
            <th className="px-4 py-3 text-left font-medium">Last Rotated</th>
          </tr>
        </thead>
        <tbody>
          {data.map((p) => (
            <tr key={p.id} className="border-b last:border-0">
              <td className="px-4 py-3 font-mono text-xs">{p.name}</td>
              <td className="px-4 py-3">{p.provider_type}</td>
              <td className="px-4 py-3">
                {p.has_credential ? (
                  <span className="rounded bg-green-100 px-2 py-0.5 text-xs text-green-800 dark:bg-green-900/30 dark:text-green-400">
                    Set
                  </span>
                ) : (
                  <span className="rounded bg-yellow-100 px-2 py-0.5 text-xs text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400">
                    Missing
                  </span>
                )}
              </td>
              <td className="px-4 py-3 text-muted-foreground">
                {new Date(p.last_rotated_at).toLocaleDateString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
