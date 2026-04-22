"use client";

import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api-fetch";

interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
}

interface Props {
  workspaceId: string;
}

export function ApiKeysTable({ workspaceId }: Props) {
  const { data, isLoading, error } = useQuery<ApiKey[]>({
    queryKey: ["api-keys", workspaceId],
    queryFn: () => apiFetch("/v1/keys"),
  });

  if (isLoading) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (error) return <p className="text-sm text-destructive">Failed to load API keys.</p>;
  if (!data?.length) return <p className="text-sm text-muted-foreground">No API keys yet.</p>;

  return (
    <div className="rounded-md border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b bg-muted/50">
            <th className="px-4 py-3 text-left font-medium">Name</th>
            <th className="px-4 py-3 text-left font-medium">Key Prefix</th>
            <th className="px-4 py-3 text-left font-medium">Created</th>
            <th className="px-4 py-3 text-left font-medium">Last Used</th>
            <th className="px-4 py-3 text-left font-medium">Expires</th>
          </tr>
        </thead>
        <tbody>
          {data.map((k) => (
            <tr key={k.id} className="border-b last:border-0">
              <td className="px-4 py-3">{k.name}</td>
              <td className="px-4 py-3 font-mono text-xs">{k.key_prefix}…</td>
              <td className="px-4 py-3 text-muted-foreground">
                {new Date(k.created_at).toLocaleDateString()}
              </td>
              <td className="px-4 py-3 text-muted-foreground">
                {k.last_used_at ? new Date(k.last_used_at).toLocaleDateString() : "Never"}
              </td>
              <td className="px-4 py-3 text-muted-foreground">
                {k.expires_at ? new Date(k.expires_at).toLocaleDateString() : "Never"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
