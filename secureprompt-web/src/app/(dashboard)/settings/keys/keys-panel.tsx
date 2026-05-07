"use client";

/**
 * Phase 5 / Plan 05-04 — API Keys client panel.
 *
 * Lists workspace API keys (prefix only, never full key) and allows admins
 * to create new keys (one-time reveal) and revoke existing ones.
 */

import { useCallback, useMemo } from "react";
import { useSession } from "next-auth/react";
import { toast } from "sonner";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/data-table/data-table";
import { useKeys, useRevokeKey, type KeyResponse } from "@/lib/hooks/use-keys";
import { useUsers } from "@/lib/hooks/use-users";
import { CreateKeyDialog } from "./create-key-dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { canWrite } from "@/lib/roles";

interface KeysPanelProps {
  workspaceId: string;
}

export function KeysPanel({ workspaceId: _workspaceId }: KeysPanelProps) {
  const { data: session } = useSession();
  const writable = canWrite(session?.role);
  const { data: keys, isLoading } = useKeys();
  const { data: users } = useUsers();
  const userEmailById = useMemo(() => {
    const map = new Map<string, string>();
    (users ?? []).forEach((u) => map.set(u.id, u.email));
    return map;
  }, [users]);
  const revoke = useRevokeKey();

  const handleRevoke = useCallback(
    (id: string, name: string) => {
      if (!window.confirm(`Revoke key "${name}"? This cannot be undone.`)) return;
      revoke.mutate(id, {
        onSuccess: () => toast.success("Key revoked."),
        onError: () => toast.error("Failed to revoke key."),
      });
    },
    [revoke],
  );

  const columns: ColumnDef<KeyResponse>[] = [
    {
      accessorKey: "name",
      header: "Name",
      cell: ({ getValue }) => (
        <span className="font-medium">{getValue<string>()}</span>
      ),
    },
    {
      accessorKey: "prefix",
      header: "Prefix",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs text-muted-foreground">
          {getValue<string>()}...
        </span>
      ),
    },
    {
      accessorKey: "assigned_user_id",
      header: "Assignee",
      cell: ({ getValue }) => {
        const id = getValue<string | null | undefined>();
        if (!id) {
          return <span className="text-xs text-muted-foreground">—</span>;
        }
        const email = userEmailById.get(id);
        return (
          <span className="text-xs">
            {email ?? <span className="text-muted-foreground">user {id.slice(0, 8)}…</span>}
          </span>
        );
      },
    },
    {
      accessorKey: "created_at",
      header: "Created",
      cell: ({ getValue }) => (
        <span className="text-xs text-muted-foreground">
          {new Date(getValue<string>()).toLocaleDateString()}
        </span>
      ),
    },
    {
      accessorKey: "revoked_at",
      header: "Status",
      cell: ({ getValue }) =>
        getValue<string | null>() ? (
          <Badge variant="destructive">Revoked</Badge>
        ) : (
          <Badge variant="secondary">Active</Badge>
        ),
    },
    {
      id: "actions",
      header: "",
      cell: ({ row }) => {
        const key = row.original;
        if (key.revoked_at || !writable) return null;
        return (
          <Button
            size="sm"
            variant="outline"
            onClick={() => handleRevoke(key.id, key.name)}
            disabled={revoke.isPending}
          >
            Revoke
          </Button>
        );
      },
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-medium">API Keys</h2>
          <p className="text-sm text-muted-foreground">
            Keys are shown with prefix only — the full key is revealed once at
            creation.
            {!writable && (
              <span className="block mt-1 text-xs">
                Only owners and admins can create or revoke keys.
              </span>
            )}
          </p>
        </div>
        {writable && <CreateKeyDialog />}
      </div>

      <DataTable
        columns={columns}
        data={keys ?? []}
        isLoading={isLoading}
        emptyMessage="No API keys yet. Create one to get started."
      />
    </div>
  );
}
