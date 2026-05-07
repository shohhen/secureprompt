"use client";

/**
 * Phase 5 / Plan 05-04 — Providers management panel.
 */

import { useState, useCallback } from "react";
import { useSession } from "next-auth/react";
import { toast } from "sonner";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/data-table/data-table";
import {
  useProviders,
  useDeleteProvider,
  type ProviderResponse,
} from "@/lib/hooks/use-providers";
import { ProviderForm } from "./provider-form";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { canWrite } from "@/lib/roles";

export function ProvidersPanel() {
  const { data: session } = useSession();
  const writable = canWrite(session?.role);
  const { data: providers, isLoading } = useProviders();
  const deleteProvider = useDeleteProvider();
  const [editTarget, setEditTarget] = useState<ProviderResponse | undefined>();
  const [addOpen, setAddOpen] = useState(false);

  const handleDelete = useCallback(
    (id: string, name: string) => {
      if (!window.confirm(`Delete provider "${name}"?`)) return;
      deleteProvider.mutate(id, {
        onSuccess: () => toast.success("Provider deleted."),
        onError: () => toast.error("Failed to delete provider."),
      });
    },
    [deleteProvider],
  );

  const columns: ColumnDef<ProviderResponse>[] = [
    {
      accessorKey: "name",
      header: "Name",
      cell: ({ getValue }) => (
        <span className="font-medium">{getValue<string>()}</span>
      ),
    },
    {
      accessorKey: "provider_type",
      header: "Type",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs">{getValue<string>()}</span>
      ),
    },
    {
      accessorKey: "has_credential",
      header: "Credential",
      cell: ({ getValue }) =>
        getValue<boolean>() ? (
          <Badge variant="secondary">Set</Badge>
        ) : (
          <Badge variant="outline">Not set</Badge>
        ),
    },
    {
      accessorKey: "last_rotated_at",
      header: "Last Rotated",
      cell: ({ getValue }) => {
        const v = getValue<string>();
        return (
          <span className="text-xs text-muted-foreground">
            {v ? new Date(v).toLocaleDateString() : "Never"}
          </span>
        );
      },
    },
    {
      id: "actions",
      header: "",
      cell: ({ row }) => {
        const prov = row.original;
        if (!writable) return null;
        return (
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => setEditTarget(prov)}
            >
              Edit
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => handleDelete(prov.id, prov.name)}
              disabled={deleteProvider.isPending}
            >
              Delete
            </Button>
          </div>
        );
      },
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-medium">AI Providers</h2>
          <p className="text-sm text-muted-foreground">
            Manage provider credentials. Credentials are stored encrypted and
            are never exposed in API responses.
            {!writable && (
              <span className="block mt-1 text-xs">
                Only owners and admins can add or edit providers.
              </span>
            )}
          </p>
        </div>
        {writable && (
          <Button size="sm" onClick={() => setAddOpen(true)}>
            Add Provider
          </Button>
        )}
      </div>

      <DataTable
        columns={columns}
        data={providers ?? []}
        isLoading={isLoading}
        emptyMessage="No providers configured."
      />

      {/* Add dialog */}
      <ProviderForm
        open={addOpen}
        onOpenChange={setAddOpen}
      />

      {/* Edit dialog */}
      {editTarget && (
        <ProviderForm
          provider={editTarget}
          open={true}
          onOpenChange={(open) => {
            if (!open) setEditTarget(undefined);
          }}
        />
      )}
    </div>
  );
}
