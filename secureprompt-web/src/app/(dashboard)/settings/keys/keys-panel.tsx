"use client";

/**
 * Phase 5 / Plan 05-04 — API Keys client panel.
 *
 * Lists workspace API keys (prefix only, never full key) and allows admins
 * to create new keys (one-time reveal) and revoke existing ones.
 */

import { useCallback, useMemo } from "react";
import { useTranslations } from "next-intl";
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
  const t = useTranslations("keys");
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
      if (!window.confirm(t("revokeConfirm", { name }))) return;
      revoke.mutate(id, {
        onSuccess: () => toast.success(t("revoked")),
        onError: () => toast.error(t("revokeFailed")),
      });
    },
    [revoke, t],
  );

  const columns: ColumnDef<KeyResponse>[] = [
    {
      accessorKey: "name",
      header: t("colName"),
      cell: ({ getValue }) => (
        <span className="font-medium">{getValue<string>()}</span>
      ),
    },
    {
      accessorKey: "prefix",
      header: t("colPrefix"),
      cell: ({ getValue }) => (
        <span className="font-mono text-xs text-muted-foreground">
          {getValue<string>()}...
        </span>
      ),
    },
    {
      accessorKey: "assigned_user_id",
      header: t("colAssignee"),
      cell: ({ getValue }) => {
        const id = getValue<string | null | undefined>();
        if (!id) {
          return <span className="text-xs text-muted-foreground">—</span>;
        }
        const email = userEmailById.get(id);
        return (
          <span className="text-xs">
            {email ?? <span className="text-muted-foreground">{t("unnamedUser", { id: id.slice(0, 8) })}</span>}
          </span>
        );
      },
    },
    {
      accessorKey: "created_at",
      header: t("colCreated"),
      cell: ({ getValue }) => (
        <span className="text-xs text-muted-foreground">
          {new Date(getValue<string>()).toLocaleDateString()}
        </span>
      ),
    },
    {
      accessorKey: "revoked_at",
      header: t("colStatus"),
      cell: ({ getValue }) =>
        getValue<string | null>() ? (
          <Badge variant="destructive">{t("statusRevoked")}</Badge>
        ) : (
          <Badge variant="secondary">{t("statusActive")}</Badge>
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
            {t("revoke")}
          </Button>
        );
      },
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-medium">{t("title")}</h2>
          <p className="text-sm text-muted-foreground">
            {t("description")}
            {!writable && (
              <span className="block mt-1 text-xs">{t("readOnlyNotice")}</span>
            )}
          </p>
        </div>
        {writable && <CreateKeyDialog />}
      </div>

      <DataTable
        columns={columns}
        data={keys ?? []}
        isLoading={isLoading}
        emptyMessage={t("empty")}
      />
    </div>
  );
}
