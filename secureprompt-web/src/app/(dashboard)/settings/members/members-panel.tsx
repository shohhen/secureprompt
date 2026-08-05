"use client";

/**
 * Workspace members panel.
 *
 * Lists users in the caller's workspace (GET /v1/users) and — for admins and
 * owners — exposes an invite form that creates a new user account via
 * POST /v1/users. Role changes and deletion are not yet supported by the
 * backend, so this panel is intentionally minimal.
 */

import { useCallback } from "react";
import { useTranslations } from "next-intl";
import { useSession } from "next-auth/react";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/data-table/data-table";
import { useUsers, type UserResponse } from "@/lib/hooks/use-users";
import { InviteUserDialog } from "./invite-user-dialog";
import { Badge } from "@/components/ui/badge";
import type { AppRole } from "@/types/next-auth";

const ADMIN_ROLES: AppRole[] = ["owner", "admin"];

const ROLE_BADGE_VARIANT: Record<AppRole, "default" | "secondary" | "outline"> = {
  owner: "default",
  admin: "default",
  developer: "secondary",
  employee: "outline",
  viewer: "outline",
};

export function MembersPanel() {
  const { data: session } = useSession();
  const t = useTranslations("members");
  const canInvite = !!session?.role && ADMIN_ROLES.includes(session.role);
  const { data: users, isLoading } = useUsers();

  const columns = useCallback((): ColumnDef<UserResponse>[] => {
    return [
      {
        accessorKey: "email",
        header: t("colEmail"),
        cell: ({ row, getValue }) => {
          const isSelf = row.original.id === session?.user?.id;
          return (
            <span className="font-medium">
              {getValue<string>()}
              {isSelf && (
                <span className="ml-2 text-xs text-muted-foreground">{t("you")}</span>
              )}
            </span>
          );
        },
      },
      {
        accessorKey: "role",
        header: t("colRole"),
        cell: ({ getValue }) => {
          const role = getValue<AppRole>();
          return (
            <Badge variant={ROLE_BADGE_VARIANT[role] ?? "outline"}>{role}</Badge>
          );
        },
      },
      {
        accessorKey: "created_at",
        header: t("colJoined"),
        cell: ({ getValue }) => (
          <span className="text-xs text-muted-foreground">
            {new Date(getValue<string>()).toLocaleDateString()}
          </span>
        ),
      },
    ];
  }, [session?.user?.id, t])();

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-medium">{t("title")}</h2>
          <p className="text-sm text-muted-foreground">
            {t("description")}
          </p>
        </div>
        {canInvite && <InviteUserDialog />}
      </div>

      <DataTable
        columns={columns}
        data={users ?? []}
        isLoading={isLoading}
        emptyMessage={t("empty")}
      />
    </div>
  );
}
