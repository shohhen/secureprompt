"use client";

/**
 * Phase 5 / Plan 05-04 — Policy Rules management panel.
 *
 * Inline toggle switches for enabled/dry-run use PATCH endpoints.
 */

import { useState, useCallback } from "react";
import { useTranslations } from "next-intl";
import { useSession } from "next-auth/react";
import { toast } from "sonner";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/data-table/data-table";
import {
  usePolicyRules,
  useDeletePolicyRule,
  useTogglePolicyRuleEnabled,
  useTogglePolicyRuleDryRun,
  type PolicyRuleResponse,
} from "@/lib/hooks/use-policy-rules";
import { RuleForm } from "./rule-form";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { canWrite } from "@/lib/roles";

export function PolicyRulesPanel() {
  const { data: session } = useSession();
  const t = useTranslations("policyRules");
  const writable = canWrite(session?.role);
  const { data: rules, isLoading } = usePolicyRules();
  const deleteRule = useDeletePolicyRule();
  const toggleEnabled = useTogglePolicyRuleEnabled();
  const toggleDryRun = useTogglePolicyRuleDryRun();
  const [editTarget, setEditTarget] = useState<PolicyRuleResponse | undefined>();
  const [addOpen, setAddOpen] = useState(false);

  const handleDelete = useCallback(
    (id: string, name: string) => {
      if (!window.confirm(t("deleteConfirm", { name }))) return;
      deleteRule.mutate(id, {
        onSuccess: () => toast.success(t("deleted")),
        onError: () => toast.error(t("deleteFailed")),
      });
    },
    [deleteRule, t],
  );

  const columns: ColumnDef<PolicyRuleResponse>[] = [
    {
      accessorKey: "priority",
      header: t("colPriority"),
      cell: ({ getValue }) => (
        <span className="tabular-nums text-xs font-mono">{getValue<number>()}</span>
      ),
    },
    {
      accessorKey: "name",
      header: t("colName"),
      cell: ({ getValue }) => (
        <span className="font-medium">{getValue<string>()}</span>
      ),
    },
    {
      accessorKey: "action",
      header: t("colAction"),
      cell: ({ getValue }) => {
        const action = getValue<string>();
        const variant =
          action === "deny"
            ? "destructive"
            : action === "allow"
              ? "secondary"
              : "outline";
        return <Badge variant={variant}>{action}</Badge>;
      },
    },
    {
      accessorKey: "enabled",
      header: t("colEnabled"),
      cell: ({ row }) => {
        const rule = row.original;
        return (
          <input
            type="checkbox"
            checked={rule.enabled}
            onChange={(e) => {
              toggleEnabled.mutate(
                { id: rule.id, value: e.target.checked },
                {
                  onError: () => toast.error(t("toggleFailed")),
                },
              );
            }}
            disabled={!writable}
            className="cursor-pointer disabled:cursor-not-allowed disabled:opacity-50"
            aria-label={t("toggleEnabledAria", { name: rule.name })}
          />
        );
      },
    },
    {
      accessorKey: "dry_run",
      header: t("colDryRun"),
      cell: ({ row }) => {
        const rule = row.original;
        return (
          <input
            type="checkbox"
            checked={rule.dry_run}
            onChange={(e) => {
              toggleDryRun.mutate(
                { id: rule.id, value: e.target.checked },
                {
                  onError: () => toast.error(t("toggleDryRunFailed")),
                },
              );
            }}
            disabled={!writable}
            className="cursor-pointer disabled:cursor-not-allowed disabled:opacity-50"
            aria-label={t("toggleDryRunAria", { name: rule.name })}
          />
        );
      },
    },
    {
      id: "actions",
      header: "",
      cell: ({ row }) => {
        const rule = row.original;
        if (!writable) return null;
        return (
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => setEditTarget(rule)}
            >
              {t("edit")}
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => handleDelete(rule.id, rule.name)}
              disabled={deleteRule.isPending}
            >
              {t("delete")}
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
          <h2 className="text-lg font-medium">{t("title")}</h2>
          <p className="text-sm text-muted-foreground">
            {t("description")}
            {!writable && (
              <span className="block mt-1 text-xs">{t("readOnlyNotice")}</span>
            )}
          </p>
        </div>
        {writable && (
          <Button size="sm" onClick={() => setAddOpen(true)}>
            {t("addRule")}
          </Button>
        )}
      </div>

      <DataTable
        columns={columns}
        data={rules ?? []}
        isLoading={isLoading}
        emptyMessage={t("empty")}
      />

      {/* Add dialog */}
      <RuleForm open={addOpen} onOpenChange={setAddOpen} />

      {/* Edit dialog */}
      {editTarget && (
        <RuleForm
          rule={editTarget}
          open={true}
          onOpenChange={(open) => {
            if (!open) setEditTarget(undefined);
          }}
        />
      )}
    </div>
  );
}
