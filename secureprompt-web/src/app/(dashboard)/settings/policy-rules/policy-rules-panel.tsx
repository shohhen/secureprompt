"use client";

/**
 * Phase 5 / Plan 05-04 — Policy Rules management panel.
 *
 * Inline toggle switches for enabled/dry-run use PATCH endpoints.
 */

import { useState, useCallback } from "react";
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
  const writable = canWrite(session?.role);
  const { data: rules, isLoading } = usePolicyRules();
  const deleteRule = useDeletePolicyRule();
  const toggleEnabled = useTogglePolicyRuleEnabled();
  const toggleDryRun = useTogglePolicyRuleDryRun();
  const [editTarget, setEditTarget] = useState<PolicyRuleResponse | undefined>();
  const [addOpen, setAddOpen] = useState(false);

  const handleDelete = useCallback(
    (id: string, name: string) => {
      if (!window.confirm(`Delete rule "${name}"?`)) return;
      deleteRule.mutate(id, {
        onSuccess: () => toast.success("Rule deleted."),
        onError: () => toast.error("Failed to delete rule."),
      });
    },
    [deleteRule],
  );

  const columns: ColumnDef<PolicyRuleResponse>[] = [
    {
      accessorKey: "priority",
      header: "Priority",
      cell: ({ getValue }) => (
        <span className="tabular-nums text-xs font-mono">{getValue<number>()}</span>
      ),
    },
    {
      accessorKey: "name",
      header: "Name",
      cell: ({ getValue }) => (
        <span className="font-medium">{getValue<string>()}</span>
      ),
    },
    {
      accessorKey: "action",
      header: "Action",
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
      header: "Enabled",
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
                  onError: () => toast.error("Failed to toggle rule."),
                },
              );
            }}
            disabled={!writable}
            className="cursor-pointer disabled:cursor-not-allowed disabled:opacity-50"
            aria-label={`Toggle enabled for ${rule.name}`}
          />
        );
      },
    },
    {
      accessorKey: "dry_run",
      header: "Dry Run",
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
                  onError: () => toast.error("Failed to toggle dry-run."),
                },
              );
            }}
            disabled={!writable}
            className="cursor-pointer disabled:cursor-not-allowed disabled:opacity-50"
            aria-label={`Toggle dry-run for ${rule.name}`}
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
              Edit
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => handleDelete(rule.id, rule.name)}
              disabled={deleteRule.isPending}
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
          <h2 className="text-lg font-medium">Policy Rules</h2>
          <p className="text-sm text-muted-foreground">
            Rules are evaluated in priority order (lower number = higher
            priority). Use dry-run to test without enforcement.
            {!writable && (
              <span className="block mt-1 text-xs">
                Only owners and admins can add or edit policy rules.
              </span>
            )}
          </p>
        </div>
        {writable && (
          <Button size="sm" onClick={() => setAddOpen(true)}>
            Add Rule
          </Button>
        )}
      </div>

      <DataTable
        columns={columns}
        data={rules ?? []}
        isLoading={isLoading}
        emptyMessage="No policy rules. Create one to start enforcing policies."
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
