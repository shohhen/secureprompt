"use client";

/**
 * Phase 5 / Plan 05-04 — Policy rule create/edit form.
 */

import { useEffect } from "react";
import { useTranslations } from "next-intl";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { toast } from "sonner";
import * as Dialog from "@radix-ui/react-dialog";
import {
  useCreatePolicyRule,
  useUpdatePolicyRule,
  type PolicyRuleResponse,
} from "@/lib/hooks/use-policy-rules";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const ACTIONS = ["allow", "deny", "redact", "transform", "flag"] as const;

const schema = z.object({
  name: z.string().min(1, "validation.nameRequired").max(200),
  priority: z.coerce.number().int().min(0).max(10000),
  action: z.enum(ACTIONS),
  enabled: z.boolean(),
  dry_run: z.boolean(),
});
type FormData = z.infer<typeof schema>;

interface RuleFormProps {
  rule?: PolicyRuleResponse;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function RuleForm({ rule, open, onOpenChange }: RuleFormProps) {
  const t = useTranslations("policyRules");
  const isEdit = Boolean(rule);
  const create = useCreatePolicyRule();
  const update = useUpdatePolicyRule();
  const isPending = create.isPending || update.isPending;

  const form = useForm<FormData>({
    resolver: zodResolver(schema),
    defaultValues: {
      name: rule?.name ?? "",
      priority: rule?.priority ?? 100,
      action: (rule?.action as FormData["action"]) ?? "allow",
      enabled: rule?.enabled ?? true,
      dry_run: rule?.dry_run ?? false,
    },
  });

  useEffect(() => {
    if (open) {
      form.reset({
        name: rule?.name ?? "",
        priority: rule?.priority ?? 100,
        action: (rule?.action as FormData["action"]) ?? "allow",
        enabled: rule?.enabled ?? true,
        dry_run: rule?.dry_run ?? false,
      });
    }
  }, [open, rule, form]);

  async function onSubmit(data: FormData) {
    try {
      if (isEdit && rule) {
        await update.mutateAsync({
          id: rule.id,
          ...data,
        });
        toast.success(t("updated"));
      } else {
        await create.mutateAsync(data);
        toast.success(t("created"));
      }
      onOpenChange(false);
    } catch (err: unknown) {
      const code =
        err instanceof Error && "code" in err
          ? (err as { code: string }).code
          : "";
      if (code === "priority_conflict") {
        toast.error(t("priorityConflict"));
      } else {
        toast.error(isEdit ? t("updateFailed") : t("createFailed"));
      }
    }
  }

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/40 z-40" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-lg bg-background border shadow-lg p-6 space-y-4">
          <Dialog.Title className="text-lg font-semibold">
            {isEdit ? t("editTitle") : t("newTitle")}
          </Dialog.Title>

          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="rule-name">{t("fieldName")}</Label>
              <Input
                id="rule-name"
                placeholder={t("fieldNamePlaceholder")}
                {...form.register("name")}
              />
              {form.formState.errors.name && (
                <p className="text-xs text-destructive">
                  {form.formState.errors.name.message}
                </p>
              )}
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="rule-priority">{t("fieldPriority")}</Label>
                <Input
                  id="rule-priority"
                  type="number"
                  min={0}
                  max={10000}
                  {...form.register("priority")}
                />
                {form.formState.errors.priority && (
                  <p className="text-xs text-destructive">
                    {form.formState.errors.priority.message}
                  </p>
                )}
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="rule-action">{t("fieldAction")}</Label>
                <select
                  id="rule-action"
                  {...form.register("action")}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                >
                  {ACTIONS.map((a) => (
                    <option key={a} value={a}>
                      {a}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="flex gap-6">
              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input type="checkbox" {...form.register("enabled")} />
                {t("fieldEnabled")}
              </label>
              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input type="checkbox" {...form.register("dry_run")} />
                {t("fieldDryRun")}
              </label>
            </div>

            <div className="flex justify-end gap-2">
              <Dialog.Close asChild>
                <Button variant="outline" size="sm" type="button">
                  {t("cancel")}
                </Button>
              </Dialog.Close>
              <Button size="sm" type="submit" disabled={isPending}>
                {isPending ? t("saving") : isEdit ? t("save") : t("create")}
              </Button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
