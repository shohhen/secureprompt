"use client";

/**
 * Client-side editor for the workspace secure-mode config.
 *
 * Binds to `useSecureMode()` + `useUpdateSecureMode()`. The form is
 * read-only for non-admin sessions (matching the backend's 403).
 */

import { useEffect } from "react";
import { useTranslations } from "next-intl";
import { useSession } from "next-auth/react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { toast } from "sonner";
import {
  useSecureMode,
  useUpdateSecureMode,
  type SecureModeLevel,
} from "@/lib/hooks/use-secure-mode";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import type { AppRole } from "@/types/next-auth";

const schema = z.object({
  enabled: z.boolean(),
  level: z.enum(["permissive", "standard", "strict"]),
  block_on_pii_detection: z.boolean(),
  block_on_injection_detection: z.boolean(),
  redact_pii_in_responses: z.boolean(),
});
type FormData = z.infer<typeof schema>;

/** Values only; the label and hint are resolved per render from `secureMode`. */
const LEVEL_OPTIONS: SecureModeLevel[] = ["permissive", "standard", "strict"];

const ADMIN_ROLES: AppRole[] = ["owner", "admin"];

export function SecureModeEditor() {
  const t = useTranslations("secureMode");
  const { data: session } = useSession();
  const { data, isLoading, error } = useSecureMode();
  const update = useUpdateSecureMode();
  const canEdit = !!session?.role && ADMIN_ROLES.includes(session.role);

  const form = useForm<FormData>({
    resolver: zodResolver(schema),
    defaultValues: {
      enabled: false,
      level: "standard",
      block_on_pii_detection: true,
      block_on_injection_detection: false,
      redact_pii_in_responses: true,
    },
  });

  useEffect(() => {
    if (data) {
      form.reset({
        enabled: data.enabled,
        level: data.level,
        block_on_pii_detection: data.block_on_pii_detection,
        block_on_injection_detection: data.block_on_injection_detection,
        redact_pii_in_responses: data.redact_pii_in_responses,
      });
    }
  }, [data, form]);

  async function onSubmit(values: FormData) {
    try {
      await update.mutateAsync(values);
      toast.success(t("updated"));
    } catch (e) {
      const message = e instanceof Error ? e.message : t("updateFailed");
      toast.error(message);
    }
  }

  // Rules of Hooks: every hook (including `form.watch` and `useEffect`) must
  // run on every render. The early `isLoading` / `error` returns below
  // would skip later hooks if we placed them after, so they live up here.
  const level = form.watch("level");

  // Couple level → block toggles. permissive forces all blocks OFF (the
  // mode's whole point is "never block"); strict forces them ON (the mode
  // blocks on any detection regardless of toggle). standard is the only
  // level where toggles are user-configurable.
  useEffect(() => {
    if (level === "permissive") {
      form.setValue("block_on_pii_detection", false, { shouldDirty: true });
      form.setValue("block_on_injection_detection", false, { shouldDirty: true });
    } else if (level === "strict") {
      form.setValue("block_on_pii_detection", true, { shouldDirty: true });
      form.setValue("block_on_injection_detection", true, { shouldDirty: true });
    }
  }, [level, form]);

  const blockTogglesLocked = level !== "standard";

  if (isLoading) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-20 w-full" />
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-16 w-full" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-lg border border-destructive/30 bg-destructive/5 p-4 text-sm">
        <p className="font-medium text-destructive">{t("loadFailed")}</p>
        <p className="text-muted-foreground mt-1">{error.message}</p>
      </div>
    );
  }

  return (
    <form
      onSubmit={form.handleSubmit(onSubmit)}
      className="space-y-6"
      aria-disabled={!canEdit}
    >
      <fieldset disabled={!canEdit} className="space-y-6 disabled:opacity-60">
        {/* Master switch */}
        <div className="rounded-lg border p-6 flex items-center justify-between gap-4">
          <div>
            <p className="font-medium">{t("masterTitle")}</p>
            <p className="text-sm text-muted-foreground max-w-2xl">
              {t("masterDescription")}
            </p>
          </div>
          <Switch
            checked={form.watch("enabled")}
            onCheckedChange={(v) => form.setValue("enabled", v, { shouldDirty: true })}
            aria-label={t("enableAria")}
          />
        </div>

        {/* Level radios */}
        <div className="rounded-lg border p-6 space-y-4">
          <div>
            <p className="font-medium">{t("levelTitle")}</p>
            <p className="text-sm text-muted-foreground">{t("levelDescription")}</p>
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            {LEVEL_OPTIONS.map((opt) => {
              const active = level === opt;
              return (
                <label
                  key={opt}
                  className={`cursor-pointer rounded-md border p-4 transition-colors ${
                    active
                      ? "border-primary bg-primary/5"
                      : "hover:bg-muted/50"
                  }`}
                >
                  <input
                    type="radio"
                    className="sr-only"
                    value={opt}
                    checked={active}
                    onChange={() => form.setValue("level", opt, { shouldDirty: true })}
                  />
                  <p className="font-medium text-sm">{t(`level_${opt}`)}</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {t(`level_${opt}_hint`)}
                  </p>
                </label>
              );
            })}
          </div>
        </div>

        {/* Toggles */}
        {blockTogglesLocked && (
          <p className="text-xs text-muted-foreground -mb-3">
            {level === "permissive"
              ? t("togglesLockedPermissive")
              : t("togglesLockedStrict")}{" "}
            {t("togglesLockedHint")}
          </p>
        )}
        <div className="rounded-lg border divide-y">
          <ToggleRow
            title={t("blockPiiTitle")}
            hint={t("blockPiiHint")}
            checked={form.watch("block_on_pii_detection")}
            onCheckedChange={(v) =>
              form.setValue("block_on_pii_detection", v, { shouldDirty: true })
            }
            disabled={blockTogglesLocked}
          />
          <ToggleRow
            title={t("blockInjectionTitle")}
            hint={t("blockInjectionHint")}
            checked={form.watch("block_on_injection_detection")}
            onCheckedChange={(v) =>
              form.setValue("block_on_injection_detection", v, { shouldDirty: true })
            }
            disabled={blockTogglesLocked}
          />
          <ToggleRow
            title={t("redactResponsesTitle")}
            hint={t("redactResponsesHint")}
            checked={form.watch("redact_pii_in_responses")}
            onCheckedChange={(v) =>
              form.setValue("redact_pii_in_responses", v, { shouldDirty: true })
            }
          />
        </div>

        {!canEdit && (
          <p className="text-xs text-muted-foreground">
            {t("readOnlyNotice", { role: session?.role ?? t("roleGuest") })}
          </p>
        )}

        {data?.updated_at && (
          <p className="text-xs text-muted-foreground">
            {t("lastUpdated", { when: new Date(data.updated_at).toLocaleString() })}
          </p>
        )}

        <div className="flex gap-2 justify-end">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => data && form.reset(data)}
            disabled={!form.formState.isDirty || update.isPending}
          >
            {t("reset")}
          </Button>
          <Button
            type="submit"
            size="sm"
            disabled={!canEdit || !form.formState.isDirty || update.isPending}
          >
            {update.isPending ? t("saving") : t("saveChanges")}
          </Button>
        </div>
      </fieldset>
    </form>
  );
}

function ToggleRow({
  title,
  hint,
  checked,
  onCheckedChange,
  disabled = false,
}: {
  title: string;
  hint: string;
  checked: boolean;
  onCheckedChange: (next: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <div className={`flex items-center justify-between gap-4 p-6 ${disabled ? "opacity-60" : ""}`}>
      <div>
        <Label className="font-medium">{title}</Label>
        <p className="text-sm text-muted-foreground max-w-2xl">{hint}</p>
      </div>
      <Switch
        checked={checked}
        onCheckedChange={onCheckedChange}
        aria-label={title}
        disabled={disabled}
      />
    </div>
  );
}
