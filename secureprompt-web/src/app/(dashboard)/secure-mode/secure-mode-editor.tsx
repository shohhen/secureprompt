"use client";

/**
 * Client-side editor for the workspace secure-mode config.
 *
 * Binds to `useSecureMode()` + `useUpdateSecureMode()`. The form is
 * read-only for non-admin sessions (matching the backend's 403).
 */

import { useEffect } from "react";
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

const LEVEL_OPTIONS: { value: SecureModeLevel; label: string; hint: string }[] = [
  {
    value: "permissive",
    label: "Permissive",
    hint: "Log detections but never block. Good for onboarding.",
  },
  {
    value: "standard",
    label: "Standard",
    hint: "Redact PII/secrets in-flight. Block only on high-confidence violations.",
  },
  {
    value: "strict",
    label: "Strict",
    hint: "Block the request on any PII, secret, or injection detection.",
  },
];

const ADMIN_ROLES: AppRole[] = ["owner", "admin"];

export function SecureModeEditor() {
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
      toast.success("Secure mode updated.");
    } catch (e) {
      const message = e instanceof Error ? e.message : "Failed to update secure mode.";
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
        <p className="font-medium text-destructive">Failed to load secure mode.</p>
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
            <p className="font-medium">Secure Mode</p>
            <p className="text-sm text-muted-foreground max-w-2xl">
              Master switch for all workspace-level security controls. When off,
              the gateway still logs traffic but applies no redaction or blocking.
            </p>
          </div>
          <Switch
            checked={form.watch("enabled")}
            onCheckedChange={(v) => form.setValue("enabled", v, { shouldDirty: true })}
            aria-label="Enable secure mode"
          />
        </div>

        {/* Level radios */}
        <div className="rounded-lg border p-6 space-y-4">
          <div>
            <p className="font-medium">Enforcement level</p>
            <p className="text-sm text-muted-foreground">
              Controls how aggressively the gateway reacts to detections.
            </p>
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            {LEVEL_OPTIONS.map((opt) => {
              const active = level === opt.value;
              return (
                <label
                  key={opt.value}
                  className={`cursor-pointer rounded-md border p-4 transition-colors ${
                    active
                      ? "border-primary bg-primary/5"
                      : "hover:bg-muted/50"
                  }`}
                >
                  <input
                    type="radio"
                    className="sr-only"
                    value={opt.value}
                    checked={active}
                    onChange={() =>
                      form.setValue("level", opt.value, { shouldDirty: true })
                    }
                  />
                  <p className="font-medium text-sm">{opt.label}</p>
                  <p className="text-xs text-muted-foreground mt-1">{opt.hint}</p>
                </label>
              );
            })}
          </div>
        </div>

        {/* Toggles */}
        {blockTogglesLocked && (
          <p className="text-xs text-muted-foreground -mb-3">
            {level === "permissive"
              ? "Block toggles are forced off at Permissive level."
              : "Block toggles are forced on at Strict level."}{" "}
            Switch to Standard to control them individually.
          </p>
        )}
        <div className="rounded-lg border divide-y">
          <ToggleRow
            title="Block on PII detection"
            hint="Reject the request when personal data (names, emails, SSNs, etc.) is detected."
            checked={form.watch("block_on_pii_detection")}
            onCheckedChange={(v) =>
              form.setValue("block_on_pii_detection", v, { shouldDirty: true })
            }
            disabled={blockTogglesLocked}
          />
          <ToggleRow
            title="Block on prompt injection"
            hint="Reject the request when the ML sidecar flags likely prompt injection (requires ML sidecar)."
            checked={form.watch("block_on_injection_detection")}
            onCheckedChange={(v) =>
              form.setValue("block_on_injection_detection", v, { shouldDirty: true })
            }
            disabled={blockTogglesLocked}
          />
          <ToggleRow
            title="Redact PII in responses"
            hint="Scan model completions and replace PII with opaque tokens before returning to the caller."
            checked={form.watch("redact_pii_in_responses")}
            onCheckedChange={(v) =>
              form.setValue("redact_pii_in_responses", v, { shouldDirty: true })
            }
          />
        </div>

        {!canEdit && (
          <p className="text-xs text-muted-foreground">
            You have {session?.role ?? "guest"} access — only admins and owners
            can modify secure-mode settings.
          </p>
        )}

        {data?.updated_at && (
          <p className="text-xs text-muted-foreground">
            Last updated {new Date(data.updated_at).toLocaleString()}.
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
            Reset
          </Button>
          <Button
            type="submit"
            size="sm"
            disabled={!canEdit || !form.formState.isDirty || update.isPending}
          >
            {update.isPending ? "Saving…" : "Save changes"}
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
