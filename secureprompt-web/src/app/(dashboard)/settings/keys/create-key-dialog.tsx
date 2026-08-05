"use client";

/**
 * Phase 5 / Plan 05-04 — Create API key dialog.
 *
 * On success, shows the one-time key value in a read-only input.
 * The key is never stored in state beyond dialog lifetime — closing
 * the dialog clears it.
 *
 * Phase 7 (009 migration) — admin can assign the key to a workspace
 * member. When assigned, the plaintext is encrypted-at-rest so the
 * LibreChat backend can fetch it server-to-server via the member's
 * JWT (member never sees or types the raw key).
 */

import { useState } from "react";
import { useTranslations } from "next-intl";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { toast } from "sonner";
import * as Dialog from "@radix-ui/react-dialog";
import { useCreateKey } from "@/lib/hooks/use-keys";
import { useUsers } from "@/lib/hooks/use-users";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const schema = z.object({
  name: z.string().min(1, "validation.nameRequired").max(120),
  user_id: z.string().optional(),
});
type FormData = z.infer<typeof schema>;

interface CreateKeyDialogProps {
  onCreated?: () => void;
}

export function CreateKeyDialog({ onCreated }: CreateKeyDialogProps) {
  const t = useTranslations("keys");
  const [open, setOpen] = useState(false);
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const { mutateAsync, isPending } = useCreateKey();
  const { data: users, isLoading: usersLoading } = useUsers();

  const form = useForm<FormData>({
    resolver: zodResolver(schema),
    defaultValues: { name: "", user_id: "" },
  });

  function handleOpenChange(next: boolean) {
    if (!next) {
      // Flush one-time key on close
      setCreatedKey(null);
      form.reset();
    }
    setOpen(next);
  }

  async function onSubmit(data: FormData) {
    try {
      const result = await mutateAsync({
        name: data.name,
        // Empty string from <select> means "unassigned workspace-scoped key";
        // omit the field rather than send "" so the backend treats it as None.
        ...(data.user_id ? { user_id: data.user_id } : {}),
      });
      setCreatedKey(result.api_key);
      onCreated?.();
    } catch {
      toast.error(t("createFailed"));
    }
  }

  return (
    <Dialog.Root open={open} onOpenChange={handleOpenChange}>
      <Dialog.Trigger asChild>
        <Button size="sm">{t("createKey")}</Button>
      </Dialog.Trigger>

      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/40 z-40" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-lg bg-background border shadow-lg p-6 space-y-4">
          <Dialog.Title className="text-lg font-semibold">
            {createdKey ? t("keyCreatedTitle") : t("createKeyTitle")}
          </Dialog.Title>

          {createdKey ? (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                {t("copyNowWarning")}
              </p>
              <div className="relative">
                <Input
                  readOnly
                  value={createdKey}
                  className="font-mono text-xs pr-24"
                  onFocus={(e) => e.target.select()}
                />
                <button
                  type="button"
                  onClick={() => {
                    void navigator.clipboard.writeText(createdKey);
                    toast.success(t("copiedToClipboard"));
                  }}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-xs text-primary hover:underline"
                >
                  {t("copy")}
                </button>
              </div>
              <div className="flex justify-end">
                <Dialog.Close asChild>
                  <Button variant="outline" size="sm">
                    {t("done")}
                  </Button>
                </Dialog.Close>
              </div>
            </div>
          ) : (
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="key-name">{t("keyName")}</Label>
                <Input
                  id="key-name"
                  placeholder={t("keyNamePlaceholder")}
                  {...form.register("name")}
                />
                {form.formState.errors.name && (
                  <p className="text-xs text-destructive">
                    {form.formState.errors.name.message}
                  </p>
                )}
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="key-assignee">{t("assignee")}</Label>
                <select
                  id="key-assignee"
                  className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                  {...form.register("user_id")}
                  disabled={usersLoading}
                >
                  <option value="">{t("assigneeUnassigned")}</option>
                  {(users ?? []).map((u) => (
                    <option key={u.id} value={u.id}>
                      {u.email} ({u.role})
                    </option>
                  ))}
                </select>
                <p className="text-xs text-muted-foreground">
                  {t("assigneeHint")}
                </p>
              </div>

              <div className="flex justify-end gap-2">
                <Dialog.Close asChild>
                  <Button variant="outline" size="sm" type="button">
                    {t("cancel")}
                  </Button>
                </Dialog.Close>
                <Button size="sm" type="submit" disabled={isPending}>
                  {isPending ? t("creating") : t("create")}
                </Button>
              </div>
            </form>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
