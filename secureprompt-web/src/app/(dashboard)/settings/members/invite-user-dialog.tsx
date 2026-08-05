"use client";

/**
 * Invite a new user to the current workspace.
 *
 * The backend's POST /v1/users creates the account with the provided password
 * (there is no email-invite flow yet), so this dialog asks the admin to set
 * a temporary password they can hand to the new member out-of-band.
 */

import { useState } from "react";
import { useTranslations } from "next-intl";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { toast } from "sonner";
import * as Dialog from "@radix-ui/react-dialog";
import { useCreateUser } from "@/lib/hooks/use-users";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { AppRole } from "@/types/next-auth";

const ROLE_OPTIONS: AppRole[] = ["admin", "developer", "viewer"];

const schema = z.object({
  email: z.string().email("validation.emailRequired"),
  password: z
    .string()
    .min(12, "validation.passwordMin12")
    .max(128, "validation.passwordMax128"),
  role: z.enum(["admin", "developer", "viewer"]),
});
type FormData = z.infer<typeof schema>;

export function InviteUserDialog() {
  const t = useTranslations("members");
  const [open, setOpen] = useState(false);
  const { mutateAsync, isPending } = useCreateUser();

  const form = useForm<FormData>({
    resolver: zodResolver(schema),
    defaultValues: { email: "", password: "", role: "developer" },
  });

  function handleOpenChange(next: boolean) {
    if (!next) form.reset();
    setOpen(next);
  }

  async function onSubmit(values: FormData) {
    try {
      await mutateAsync(values);
      toast.success(t("invited", { email: values.email }));
      handleOpenChange(false);
    } catch (e) {
      // A gateway message is already localised server-side; only the
      // fallback is ours.
      const message = e instanceof Error ? e.message : t("inviteFailed");
      toast.error(message);
    }
  }

  return (
    <Dialog.Root open={open} onOpenChange={handleOpenChange}>
      <Dialog.Trigger asChild>
        <Button size="sm">{t("invite")}</Button>
      </Dialog.Trigger>

      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/40 z-40" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-lg bg-background border shadow-lg p-6 space-y-4">
          <Dialog.Title className="text-lg font-semibold">
            {t("inviteTitle")}
          </Dialog.Title>
          <Dialog.Description className="text-sm text-muted-foreground">
            {t("inviteDescription")}
          </Dialog.Description>

          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="invite-email">{t("email")}</Label>
              <Input
                id="invite-email"
                type="email"
                placeholder={t("emailPlaceholder")}
                autoComplete="off"
                {...form.register("email")}
              />
              {form.formState.errors.email && (
                <p className="text-xs text-destructive">
                  {form.formState.errors.email.message}
                </p>
              )}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="invite-password">{t("temporaryPassword")}</Label>
              <Input
                id="invite-password"
                type="password"
                autoComplete="new-password"
                {...form.register("password")}
              />
              {form.formState.errors.password && (
                <p className="text-xs text-destructive">
                  {form.formState.errors.password.message}
                </p>
              )}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="invite-role">{t("role")}</Label>
              <select
                id="invite-role"
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm shadow-sm focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-1"
                {...form.register("role")}
              >
                {ROLE_OPTIONS.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
              <p className="text-xs text-muted-foreground">
                {t("ownerRoleHint")}
              </p>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <Dialog.Close asChild>
                <Button variant="outline" size="sm" type="button">
                  {t("cancel")}
                </Button>
              </Dialog.Close>
              <Button size="sm" type="submit" disabled={isPending}>
                {isPending ? t("inviting") : t("sendInvite")}
              </Button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
