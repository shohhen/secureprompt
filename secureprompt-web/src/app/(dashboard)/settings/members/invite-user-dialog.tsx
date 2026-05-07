"use client";

/**
 * Invite a new user to the current workspace.
 *
 * The backend's POST /v1/users creates the account with the provided password
 * (there is no email-invite flow yet), so this dialog asks the admin to set
 * a temporary password they can hand to the new member out-of-band.
 */

import { useState } from "react";
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
  email: z.string().email("Valid email required"),
  password: z
    .string()
    .min(12, "At least 12 characters")
    .max(128, "Max 128 characters"),
  role: z.enum(["admin", "developer", "viewer"]),
});
type FormData = z.infer<typeof schema>;

export function InviteUserDialog() {
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
      toast.success(`Invited ${values.email}.`);
      handleOpenChange(false);
    } catch (e) {
      const message = e instanceof Error ? e.message : "Failed to invite user.";
      toast.error(message);
    }
  }

  return (
    <Dialog.Root open={open} onOpenChange={handleOpenChange}>
      <Dialog.Trigger asChild>
        <Button size="sm">Invite member</Button>
      </Dialog.Trigger>

      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/40 z-40" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-lg bg-background border shadow-lg p-6 space-y-4">
          <Dialog.Title className="text-lg font-semibold">
            Invite workspace member
          </Dialog.Title>
          <Dialog.Description className="text-sm text-muted-foreground">
            The new account is created immediately with the password you set —
            share it with the member out-of-band and ask them to change it on
            first login.
          </Dialog.Description>

          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="invite-email">Email</Label>
              <Input
                id="invite-email"
                type="email"
                placeholder="teammate@company.com"
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
              <Label htmlFor="invite-password">Temporary password</Label>
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
              <Label htmlFor="invite-role">Role</Label>
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
                Owner role is assigned automatically at workspace creation and
                cannot be granted from this form.
              </p>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <Dialog.Close asChild>
                <Button variant="outline" size="sm" type="button">
                  Cancel
                </Button>
              </Dialog.Close>
              <Button size="sm" type="submit" disabled={isPending}>
                {isPending ? "Inviting…" : "Send invite"}
              </Button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
