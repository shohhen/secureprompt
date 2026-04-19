"use client";

/**
 * Phase 5 / Plan 05-04 — Provider create/edit form (dialog).
 */

import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { toast } from "sonner";
import * as Dialog from "@radix-ui/react-dialog";
import {
  useCreateProvider,
  useUpdateProvider,
  type ProviderResponse,
} from "@/lib/hooks/use-providers";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const PROVIDER_TYPES = ["openai", "anthropic", "google", "azure", "bedrock", "custom"];

const schema = z.object({
  name: z.string().min(1, "Name is required").max(120),
  provider_type: z.string().min(1, "Provider type is required"),
  credential: z.string().optional(),
});
type FormData = z.infer<typeof schema>;

interface ProviderFormProps {
  provider?: ProviderResponse;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function ProviderForm({ provider, open, onOpenChange }: ProviderFormProps) {
  const isEdit = Boolean(provider);
  const create = useCreateProvider();
  const update = useUpdateProvider();
  const isPending = create.isPending || update.isPending;

  const form = useForm<FormData>({
    resolver: zodResolver(schema),
    defaultValues: {
      name: provider?.name ?? "",
      provider_type: provider?.provider_type ?? "openai",
      credential: "",
    },
  });

  useEffect(() => {
    if (open) {
      form.reset({
        name: provider?.name ?? "",
        provider_type: provider?.provider_type ?? "openai",
        credential: "",
      });
    }
  }, [open, provider, form]);

  async function onSubmit(data: FormData) {
    try {
      if (isEdit && provider) {
        await update.mutateAsync({
          id: provider.id,
          name: data.name,
          provider_type: data.provider_type,
          ...(data.credential ? { credential: data.credential } : {}),
        });
        toast.success("Provider updated.");
      } else {
        await create.mutateAsync({
          name: data.name,
          provider_type: data.provider_type,
          ...(data.credential ? { credential: data.credential } : {}),
        });
        toast.success("Provider created.");
      }
      onOpenChange(false);
    } catch {
      toast.error(isEdit ? "Failed to update provider." : "Failed to create provider.");
    }
  }

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/40 z-40" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-lg bg-background border shadow-lg p-6 space-y-4">
          <Dialog.Title className="text-lg font-semibold">
            {isEdit ? "Edit Provider" : "Add Provider"}
          </Dialog.Title>

          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="prov-name">Name</Label>
              <Input
                id="prov-name"
                placeholder="e.g. OpenAI Production"
                {...form.register("name")}
              />
              {form.formState.errors.name && (
                <p className="text-xs text-destructive">
                  {form.formState.errors.name.message}
                </p>
              )}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="prov-type">Provider Type</Label>
              <select
                id="prov-type"
                {...form.register("provider_type")}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              >
                {PROVIDER_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="prov-cred">
                {isEdit ? "API Key (leave blank to keep existing)" : "API Key"}
              </Label>
              <Input
                id="prov-cred"
                type="password"
                placeholder={isEdit ? "••••••••" : "sk-..."}
                {...form.register("credential")}
              />
            </div>

            <div className="flex justify-end gap-2">
              <Dialog.Close asChild>
                <Button variant="outline" size="sm" type="button">
                  Cancel
                </Button>
              </Dialog.Close>
              <Button size="sm" type="submit" disabled={isPending}>
                {isPending ? "Saving…" : isEdit ? "Save" : "Add"}
              </Button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
