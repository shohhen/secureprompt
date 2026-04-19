"use client";

/**
 * Phase 5 / Plan 05-04 — Create API key dialog.
 *
 * On success, shows the one-time key value in a read-only input.
 * The key is never stored in state beyond dialog lifetime — closing
 * the dialog clears it.
 */

import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { toast } from "sonner";
import * as Dialog from "@radix-ui/react-dialog";
import { useCreateKey } from "@/lib/hooks/use-keys";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const schema = z.object({
  name: z.string().min(1, "Name is required").max(120),
});
type FormData = z.infer<typeof schema>;

interface CreateKeyDialogProps {
  onCreated?: () => void;
}

export function CreateKeyDialog({ onCreated }: CreateKeyDialogProps) {
  const [open, setOpen] = useState(false);
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const { mutateAsync, isPending } = useCreateKey();

  const form = useForm<FormData>({
    resolver: zodResolver(schema),
    defaultValues: { name: "" },
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
      const result = await mutateAsync({ name: data.name });
      setCreatedKey(result.api_key);
      onCreated?.();
    } catch {
      toast.error("Failed to create API key.");
    }
  }

  return (
    <Dialog.Root open={open} onOpenChange={handleOpenChange}>
      <Dialog.Trigger asChild>
        <Button size="sm">Create Key</Button>
      </Dialog.Trigger>

      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/40 z-40" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-lg bg-background border shadow-lg p-6 space-y-4">
          <Dialog.Title className="text-lg font-semibold">
            {createdKey ? "Key Created" : "Create API Key"}
          </Dialog.Title>

          {createdKey ? (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Copy this key now — it will not be shown again.
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
                    toast.success("Copied to clipboard.");
                  }}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-xs text-primary hover:underline"
                >
                  Copy
                </button>
              </div>
              <div className="flex justify-end">
                <Dialog.Close asChild>
                  <Button variant="outline" size="sm">
                    Done
                  </Button>
                </Dialog.Close>
              </div>
            </div>
          ) : (
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="key-name">Key Name</Label>
                <Input
                  id="key-name"
                  placeholder="e.g. production-backend"
                  {...form.register("name")}
                />
                {form.formState.errors.name && (
                  <p className="text-xs text-destructive">
                    {form.formState.errors.name.message}
                  </p>
                )}
              </div>

              <div className="flex justify-end gap-2">
                <Dialog.Close asChild>
                  <Button variant="outline" size="sm" type="button">
                    Cancel
                  </Button>
                </Dialog.Close>
                <Button size="sm" type="submit" disabled={isPending}>
                  {isPending ? "Creating…" : "Create"}
                </Button>
              </div>
            </form>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
