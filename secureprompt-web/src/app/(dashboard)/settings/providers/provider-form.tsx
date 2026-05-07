"use client";

/**
 * Phase 5 / Plan 05-04 — Provider create/edit form (dialog).
 */

import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { toast } from "sonner";
import * as Dialog from "@radix-ui/react-dialog";
import {
  useAddProviderModel,
  useCreateProvider,
  useDeleteProviderModel,
  useProviderModels,
  useSyncProviderModels,
  useTestProviderConnection,
  useUpdateProvider,
  type ProviderResponse,
  type TestConnectionResult,
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
  const testConn = useTestProviderConnection();
  const [testResult, setTestResult] = useState<TestConnectionResult | null>(null);
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
      setTestResult(null);
    }
  }, [open, provider, form]);

  async function handleTestConnection() {
    const credential = form.getValues("credential");
    const provider_type = form.getValues("provider_type");
    if (!credential || credential.trim().length === 0) {
      setTestResult({ success: false, error: "Enter an API key first." });
      return;
    }
    try {
      const result = await testConn.mutateAsync({ provider_type, credential });
      setTestResult(result);
    } catch (e) {
      setTestResult({
        success: false,
        error: e instanceof Error ? e.message : "Test request failed.",
      });
    }
  }

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
                onChange={(e) => {
                  // Reset test status when the user edits the key — the
                  // previous result no longer reflects what's typed.
                  form.setValue("credential", e.target.value);
                  setTestResult(null);
                }}
              />
              <div className="flex items-center gap-2 pt-1">
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={handleTestConnection}
                  disabled={testConn.isPending}
                >
                  {testConn.isPending ? "Testing…" : "Test Connection"}
                </Button>
                {testResult && (
                  <span
                    className={
                      testResult.success
                        ? "text-xs text-green-600 dark:text-green-400"
                        : "text-xs text-destructive"
                    }
                  >
                    {testResult.success
                      ? `✓ Connected (${testResult.model_count ?? 0} models)`
                      : `✗ ${testResult.error ?? "Connection failed"}`}
                  </span>
                )}
              </div>
            </div>

            {isEdit && provider && <ModelsPanel providerId={provider.id} />}

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

/**
 * Per-provider model registry panel rendered inside the edit dialog. Lets
 * the admin add / remove the model strings the workspace allows for this
 * provider. The list is the source of truth for LibreChat's discovery
 * client (nested `models` field on `GET /v1/providers`).
 */
function ModelsPanel({ providerId }: { providerId: string }) {
  const { data: models = [], isLoading } = useProviderModels(providerId);
  const add = useAddProviderModel(providerId);
  const remove = useDeleteProviderModel(providerId);
  const sync = useSyncProviderModels(providerId);
  const [name, setName] = useState("");

  async function handleAdd(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = name.trim();
    if (!trimmed) return;
    try {
      await add.mutateAsync({ name: trimmed });
      setName("");
      toast.success(`Added ${trimmed}`);
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Failed to add model.",
      );
    }
  }

  async function handleSync() {
    try {
      const diff = await sync.mutateAsync();
      if (diff.added.length === 0) {
        toast.success(
          `Already in sync (${diff.kept.length} models tracked).`,
        );
      } else {
        toast.success(
          `Synced — added ${diff.added.length} new model${
            diff.added.length === 1 ? "" : "s"
          } (${diff.total} total).`,
        );
      }
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Failed to sync models.",
      );
    }
  }

  return (
    <div className="space-y-2 border-t pt-4">
      <div className="flex items-center justify-between gap-2">
        <Label className="text-sm font-medium">Models</Label>
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={handleSync}
          disabled={sync.isPending}
        >
          {sync.isPending ? "Syncing…" : "Sync from upstream"}
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">
        Auto-fetched from the provider&apos;s API key on save. Click Sync
        to refresh after the upstream adds new models, or add one
        manually below.
      </p>
      {isLoading ? (
        <p className="text-xs text-muted-foreground">Loading…</p>
      ) : models.length === 0 ? (
        <p className="text-xs text-muted-foreground italic">
          No models registered yet.
        </p>
      ) : (
        <ul className="space-y-1">
          {models.map((m) => (
            <li
              key={m.id}
              className="flex items-center justify-between rounded border px-2 py-1 text-xs"
            >
              <span className="font-mono">{m.name}</span>
              <button
                type="button"
                onClick={() =>
                  remove.mutate(m.name, {
                    onSuccess: () => toast.success(`Removed ${m.name}`),
                    onError: (e) => toast.error(e.message),
                  })
                }
                className="text-destructive hover:underline"
                disabled={remove.isPending}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      <form onSubmit={handleAdd} className="flex gap-2">
        <Input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Model name (e.g. gemini-2.5-flash)"
          className="text-xs"
        />
        <Button
          type="submit"
          size="sm"
          variant="outline"
          disabled={add.isPending || !name.trim()}
        >
          {add.isPending ? "Adding…" : "Add"}
        </Button>
      </form>
    </div>
  );
}
