"use client";

/**
 * Phase 5 / Plan 05-04 — Provider create/edit form (dialog).
 */

import { useEffect, useMemo, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { toast } from "sonner";
import * as Dialog from "@radix-ui/react-dialog";
import {
  useAddProviderModel,
  useBulkDeleteProviderModels,
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

const PROVIDER_TYPES = ["openai", "anthropic", "google", "vertex", "azure", "bedrock", "custom"];

const schema = z.object({
  name: z.string().min(1, "Name is required").max(120),
  provider_type: z.string().min(1, "Provider type is required"),
  credential: z.string().optional(),
  region: z.string().optional(),
  project: z.string().optional(),
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
      region:
        (provider?.config as { region?: string; project?: string } | undefined)?.region ??
        "us-central1",
      project:
        (provider?.config as { region?: string; project?: string } | undefined)?.project ?? "",
    },
  });

  const providerType = form.watch("provider_type");
  const isVertex = providerType === "vertex";

  useEffect(() => {
    if (open) {
      form.reset({
        name: provider?.name ?? "",
        provider_type: provider?.provider_type ?? "openai",
        credential: "",
        region:
          (provider?.config as { region?: string; project?: string } | undefined)?.region ??
          "us-central1",
        project:
          (provider?.config as { region?: string; project?: string } | undefined)?.project ?? "",
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
    const config =
      provider_type === "vertex"
        ? {
            region: form.getValues("region") || "us-central1",
            project: form.getValues("project") || undefined,
          }
        : undefined;
    try {
      const result = await testConn.mutateAsync({
        provider_type,
        credential,
        ...(config ? { config } : {}),
      });
      setTestResult(result);
    } catch (e) {
      setTestResult({
        success: false,
        error: e instanceof Error ? e.message : "Test request failed.",
      });
    }
  }

  async function onSubmit(data: FormData) {
    const config =
      data.provider_type === "vertex"
        ? { region: data.region || "us-central1", ...(data.project ? { project: data.project } : {}) }
        : undefined;
    try {
      if (isEdit && provider) {
        await update.mutateAsync({
          id: provider.id,
          name: data.name,
          provider_type: data.provider_type,
          ...(data.credential ? { credential: data.credential } : {}),
          ...(config ? { config } : {}),
        });
        toast.success("Provider updated.");
      } else {
        await create.mutateAsync({
          name: data.name,
          provider_type: data.provider_type,
          ...(data.credential ? { credential: data.credential } : {}),
          ...(config ? { config } : {}),
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
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 max-h-[85vh] overflow-y-auto rounded-lg bg-background border shadow-lg p-6 space-y-4">
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

            {isVertex && (
              <>
                <div className="space-y-1.5">
                  <Label htmlFor="prov-region">Region</Label>
                  <Input id="prov-region" placeholder="us-central1" {...form.register("region")} />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="prov-project">Project (optional)</Label>
                  <Input
                    id="prov-project"
                    placeholder="leave blank to use the SA key's project"
                    {...form.register("project")}
                  />
                </div>
              </>
            )}

            <div className="space-y-1.5">
              <Label htmlFor="prov-cred">
                {isVertex
                  ? "Service Account JSON"
                  : isEdit
                    ? "API Key (leave blank to keep existing)"
                    : "API Key"}
              </Label>
              {isVertex ? (
                <textarea
                  id="prov-cred"
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm font-mono min-h-[120px]"
                  placeholder={'{ "type": "service_account", ... }  — optional (ADC if blank)'}
                  {...form.register("credential")}
                  onChange={(e) => {
                    form.setValue("credential", e.target.value);
                    setTestResult(null);
                  }}
                />
              ) : (
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
              )}
              {isVertex && (
                <p className="text-xs text-muted-foreground">
                  Optional — uses Workload Identity / ADC if blank
                </p>
              )}
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
  const bulkDelete = useBulkDeleteProviderModels(providerId);
  const [name, setName] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());

  // `selected` may retain names that were just deleted; intersect with the
  // current models at read time (derived) rather than syncing state in an
  // effect, so stale selections never drive a delete or a wrong count.
  const modelNames = useMemo(() => new Set(models.map((m) => m.name)), [models]);
  const selectedNames = useMemo(
    () => [...selected].filter((n) => modelNames.has(n)),
    [selected, modelNames],
  );
  const selectedCount = selectedNames.length;
  const allSelected = models.length > 0 && selectedCount === models.length;

  function toggleOne(modelName: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(modelName)) {
        next.delete(modelName);
      } else {
        next.add(modelName);
      }
      return next;
    });
  }

  function toggleAll() {
    setSelected(allSelected ? new Set() : new Set(modelNames));
  }

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

  async function handleBulkDelete() {
    if (selectedNames.length === 0) return;
    try {
      const { deleted } = await bulkDelete.mutateAsync(selectedNames);
      setSelected(new Set());
      toast.success(`Removed ${deleted} model${deleted === 1 ? "" : "s"}`);
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Failed to delete models.",
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
        Auto-fetched from the provider&apos;s API key on save. Removed models
        stay removed across syncs. Add one back manually below, or click Sync
        to pull newly-released upstream models.
      </p>
      {isLoading ? (
        <p className="text-xs text-muted-foreground">Loading…</p>
      ) : models.length === 0 ? (
        <p className="text-xs text-muted-foreground italic">
          No models registered yet.
        </p>
      ) : (
        <>
          <div className="flex items-center justify-between gap-2 px-1">
            <label className="flex items-center gap-2 text-xs text-muted-foreground">
              <input
                type="checkbox"
                checked={allSelected}
                ref={(el) => {
                  if (el)
                    el.indeterminate =
                      selectedCount > 0 && selectedCount < models.length;
                }}
                onChange={toggleAll}
                aria-label="Select all models"
              />
              {selectedCount > 0
                ? `${selectedCount} selected`
                : `Select all (${models.length})`}
            </label>
            {selectedCount > 0 && (
              <Button
                type="button"
                size="sm"
                variant="destructive"
                onClick={handleBulkDelete}
                disabled={bulkDelete.isPending}
              >
                {bulkDelete.isPending
                  ? "Deleting…"
                  : `Delete selected (${selectedCount})`}
              </Button>
            )}
          </div>
          <ul className="max-h-64 space-y-1 overflow-y-auto pr-1">
            {models.map((m) => (
              <li
                key={m.id}
                className="flex items-center justify-between gap-2 rounded border px-2 py-1 text-xs"
              >
                <label className="flex min-w-0 flex-1 items-center gap-2">
                  <input
                    type="checkbox"
                    checked={selected.has(m.name)}
                    onChange={() => toggleOne(m.name)}
                    aria-label={`Select ${m.name}`}
                  />
                  <span className="truncate font-mono">{m.name}</span>
                </label>
                <button
                  type="button"
                  onClick={() =>
                    remove.mutate(m.name, {
                      onSuccess: () => toast.success(`Removed ${m.name}`),
                      onError: (e) => toast.error(e.message),
                    })
                  }
                  className="shrink-0 text-destructive hover:underline"
                  disabled={remove.isPending}
                >
                  Remove
                </button>
              </li>
            ))}
          </ul>
        </>
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
