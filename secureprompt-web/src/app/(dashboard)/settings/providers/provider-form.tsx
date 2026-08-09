"use client";

/**
 * Phase 5 / Plan 05-04 — Provider create/edit form (dialog).
 */

import { useEffect, useMemo, useState } from "react";
import { useTranslations } from "next-intl";
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


// Provider types whose endpoint has no single global address, so the gateway
// cannot carry a default for them. `bedrock`'s host embeds an AWS region;
// `azure` and `custom` are site-specific by definition. Choosing one of these
// in the dialog without supplying an address is what produced
// "no default base_url for provider_type=bedrock; supply one explicitly".
const TYPES_NEEDING_BASE_URL = ["azure", "custom"];

// Bedrock is asked for a REGION rather than a URL: it is the only part that
// varies, an operator knows it, and deriving the URL here means the console
// never sends an arbitrary address for the gateway to dial.
//
// `bedrock-mantle`, NOT `bedrock-runtime`. Bedrock exposes two surfaces and
// only one of them is fully OpenAI-shaped. Measured against eu-north-1 with a
// dummy bearer token, where 401 proves the route exists and 404 proves it does
// not:
//
//   bedrock-runtime/openai/v1/models            404 <UnknownOperationException/>
//   bedrock-runtime/v1/models                   404 <UnknownOperationException/>
//   bedrock-runtime/openai/v1/chat/completions  400 (route exists)
//   bedrock-mantle/v1/models                    401 invalid_api_key
//   bedrock-mantle/v1/chat/completions          401 invalid_api_key
//
// bedrock-runtime can complete a chat but cannot list models the OpenAI way —
// it uses the AWS-native ListFoundationModels instead. Both the credential
// probe and model sync call `GET {base}/chat../models`, so runtime would have
// left "Test connection" and "Sync" permanently broken while completions
// worked. mantle serves both from one base.
function bedrockBaseUrl(region: string): string {
  return `https://bedrock-mantle.${region.trim()}.api.aws/v1`;
}

const PROVIDER_TYPES = ["openai", "anthropic", "google", "vertex", "azure", "bedrock", "custom"];

const schema = z.object({
  name: z.string().min(1, "validation.nameRequired").max(120),
  provider_type: z.string().min(1, "validation.providerTypeRequired"),
  credential: z.string().optional(),
  region: z.string().optional(),
  project: z.string().optional(),
  base_url: z.string().optional(),
});
type FormData = z.infer<typeof schema>;

interface ProviderFormProps {
  provider?: ProviderResponse;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function ProviderForm({ provider, open, onOpenChange }: ProviderFormProps) {
  const t = useTranslations("providers");
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
      base_url:
        (provider?.config as { base_url?: string } | undefined)?.base_url ?? "",
    },
  });

  const providerType = form.watch("provider_type");
  const isVertex = providerType === "vertex";
  const isBedrock = providerType === "bedrock";
  const needsBaseUrl = TYPES_NEEDING_BASE_URL.includes(providerType);

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
        base_url:
          (provider?.config as { base_url?: string } | undefined)?.base_url ?? "",
      });
      setTestResult(null);
    }
  }, [open, provider, form]);

  async function handleTestConnection() {
    const credential = form.getValues("credential");
    const provider_type = form.getValues("provider_type");
    if (provider_type !== "vertex" && (!credential || credential.trim().length === 0)) {
      // WS6-4: `model_count` is required-and-nullable now that the spec says
      // what the handler actually sends (`Option<u32>` with no
      // skip_serializing_if is always emitted, as null). A locally-built
      // failure result has to say so rather than omit the key.
      setTestResult({
        success: false,
        model_count: null,
        error: "Enter an API key first.",
      });
      return;
    }
    const config = buildConfig(provider_type, {
      region: form.getValues("region"),
      project: form.getValues("project"),
      base_url: form.getValues("base_url"),
    });
    try {
      const baseUrl = resolveBaseUrl(provider_type, {
        region: form.getValues("region"),
        base_url: form.getValues("base_url"),
      });
      const result = await testConn.mutateAsync({
        provider_type,
        credential: credential || "",
        ...(baseUrl ? { base_url: baseUrl } : {}),
        ...(config ? { config } : {}),
      });
      setTestResult(result);
    } catch (e) {
      setTestResult({
        success: false,
        model_count: null,
        error: e instanceof Error ? e.message : "Test request failed.",
      });
    }
  }


  /**
   * Build the provider `config` for a type. Shared by "test connection" and
   * submit deliberately: when these two disagree, a provider tests green and
   * then fails in production, which is worse than failing here.
   */
  function resolveBaseUrl(
    providerType: string,
    values: { region?: string; base_url?: string },
  ): string | undefined {
    if (providerType === "bedrock") {
      const region = (values.region || "").trim();
      return region ? bedrockBaseUrl(region) : undefined;
    }
    if (TYPES_NEEDING_BASE_URL.includes(providerType)) {
      return (values.base_url || "").trim() || undefined;
    }
    return undefined;
  }

  function buildConfig(
    providerType: string,
    values: { region?: string; project?: string; base_url?: string },
  ): Record<string, string> | undefined {
    if (providerType === "vertex") {
      return {
        region: values.region || "us-central1",
        ...(values.project ? { project: values.project } : {}),
      };
    }
    const base = resolveBaseUrl(providerType, values);
    return base ? { base_url: base } : undefined;
  }

  async function onSubmit(data: FormData) {
    const config = buildConfig(data.provider_type, data);
    try {
      if (isEdit && provider) {
        await update.mutateAsync({
          id: provider.id,
          name: data.name,
          provider_type: data.provider_type,
          ...(data.credential ? { credential: data.credential } : {}),
          ...(config ? { config } : {}),
        });
        toast.success(t("updated"));
      } else {
        await create.mutateAsync({
          name: data.name,
          provider_type: data.provider_type,
          ...(data.credential ? { credential: data.credential } : {}),
          ...(config ? { config } : {}),
        });
        toast.success(t("created"));
      }
      onOpenChange(false);
    } catch {
      toast.error(isEdit ? t("updateFailed") : t("createFailed"));
    }
  }

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/40 z-40" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 max-h-[85vh] overflow-y-auto rounded-lg bg-background border shadow-lg p-6 space-y-4">
          <Dialog.Title className="text-lg font-semibold">
            {isEdit ? t("editTitle") : t("addProvider")}
          </Dialog.Title>

          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="prov-name">{t("fieldName")}</Label>
              <Input
                id="prov-name"
                placeholder={t("fieldNamePlaceholder")}
                {...form.register("name")}
              />
              {form.formState.errors.name && (
                <p className="text-xs text-destructive">
                  {form.formState.errors.name.message}
                </p>
              )}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="prov-type">{t("fieldType")}</Label>
              <select
                id="prov-type"
                {...form.register("provider_type")}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              >
                {PROVIDER_TYPES.map((pt) => (
                  <option key={pt} value={pt}>
                    {pt}
                  </option>
                ))}
              </select>
            </div>

            {isVertex && (
              <>
                <div className="space-y-1.5">
                  <Label htmlFor="prov-region">{t("fieldRegion")}</Label>
                  {/* i18n-exempt: a GCP region identifier, identical in every locale */}
                  <Input id="prov-region" placeholder="us-central1" {...form.register("region")} />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="prov-project">{t("fieldProject")}</Label>
                  <Input
                    id="prov-project"
                    placeholder={t("fieldProjectPlaceholder")}
                    {...form.register("project")}
                  />
                </div>
              </>
            )}

            {isBedrock && (
              <div className="space-y-1.5">
                <Label htmlFor="prov-bedrock-region">{t("fieldBedrockRegion")}</Label>
                {/* i18n-exempt: an AWS region identifier, identical in every locale */}
                <Input id="prov-bedrock-region" placeholder="eu-north-1" {...form.register("region")} />
                <p className="text-xs text-muted-foreground">{t("fieldBedrockRegionHint")}</p>
              </div>
            )}

            {needsBaseUrl && (
              <div className="space-y-1.5">
                <Label htmlFor="prov-base-url">{t("fieldBaseUrl")}</Label>
                {/* i18n-exempt: a URL example, identical in every locale */}
                <Input id="prov-base-url" placeholder="https://example.internal/v1" {...form.register("base_url")} />
                <p className="text-xs text-muted-foreground">{t("fieldBaseUrlHint")}</p>
              </div>
            )}

            <div className="space-y-1.5">
              <Label htmlFor="prov-cred">
                {isVertex
                  ? t("fieldServiceAccountJson")
                  : isEdit
                    ? t("fieldApiKeyExisting")
                    : t("fieldApiKey")}
              </Label>
              {isVertex ? (
                <textarea
                  id="prov-cred"
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm font-mono min-h-[120px]"
                  placeholder={t("fieldServiceAccountPlaceholder")}
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
                  {t("adcHint")}
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
                  {testConn.isPending ? t("testing") : t("testConnection")}
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
                      ? t("testSucceeded", { count: testResult.model_count ?? 0 })
                      : t("testFailed", {
                          reason: testResult.error ?? t("connectionFailed"),
                        })}
                  </span>
                )}
              </div>
            </div>

            {isEdit && provider && <ModelsPanel providerId={provider.id} />}

            <div className="flex justify-end gap-2">
              <Dialog.Close asChild>
                <Button variant="outline" size="sm" type="button">
                  {t("cancel")}
                </Button>
              </Dialog.Close>
              <Button size="sm" type="submit" disabled={isPending}>
                {isPending ? t("saving") : isEdit ? t("save") : t("add")}
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
  const t = useTranslations("providerModels");
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
      toast.success(t("added", { name: trimmed }));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t("addFailed"));
    }
  }

  async function handleBulkDelete() {
    if (selectedNames.length === 0) return;
    try {
      const { deleted } = await bulkDelete.mutateAsync(selectedNames);
      setSelected(new Set());
      toast.success(t("removedCount", { count: deleted }));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t("deleteFailed"));
    }
  }

  async function handleSync() {
    try {
      const diff = await sync.mutateAsync();
      if (diff.added.length === 0) {
        toast.success(t("alreadyInSync", { count: diff.kept.length }));
      } else {
        toast.success(
          t("synced", { count: diff.added.length, total: diff.total }),
        );
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t("syncFailed"));
    }
  }

  return (
    <div className="space-y-2 border-t pt-4">
      <div className="flex items-center justify-between gap-2">
        <Label className="text-sm font-medium">{t("title")}</Label>
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={handleSync}
          disabled={sync.isPending}
        >
          {sync.isPending ? t("syncing") : t("syncFromUpstream")}
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">
        {t("description")}
      </p>
      {isLoading ? (
        <p className="text-xs text-muted-foreground">{t("loading")}</p>
      ) : models.length === 0 ? (
        <p className="text-xs text-muted-foreground italic">
          {t("empty")}
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
                aria-label={t("selectAllAria")}
              />
              {selectedCount > 0
                ? t("selectedCount", { count: selectedCount })
                : t("selectAllCount", { count: models.length })}
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
                  ? t("deleting")
                  : t("deleteSelected", { count: selectedCount })}
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
                    aria-label={t("selectAria", { name: m.name })}
                  />
                  <span className="truncate font-mono">{m.name}</span>
                </label>
                <button
                  type="button"
                  onClick={() =>
                    remove.mutate(m.name, {
                      onSuccess: () => toast.success(t("removed", { name: m.name })),
                      onError: (e) => toast.error(e.message),
                    })
                  }
                  className="shrink-0 text-destructive hover:underline"
                  disabled={remove.isPending}
                >
                  {t("remove")}
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
          placeholder={t("addPlaceholder")}
          className="text-xs"
        />
        <Button
          type="submit"
          size="sm"
          variant="outline"
          disabled={add.isPending || !name.trim()}
        >
          {add.isPending ? t("adding") : t("add")}
        </Button>
      </form>
    </div>
  );
}
