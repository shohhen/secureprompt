"use client";

/**
 * Tokenize / detokenize playground.
 *
 * Calls POST /v1/secure-mode/tokenize to redact PII in free-form text using
 * the ML sidecar, and POST /v1/secure-mode/detokenize to reverse the
 * replacement using the returned `token_vault_id`. Vault entries expire
 * after 24 hours.
 */

import { useState } from "react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";
import { useTokenize, useDetokenize } from "@/lib/hooks/use-secure-mode";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { EntityPicker, ALL_ENTITY_VALUES } from "./entity-picker";

export function TokenizePlayground() {
  const tokenize = useTokenize();
  const detokenize = useDetokenize();

  const [input, setInput] = useState("");
  const [tokenized, setTokenized] = useState("");
  const [vaultId, setVaultId] = useState("");
  const [entityCounts, setEntityCounts] = useState<Record<string, number>>({});

  const t = useTranslations("tokenize");
  const [detokText, setDetokText] = useState("");
  const [detokVaultId, setDetokVaultId] = useState("");
  const [detokOutput, setDetokOutput] = useState("");

  const [selectedEntities, setSelectedEntities] = useState<Set<string>>(
    () => new Set(ALL_ENTITY_VALUES),
  );

  async function handleTokenize() {
    if (!input.trim()) return;
    if (selectedEntities.size === 0) {
      toast.error(t("pickAtLeastOne"));
      return;
    }
    try {
      // When the user hasn't customized the selection (all checked), send
      // undefined and let the backend apply its default universe. This way
      // future backend label additions show up without a UI change.
      const isDefault = selectedEntities.size === ALL_ENTITY_VALUES.length;
      const res = await tokenize.mutateAsync({
        text: input,
        entity_labels: isDefault ? undefined : Array.from(selectedEntities),
      });
      setTokenized(res.tokenized_text);
      setVaultId(res.token_vault_id);
      setEntityCounts(res.entity_counts);
      // Auto-fill the detokenize side so the round-trip is one click away.
      setDetokText(res.tokenized_text);
      setDetokVaultId(res.token_vault_id);
    } catch (e) {
      const message = e instanceof Error ? e.message : t("tokenizeFailed");
      toast.error(message);
    }
  }

  async function handleDetokenize() {
    if (!detokText.trim() || !detokVaultId.trim()) return;
    try {
      const res = await detokenize.mutateAsync({
        token_vault_id: detokVaultId.trim(),
        text: detokText,
      });
      setDetokOutput(res.text);
    } catch (e) {
      const message = e instanceof Error ? e.message : t("detokenizeFailed");
      toast.error(message);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-medium">{t("title")}</h2>
        <p className="text-sm text-muted-foreground">
          {t("description")}
        </p>
      </div>

      <div className="rounded-lg border p-5">
        <EntityPicker
          value={selectedEntities}
          onChange={setSelectedEntities}
          disabled={tokenize.isPending}
        />
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <div className="rounded-lg border p-5 space-y-3">
          <div className="flex items-center justify-between">
            <Label htmlFor="tokenize-input" className="font-medium">
              {t("originalText")}
            </Label>
            <Button
              size="sm"
              onClick={handleTokenize}
              disabled={
                tokenize.isPending || !input.trim() || selectedEntities.size === 0
              }
            >
              {tokenize.isPending ? t("tokenizing") : t("tokenize")}
            </Button>
          </div>
          <Textarea
            id="tokenize-input"
            rows={6}
            placeholder={t("inputPlaceholder")}
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />

          {tokenized && (
            <div className="space-y-2">
              <Label className="text-xs text-muted-foreground">
                {t("tokenizedOutput")}
              </Label>
              <pre className="rounded bg-muted p-3 text-xs whitespace-pre-wrap max-h-48 overflow-auto">
                {tokenized}
              </pre>

              <div className="flex flex-wrap gap-2">
                {Object.entries(entityCounts).map(([label, count]) => (
                  <Badge key={label} variant="secondary">
                    {label} × {count}
                  </Badge>
                ))}
                {Object.keys(entityCounts).length === 0 && (
                  <span className="text-xs text-muted-foreground">
                    {t("noPiiDetected")}
                  </span>
                )}
              </div>

              <div className="text-xs text-muted-foreground">
                <span className="font-medium">{t("vaultIdLabel")}</span>{" "}
                <span className="font-mono">{vaultId}</span>
              </div>
            </div>
          )}
        </div>

        <div className="rounded-lg border p-5 space-y-3">
          <div className="flex items-center justify-between">
            <Label className="font-medium">{t("reverse")}</Label>
            <Button
              size="sm"
              variant="outline"
              onClick={handleDetokenize}
              disabled={
                detokenize.isPending || !detokText.trim() || !detokVaultId.trim()
              }
            >
              {detokenize.isPending ? t("detokenizing") : t("detokenize")}
            </Button>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="detok-vault" className="text-xs text-muted-foreground">
              {t("vaultId")}
            </Label>
            <Input
              id="detok-vault"
              placeholder={t("vaultIdPlaceholder")}
              value={detokVaultId}
              onChange={(e) => setDetokVaultId(e.target.value)}
              className="font-mono text-xs"
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="detok-input" className="text-xs text-muted-foreground">
              {t("tokenizedText")}
            </Label>
            <Textarea
              id="detok-input"
              rows={5}
              value={detokText}
              onChange={(e) => setDetokText(e.target.value)}
            />
          </div>

          {detokOutput && (
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">{t("restored")}</Label>
              <pre className="rounded bg-muted p-3 text-xs whitespace-pre-wrap max-h-48 overflow-auto">
                {detokOutput}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
