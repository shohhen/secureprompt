"use client";

/**
 * Phase 5 / Plan 05-04 — Client component for request detail.
 *
 * Fetches via useRequestDetail() and renders metadata + DetectionsDrawer.
 */

import { useRequestDetail } from "@/lib/hooks/use-requests";
import { useTranslations } from "next-intl";
import { DetectionsDrawer } from "./detections-drawer";
import { Badge } from "@/components/ui/badge";
import Link from "next/link";

interface RequestDetailViewProps {
  requestId: string;
  workspaceId: string;
}

function MetaRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-4 py-2 border-b last:border-0">
      <span className="w-36 shrink-0 text-xs text-muted-foreground font-medium">
        {label}
      </span>
      <span className="text-sm">{children}</span>
    </div>
  );
}

export function RequestDetailView({
  requestId,
  workspaceId,
}: RequestDetailViewProps) {
  const t = useTranslations("requestDetail");
  const { data, isLoading, error } = useRequestDetail(requestId, workspaceId);

  if (isLoading) {
    return <p className="text-sm text-muted-foreground">{t("loading")}</p>;
  }

  if (error) {
    return (
      <p className="text-sm text-destructive">
        {t("loadFailed")}
      </p>
    );
  }

  if (!data) return null;

  const actionVariant =
    data.final_action === "allow"
      ? "secondary"
      : data.final_action === "deny"
        ? "destructive"
        : "outline";

  return (
    <div className="space-y-6">
      {/* Back link */}
      <Link
        href="/requests"
        className="text-xs text-primary hover:underline underline-offset-2"
      >
        {t("backToRequests")}
      </Link>

      {/* Metadata card */}
      <div className="rounded-md border p-4 space-y-0">
        <MetaRow label={t("fieldRequestId")}>
          <span className="font-mono text-xs">{data.request_id}</span>
        </MetaRow>
        <MetaRow label={t("fieldTime")}>
          {new Date(data.created_at).toLocaleString()}
        </MetaRow>
        <MetaRow label={t("fieldProvider")}>
          <span className="font-mono">{data.provider}</span>
        </MetaRow>
        <MetaRow label={t("fieldModel")}>
          <span className="font-mono">{data.model}</span>
        </MetaRow>
        <MetaRow label={t("fieldFinalAction")}>
          <Badge variant={actionVariant}>{data.final_action}</Badge>
        </MetaRow>
        <MetaRow label={t("fieldCost")}>${data.cost_usd.toFixed(6)}</MetaRow>
        {data.input_tokens != null && (
          <MetaRow label={t("fieldInputTokens")}>
            {data.input_tokens.toLocaleString()}
          </MetaRow>
        )}
        {data.output_tokens != null && (
          <MetaRow label={t("fieldOutputTokens")}>
            {data.output_tokens.toLocaleString()}
          </MetaRow>
        )}
        {data.reasoning_tokens != null && (
          <MetaRow label={t("fieldReasoningTokens")}>
            {data.reasoning_tokens.toLocaleString()}
          </MetaRow>
        )}
        {data.cache_read_tokens != null && (
          <MetaRow label={t("fieldCacheRead")}>
            {data.cache_read_tokens.toLocaleString()}
          </MetaRow>
        )}
        {data.cache_write_tokens != null && (
          <MetaRow label={t("fieldCacheWrite")}>
            {data.cache_write_tokens.toLocaleString()}
          </MetaRow>
        )}
      </div>

      {/* Policy events / detections */}
      <DetectionsDrawer events={data.policy_events} />
    </div>
  );
}
