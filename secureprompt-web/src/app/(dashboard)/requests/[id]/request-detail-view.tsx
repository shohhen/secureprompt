"use client";

/**
 * Phase 5 / Plan 05-04 — Client component for request detail.
 *
 * Fetches via useRequestDetail() and renders metadata + DetectionsDrawer.
 */

import { useRequestDetail } from "@/lib/hooks/use-requests";
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
  const { data, isLoading, error } = useRequestDetail(requestId, workspaceId);

  if (isLoading) {
    return <p className="text-sm text-muted-foreground">Loading…</p>;
  }

  if (error) {
    return (
      <p className="text-sm text-destructive">
        Failed to load request detail.
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
        Back to requests
      </Link>

      {/* Metadata card */}
      <div className="rounded-md border p-4 space-y-0">
        <MetaRow label="Request ID">
          <span className="font-mono text-xs">{data.request_id}</span>
        </MetaRow>
        <MetaRow label="Time">
          {new Date(data.created_at).toLocaleString()}
        </MetaRow>
        <MetaRow label="Provider">
          <span className="font-mono">{data.provider}</span>
        </MetaRow>
        <MetaRow label="Model">
          <span className="font-mono">{data.model}</span>
        </MetaRow>
        <MetaRow label="Final Action">
          <Badge variant={actionVariant}>{data.final_action}</Badge>
        </MetaRow>
        <MetaRow label="Cost (USD)">${data.cost_usd.toFixed(6)}</MetaRow>
        {data.input_tokens != null && (
          <MetaRow label="Input Tokens">
            {data.input_tokens.toLocaleString()}
          </MetaRow>
        )}
        {data.output_tokens != null && (
          <MetaRow label="Output Tokens">
            {data.output_tokens.toLocaleString()}
          </MetaRow>
        )}
        {data.reasoning_tokens != null && (
          <MetaRow label="Reasoning Tokens">
            {data.reasoning_tokens.toLocaleString()}
          </MetaRow>
        )}
        {data.cache_read_tokens != null && (
          <MetaRow label="Cache Read">
            {data.cache_read_tokens.toLocaleString()}
          </MetaRow>
        )}
        {data.cache_write_tokens != null && (
          <MetaRow label="Cache Write">
            {data.cache_write_tokens.toLocaleString()}
          </MetaRow>
        )}
      </div>

      {/* Policy events / detections */}
      <DetectionsDrawer events={data.policy_events} />
    </div>
  );
}
