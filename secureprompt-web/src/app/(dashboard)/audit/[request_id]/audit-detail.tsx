"use client";

/**
 * Audit detail — full record for a single gateway request.
 *
 * Renders the actor (user + API key), transport (IP + User-Agent), the
 * placeholder-safe prompt body, and any policy violations triggered for
 * this request. Reached by clicking a row on /audit.
 */

import Link from "next/link";
import { useRequestDetail } from "@/lib/hooks/use-requests";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

interface Props {
  requestId: string;
  workspaceId: string;
}

const ACTION_VARIANT: Record<
  string,
  "default" | "secondary" | "destructive" | "outline"
> = {
  allow: "secondary",
  redact: "outline",
  block: "destructive",
  deny: "destructive",
};

export function AuditDetail({ requestId, workspaceId }: Props) {
  const { data, isLoading, error } = useRequestDetail(requestId, workspaceId);

  if (isLoading) {
    return (
      <p className="text-sm text-muted-foreground">Loading request detail…</p>
    );
  }

  if (error || !data) {
    return (
      <div className="space-y-4">
        <BackLink />
        <p className="text-sm text-destructive">
          Failed to load request detail. The request may have been purged
          (90-day TTL) or the ID is invalid.
        </p>
      </div>
    );
  }

  const created = new Date(data.created_at);
  const device = parseUserAgent(data.user_agent);

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <BackLink />
          <h1 className="mt-2 text-2xl font-semibold">Request Detail</h1>
          <p className="text-xs font-mono text-muted-foreground mt-1 break-all">
            {data.request_id}
          </p>
        </div>
        <Badge
          variant={ACTION_VARIANT[data.final_action.toLowerCase()] ?? "outline"}
          className="shrink-0"
        >
          {data.final_action}
        </Badge>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Who</CardTitle>
            <CardDescription>Workspace member that issued this request.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <Field
              label="Name"
              value={
                [data.user_first_name, data.user_last_name]
                  .filter(Boolean)
                  .join(" ") || "—"
              }
            />
            <Field label="Position" value={data.user_position ?? "—"} />
            <Field label="Email" value={data.user_email ?? "—"} />
            <Field
              label="User ID"
              value={data.user_id ?? "—"}
              mono
            />
            <Field
              label="API key"
              value={data.api_key_name ?? "—"}
            />
            <Field
              label="API key ID"
              value={data.api_key_id ?? "—"}
              mono
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">From</CardTitle>
            <CardDescription>Transport — source, IP, device that sent it.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <Field label="Source" value={data.source ?? "Unknown"} />
            <Field
              label="IP address"
              value={data.ip_address ?? "unknown"}
              mono
            />
            <Field label="Device" value={device} />
            <Field
              label="MAC (self-reported, desktop)"
              value={data.user_device_mac ?? "—"}
              mono
            />
            <Field
              label="User-Agent"
              value={data.user_agent ?? "—"}
              mono
              wrap
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">When</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <Field label="Local time" value={created.toLocaleString()} />
            <Field
              label="UTC"
              value={created.toISOString()}
              mono
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Routing & cost</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <Field label="Provider" value={data.provider} mono />
            <Field label="Model" value={data.model} mono />
            <div className="grid grid-cols-3 gap-3 pt-1">
              <Stat label="Input" value={data.input_tokens ?? "—"} />
              <Stat label="Output" value={data.output_tokens ?? "—"} />
              <Stat
                label="Cost"
                value={`$${data.cost_usd.toFixed(4)}`}
              />
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Policy violations</CardTitle>
          <CardDescription>
            Rules that fired against this request. Empty when no policy
            triggered.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {data.policy_events.length === 0 ? (
            <p className="text-sm text-muted-foreground italic">
              No policy violations recorded.
            </p>
          ) : (
            <ul className="space-y-2">
              {data.policy_events.map((pe) => (
                <li
                  key={pe.rule_id}
                  className="flex items-center justify-between rounded border px-3 py-2 text-sm"
                >
                  <div>
                    <p className="font-medium">{pe.rule_name}</p>
                    <p className="text-xs font-mono text-muted-foreground">
                      {pe.rule_id}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    {pe.dry_run && (
                      <Badge variant="outline" className="text-xs">
                        dry-run
                      </Badge>
                    )}
                    <Badge
                      variant={
                        ACTION_VARIANT[pe.action.toLowerCase()] ?? "outline"
                      }
                    >
                      {pe.action}
                    </Badge>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">User message</CardTitle>
          <CardDescription>
            What the user typed (raw) and what the gateway forwarded
            upstream (redacted). Only the latest turn — prior conversation
            history is intentionally excluded.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-2">
          <MessagePanel
            label="Raw"
            badgeVariant="destructive"
            description="As typed — PII intact."
            content={data.raw_prompt}
            emptyMessage="No raw user message captured."
          />
          <MessagePanel
            label="Redacted"
            badgeVariant="secondary"
            description="Forwarded upstream — PII replaced with {{Class_N}} placeholders."
            content={data.redacted_prompt}
            emptyMessage="No redacted output (request didn't reach redaction)."
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">AI response</CardTitle>
          <CardDescription>
            What the upstream model emitted (raw, placeholders intact)
            and what the client received (after placeholder restoration).
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-2">
          <MessagePanel
            label="Raw"
            badgeVariant="outline"
            description="Direct from the upstream model — placeholders not yet restored."
            content={data.raw_response}
            emptyMessage="No upstream response (denied, embedding-only, or pre-migration row)."
          />
          <MessagePanel
            label="Restored"
            badgeVariant="secondary"
            description="What the client saw — placeholders mapped back to original PII."
            content={data.restored_response}
            emptyMessage="No restored response."
          />
        </CardContent>
      </Card>
    </div>
  );
}

function MessagePanel({
  label,
  badgeVariant,
  description,
  content,
  emptyMessage,
}: {
  label: string;
  badgeVariant: "default" | "secondary" | "destructive" | "outline";
  description: string;
  content: string | null;
  emptyMessage: string;
}) {
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <Badge variant={badgeVariant}>{label}</Badge>
        <p className="text-xs text-muted-foreground">{description}</p>
      </div>
      {content ? (
        <pre className="whitespace-pre-wrap break-words rounded-md border bg-muted/30 p-3 text-xs font-mono max-h-72 overflow-auto">
          {content}
        </pre>
      ) : (
        <p className="text-sm text-muted-foreground italic pl-1">
          {emptyMessage}
        </p>
      )}
    </div>
  );
}

function BackLink() {
  return (
    <Link
      href="/audit"
      className="text-xs text-muted-foreground hover:underline"
    >
      ← Back to audit log
    </Link>
  );
}

function Field({
  label,
  value,
  mono = false,
  wrap = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
  wrap?: boolean;
}) {
  return (
    <div>
      <p className="text-xs uppercase tracking-wide text-muted-foreground">
        {label}
      </p>
      <p
        className={[
          "mt-0.5",
          mono ? "font-mono text-xs" : "",
          wrap ? "break-words" : "truncate",
        ]
          .filter(Boolean)
          .join(" ")}
      >
        {value}
      </p>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <p className="text-xs uppercase tracking-wide text-muted-foreground">
        {label}
      </p>
      <p className="mt-0.5 font-medium">{value}</p>
    </div>
  );
}

/**
 * Lightweight User-Agent parser — resolves the common "browser on OS"
 * shape for display next to the raw header. We deliberately avoid pulling
 * in a heavy ua-parser dep for what is a single label in the UI.
 */
function parseUserAgent(ua: string | null | undefined): string {
  if (!ua) return "unknown";

  // LibreChat / Electron desktop client
  if (/Electron/i.test(ua)) return "LibreChat (Electron desktop)";
  if (/LibreChat/i.test(ua)) return "LibreChat";

  // Common browser signatures
  let browser = "Unknown browser";
  if (/Edg\//i.test(ua)) browser = "Edge";
  else if (/OPR\//i.test(ua) || /Opera/i.test(ua)) browser = "Opera";
  else if (/Firefox\//i.test(ua)) browser = "Firefox";
  else if (/Chrome\//i.test(ua)) browser = "Chrome";
  else if (/Safari\//i.test(ua)) browser = "Safari";

  let os = "";
  if (/Windows/i.test(ua)) os = "Windows";
  else if (/Mac OS X|Macintosh/i.test(ua)) os = "macOS";
  else if (/Android/i.test(ua)) os = "Android";
  else if (/iPhone|iPad|iOS/i.test(ua)) os = "iOS";
  else if (/Linux/i.test(ua)) os = "Linux";

  // CLI tooling — common in API integrations
  if (/curl\//i.test(ua)) return `curl (${ua.match(/curl\/[\d.]+/i)?.[0] ?? ""})`;
  if (/python-requests/i.test(ua)) return "python-requests";
  if (/openai-python/i.test(ua)) return "openai-python";
  if (/node-fetch|axios|got/i.test(ua)) return browser === "Unknown browser" ? "Node.js client" : browser;

  return os ? `${browser} on ${os}` : browser;
}
