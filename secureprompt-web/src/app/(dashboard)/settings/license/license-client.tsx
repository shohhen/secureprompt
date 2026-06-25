"use client";

/**
 * Settings → License — client panel.
 *
 * Displays current license status and lets admins activate a new token
 * (PUT /v1/license) or remove a DB-stored license (DELETE /v1/license).
 */

import { useState } from "react";
import { useSession } from "next-auth/react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { canWrite } from "@/lib/roles";
import {
  useLicense,
  useActivateLicense,
  useRemoveLicense,
  type LicenseStatusValue,
  type LicenseSource,
} from "@/lib/hooks/use-license";
import { ApiError } from "@/lib/api-fetch";

// ── Status badge ──────────────────────────────────────────────────────────────

function statusVariant(
  status: LicenseStatusValue,
): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "Valid":
      return "default";
    case "Grace":
      return "secondary";
    case "Revoked":
      return "destructive";
    default:
      return "outline";
  }
}

function sourceLabel(source: LicenseSource): string {
  switch (source) {
    case "db":
      return "Database";
    case "env":
      return "Environment";
    default:
      return "None";
  }
}

// ── Main component ────────────────────────────────────────────────────────────

export function LicenseClient() {
  const { data: session } = useSession();
  const writable = canWrite(session?.role);

  const { data: license, isLoading, error } = useLicense();
  const activate = useActivateLicense();
  const remove = useRemoveLicense();

  const [token, setToken] = useState("");
  const [activateError, setActivateError] = useState<string | null>(null);

  const handleActivate = async () => {
    if (!token.trim()) return;
    setActivateError(null);
    try {
      await activate.mutateAsync({ token: token.trim() });
      toast.success("License activated.");
      setToken("");
    } catch (err) {
      if (err instanceof ApiError && err.status === 400) {
        setActivateError(err.message || "Invalid license signature.");
      } else {
        toast.error("Failed to activate license.");
      }
    }
  };

  const handleRemove = () => {
    if (!window.confirm("Remove the database license? The gateway will fall back to the environment token (if any).")) return;
    remove.mutate(undefined, {
      onSuccess: () => toast.success("License removed."),
      onError: () => toast.error("Failed to remove license."),
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-lg font-medium">License</h2>
        <p className="text-sm text-muted-foreground">
          View your current license status and activate or remove a token.
          {!writable && (
            <span className="block mt-1 text-xs">
              Only owners and admins can activate or remove a license.
            </span>
          )}
        </p>
      </div>

      {/* Status card */}
      <div className="rounded-lg border p-5 space-y-4">
        {isLoading ? (
          <p className="text-sm text-muted-foreground">Loading license status…</p>
        ) : error ? (
          <p role="alert" className="text-sm text-destructive">
            {error instanceof ApiError && error.status === 403
              ? "You need owner or admin access to view license status."
              : "Could not load license status."}
          </p>
        ) : license ? (
          <>
            <div className="flex items-center gap-3">
              <Badge variant={statusVariant(license.status)}>{license.status}</Badge>
              <span className="text-xs text-muted-foreground">
                Source: {sourceLabel(license.source)}
              </span>
            </div>

            <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2 text-sm">
              <div>
                <dt className="text-muted-foreground">Customer</dt>
                <dd className="font-medium">
                  {license.customer_name ?? <span className="text-muted-foreground italic">—</span>}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">License ID</dt>
                <dd className="font-mono text-xs break-all">
                  {license.lic_id ?? <span className="text-muted-foreground italic">—</span>}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Expires</dt>
                <dd>
                  {license.expires_at
                    ? new Date(license.expires_at).toLocaleDateString(undefined, {
                        year: "numeric",
                        month: "long",
                        day: "numeric",
                      })
                    : <span className="text-muted-foreground italic">—</span>}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Features</dt>
                <dd>
                  {license.features.length > 0 ? (
                    <div className="flex flex-wrap gap-1 mt-1">
                      {license.features.map((f) => (
                        <Badge key={f} variant="outline" className="text-xs">
                          {f}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <span className="text-muted-foreground italic">None</span>
                  )}
                </dd>
              </div>
            </dl>

            {/* Remove button — only shown when the license is DB-sourced */}
            {writable && license.source === "db" && (
              <div className="pt-2 border-t">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={handleRemove}
                  disabled={remove.isPending}
                >
                  Remove license
                </Button>
              </div>
            )}
          </>
        ) : (
          <p className="text-sm text-muted-foreground">Could not load license status.</p>
        )}
      </div>

      {/* Activate form */}
      {writable && (
        <div className="space-y-3">
          <div>
            <label
              htmlFor="license-token"
              className="block text-sm font-medium mb-1"
            >
              Activate a new license token
            </label>
            <textarea
              id="license-token"
              className="w-full rounded-md border bg-background px-3 py-2 text-sm font-mono resize-y min-h-[80px] focus:outline-none focus:ring-2 focus:ring-ring"
              placeholder="Paste compact license token…"
              value={token}
              onChange={(e) => {
                setToken(e.target.value);
                if (activateError) setActivateError(null);
              }}
              disabled={activate.isPending}
            />
            {activateError && (
              <p role="alert" className="text-xs text-destructive mt-1">
                {activateError}
              </p>
            )}
          </div>
          <Button
            size="sm"
            onClick={handleActivate}
            disabled={activate.isPending || !token.trim()}
          >
            {activate.isPending ? "Activating…" : "Activate"}
          </Button>
        </div>
      )}
    </div>
  );
}
