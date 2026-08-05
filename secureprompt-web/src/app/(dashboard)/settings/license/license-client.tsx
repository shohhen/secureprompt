"use client";

/**
 * Settings → License — client panel.
 *
 * Displays current license status and lets admins activate a new token
 * (PUT /v1/license) or remove a DB-stored license (DELETE /v1/license).
 */

import { useState } from "react";
import { useTranslations } from "next-intl";
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

/**
 * Licence status and source are enum values from the gateway, so they are
 * rendered through the catalogue rather than printed raw — an auditor reading
 * a Russian console should not meet the word "Unlicensed".
 */
function sourceKey(source: LicenseSource): string {
  switch (source) {
    case "db":
      return "sourceDatabase";
    case "env":
      return "sourceEnvironment";
    default:
      return "sourceNone";
  }
}

// ── Main component ────────────────────────────────────────────────────────────

export function LicenseClient() {
  const t = useTranslations("license");
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
      toast.success(t("activated"));
      setToken("");
    } catch (err) {
      if (err instanceof ApiError && err.status === 400) {
        // A 400 body from the gateway names the specific signature defect;
        // only the empty case is ours to phrase.
        setActivateError(err.message || t("invalidSignature"));
      } else {
        toast.error(t("activateFailed"));
      }
    }
  };

  const handleRemove = () => {
    if (!window.confirm(t("removeConfirm"))) return;
    remove.mutate(undefined, {
      onSuccess: () => toast.success(t("removed")),
      onError: () => toast.error(t("removeFailed")),
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-lg font-medium">{t("title")}</h2>
        <p className="text-sm text-muted-foreground">
          {t("description")}
          {!writable && (
            <span className="block mt-1 text-xs">{t("readOnlyNotice")}</span>
          )}
        </p>
      </div>

      {/* Status card */}
      <div className="rounded-lg border p-5 space-y-4">
        {isLoading ? (
          <p className="text-sm text-muted-foreground">{t("loading")}</p>
        ) : error ? (
          <p role="alert" className="text-sm text-destructive">
            {error instanceof ApiError && error.status === 403
              ? t("forbidden")
              : t("loadFailed")}
          </p>
        ) : license ? (
          <>
            <div className="flex items-center gap-3">
              <Badge variant={statusVariant(license.status)}>
                {t(`status${license.status}`)}
              </Badge>
              <span className="text-xs text-muted-foreground">
                {t("source", { source: t(sourceKey(license.source)) })}
              </span>
            </div>

            <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2 text-sm">
              <div>
                <dt className="text-muted-foreground">{t("customer")}</dt>
                <dd className="font-medium">
                  {license.customer_name ?? <span className="text-muted-foreground italic">—</span>}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("licenseId")}</dt>
                <dd className="font-mono text-xs break-all">
                  {license.lic_id ?? <span className="text-muted-foreground italic">—</span>}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("expires")}</dt>
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
                <dt className="text-muted-foreground">{t("features")}</dt>
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
                    <span className="text-muted-foreground italic">{t("featuresNone")}</span>
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
                  {t("removeLicense")}
                </Button>
              </div>
            )}
          </>
        ) : (
          <p className="text-sm text-muted-foreground">{t("loadFailed")}</p>
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
              {t("activateLabel")}
            </label>
            <textarea
              id="license-token"
              className="w-full rounded-md border bg-background px-3 py-2 text-sm font-mono resize-y min-h-[80px] focus:outline-none focus:ring-2 focus:ring-ring"
              placeholder={t("activatePlaceholder")}
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
            {activate.isPending ? t("activating") : t("activate")}
          </Button>
        </div>
      )}
    </div>
  );
}
