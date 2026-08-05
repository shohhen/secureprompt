"use client";

import { useEffect, useState } from "react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { TwoFactorQr } from "@/components/two-factor/qr-code";
import {
  enroll,
  verify2fa,
  type EnrollResult,
  type Tokens,
} from "@/lib/twofa-api";

interface TwoFactorEnrollProps {
  bearer: string;
  onSuccess: (tokens: Tokens) => void;
}

/**
 * The forced 2FA enrollment screen (Task 6 of
 * docs/superpowers/plans/2026-07-22-2fa-console.md).
 *
 * `login-form.tsx` swaps this in once `loginStep1` returns
 * `{ kind: "enroll" }` — 2FA is mandatory for this account (Owner/Admin) and
 * it hasn't enrolled yet. It renders inside the same `<Card>` the login page
 * already provides (`src/app/(auth)/login/page.tsx`), matching
 * `two-factor-challenge.tsx`'s conventions (Label+aria-describedby on the
 * code input, no Card chrome of its own).
 *
 * Replaces the inline `TwoFactorEnroll` stub that used to live at the
 * bottom of `login-form.tsx`: same prop contract, same `enroll()` /
 * `verify2fa()` calls, plus the real `TwoFactorQr` (Task 1) and a more
 * deliberate "save this now" callout for the secret + backup codes.
 */
export function TwoFactorEnroll({ bearer, onSuccess }: TwoFactorEnrollProps) {
  const t = useTranslations("twoFactor");
  const [enrollment, setEnrollment] = useState<EnrollResult | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [code, setCode] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Deliberately no ref-guard against React strict-mode's dev
  // double-invoke: an earlier version tried to dedupe with a `startedRef`,
  // but combined with the per-invocation `cancelled` flag that caused a
  // PERMANENT loading hang under strict mode (the exact environment Task
  // 8's KPI demo runs in via `pnpm dev`) — the 1st invocation's result got
  // dropped by its own cleanup-set `cancelled`, and the 2nd (persisting)
  // invocation's early-return on `startedRef` meant nothing ever called
  // `setEnrollment`/`setLoadError`. The plain cancelled-only pattern below
  // lets `enroll()` fire twice in dev; that's harmless — the backend's
  // `/2fa/enroll` overwrites the secret + backup codes on repeat calls for
  // an unconfirmed account — and only the second (persisting) invocation's
  // result reaches state, matching the actually-stored secret. Production
  // has no double-invoke at all. DO NOT reintroduce a `startedRef`/similar
  // guard here.
  useEffect(() => {
    let cancelled = false;
    enroll(bearer)
      .then((res) => {
        if (cancelled) return;
        if (res) setEnrollment(res);
        else setLoadError(true);
      })
      .catch(() => {
        if (!cancelled) setLoadError(true);
      });
    return () => {
      cancelled = true;
    };
  }, [bearer]);

  /** `what` is a `twoFactor` key naming the thing copied, not copy itself. */
  async function copy(value: string, what: "secretKey" | "backupCodes") {
    try {
      await navigator.clipboard.writeText(value);
      toast.success(t("copiedToClipboard", { what: t(what) }));
    } catch {
      toast.error(t("copyFailed"));
    }
  }

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!code || submitting) return;

    setSubmitting(true);
    try {
      const tokens = await verify2fa(bearer, code);
      if (!tokens) {
        // Intentionally generic — parity with the login form's "Invalid
        // credentials" / the challenge screen's "Invalid code" wording.
        toast.error(t("invalidCode"));
        setCode("");
        return;
      }
      onSuccess(tokens);
    } catch {
      toast.error(t("unexpected"));
      setCode("");
    } finally {
      setSubmitting(false);
    }
  }

  if (loadError) {
    return (
      <p role="alert" className="text-sm text-destructive">
        {t("enrollLoadFailed")}
      </p>
    );
  }

  if (!enrollment) {
    return (
      <p aria-live="polite" className="text-sm text-muted-foreground">
        {t("enrollLoading")}
      </p>
    );
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <p id="twofa-enroll-hint" className="text-sm text-muted-foreground">
        {t("enrollHint")}
      </p>

      <TwoFactorQr value={enrollment.provisioningUri} />

      <div className="space-y-1">
        <p className="text-xs font-medium text-muted-foreground">
          {t("manualKeyHint")}
        </p>
        <div className="flex items-center gap-2">
          <code className="block flex-1 select-all break-all rounded-md border bg-muted px-3 py-2 text-sm">
            {enrollment.secretB32}
          </code>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => copy(enrollment.secretB32, "secretKey")}
          >
            {t("copy")}
          </Button>
        </div>
      </div>

      <div className="space-y-2 rounded-lg border border-warning/50 bg-warning/10 p-3">
        <div className="flex items-center justify-between gap-2">
          <p className="text-xs font-semibold text-warning">
            {t("backupCodesTitle")}
          </p>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-auto shrink-0 px-2 py-1 text-xs"
            onClick={() =>
              copy(enrollment.backupCodes.join("\n"), "backupCodes")
            }
          >
            {t("copyAll")}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">
          {t("backupCodesHint")}
        </p>
        <ul className="grid grid-cols-2 gap-1 rounded-md border bg-muted p-3 font-mono text-sm">
          {enrollment.backupCodes.map((backupCode) => (
            <li key={backupCode} className="select-all">
              {backupCode}
            </li>
          ))}
        </ul>
      </div>

      <div className="space-y-2">
        <Label htmlFor="twofa-enroll-code">{t("code")}</Label>
        <Input
          id="twofa-enroll-code"
          name="code"
          inputMode="numeric"
          autoComplete="one-time-code"
          placeholder="123456"
          autoFocus
          disabled={submitting}
          aria-describedby="twofa-enroll-hint"
          value={code}
          onChange={(e) => setCode(e.target.value)}
        />
      </div>

      <Button type="submit" className="w-full" disabled={submitting || !code}>
        {submitting ? t("verifying") : t("verifyAndContinue")}
      </Button>
    </form>
  );
}
