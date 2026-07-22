"use client";

/**
 * Settings -> Security — client panel (Task 7 of
 * docs/superpowers/plans/2026-07-22-2fa-console.md).
 *
 * Lets the CURRENT logged-in user enable or disable their own TOTP 2FA.
 * A "variant" of the login flow's enrollment screen
 * (`(auth)/login/two-factor-enroll.tsx`, Task 6) rather than a straight
 * reuse: that component is driven by a short-lived enrollment/challenge
 * token and always assumes "not yet enrolled" (the forced-enrollment
 * interstitial only ever appears for an unenrolled account), so its error
 * handling has no reason to distinguish "already enrolled" from a generic
 * failure. This panel's status logic needs exactly that distinction (see
 * below), so it re-implements the small enroll/verify UI here instead of
 * threading a new prop through the Task 6 component.
 *
 * ---- How 2FA status is determined (no dedicated status endpoint) ----
 * There is no `GET /v1/auth/2fa/status` (or similar) on the backend --
 * confirmed against `secureprompt-api/src/http/routes/dashboard/
 * twofactor.rs`. Inventing one is out of scope for this task. Instead this
 * panel infers status from `POST /v1/auth/2fa/enroll` itself:
 *   - 200  -> the account is NOT yet enrolled. The backend generates a
 *             fresh secret + backup codes on every call to an unconfirmed
 *             account, so this "status probe" doubles as fetching the QR
 *             data for the enrollment flow below -- no wasted round trip.
 *   - 409  -> the account already has CONFIRMED 2FA (the backend's
 *             `enroll()` handler explicitly rejects re-enrollment of a
 *             confirmed account: "2FA is already enabled; disable it
 *             first"). Surfaced client-side as `TwoFaAlreadyEnabledError`
 *             (twofa-api.ts) so it doesn't collapse into the same falsy
 *             result as a genuine failure.
 *   - anything else (network, 500, ...) -> status is genuinely unknown.
 * The "unknown" state is shown honestly (not guessed as enabled/disabled)
 * and offers BOTH actions with a retry, so the user is never stuck -- the
 * backend remains the real enforcer of whichever action they take.
 */

import { useEffect, useState } from "react";
import { useSession } from "next-auth/react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { TwoFactorQr } from "@/components/two-factor/qr-code";
import { TwoFaAlreadyEnabledError, type EnrollResult } from "@/lib/twofa-api";
import {
  useEnroll2fa,
  useVerify2fa,
  useDisable2fa,
} from "@/lib/hooks/use-two-factor";

type Status = "checking" | "not_enabled" | "enabled" | "unknown";

export function SecurityClient() {
  const { status: sessionStatus } = useSession();

  const [status, setStatus] = useState<Status>("checking");
  const [enrollment, setEnrollment] = useState<EnrollResult | null>(null);
  const [verifyCode, setVerifyCode] = useState("");
  const [disableCode, setDisableCode] = useState("");

  const { mutateAsync: startEnroll } = useEnroll2fa();
  const verifyMutation = useVerify2fa();
  const disableMutation = useDisable2fa();

  // Status probe on mount -- see the file-level comment above for why a
  // POST to /2fa/enroll is the status check. Deliberately NO start-guard
  // ref: React Strict Mode's dev double-invoke of effects would otherwise
  // drop BOTH invocations' results (the exact hazard already diagnosed and
  // fixed in two-factor-enroll.tsx -- a startedRef combined with a
  // per-invocation `cancelled` flag causes a PERMANENT loading hang,
  // because the first invocation's result is dropped by its own
  // cleanup-set `cancelled` while the second early-returns on the ref).
  // The cancelled-flag-only pattern below lets the probe fire twice in dev
  // (harmless -- enrolling twice just regenerates the secret again); only
  // the persisting (second) invocation's result reaches state.
  useEffect(() => {
    if (sessionStatus !== "authenticated") return;
    let cancelled = false;
    startEnroll()
      .then((data) => {
        if (cancelled) return;
        if (data) {
          setEnrollment(data);
          setStatus("not_enabled");
        } else {
          setStatus("unknown");
        }
      })
      .catch((err) => {
        if (cancelled) return;
        setStatus(
          err instanceof TwoFaAlreadyEnabledError ? "enabled" : "unknown",
        );
      });
    return () => {
      cancelled = true;
    };
  }, [sessionStatus, startEnroll]);

  async function handleRetryProbe() {
    setStatus("checking");
    try {
      const data = await startEnroll();
      if (data) {
        setEnrollment(data);
        setStatus("not_enabled");
      } else {
        setStatus("unknown");
      }
    } catch (err) {
      setEnrollment(null);
      setStatus(err instanceof TwoFaAlreadyEnabledError ? "enabled" : "unknown");
    }
  }

  async function copy(value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value);
      toast.success(`${label} copied to clipboard.`);
    } catch {
      toast.error("Couldn't copy — select the text manually.");
    }
  }

  async function handleVerify(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!verifyCode || verifyMutation.isPending) return;
    try {
      const tokens = await verifyMutation.mutateAsync(verifyCode);
      if (!tokens) {
        // Intentionally generic — parity with the login flow's wording.
        toast.error("Invalid code. Please try again.");
        setVerifyCode("");
        return;
      }
      // The reissued tokens are ignored here: the user already has a live
      // dashboard session (NextAuth), so there's nothing to swap in — the
      // verify call's only purpose on this page is to flip the account to
      // "confirmed" server-side.
      toast.success("Two-factor authentication enabled.");
      setEnrollment(null);
      setVerifyCode("");
      setStatus("enabled");
    } catch {
      toast.error("Something went wrong. Please try again.");
      setVerifyCode("");
    }
  }

  async function handleDisable(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!disableCode || disableMutation.isPending) return;
    try {
      const ok = await disableMutation.mutateAsync(disableCode);
      if (!ok) {
        toast.error("Invalid code. Please try again.");
        setDisableCode("");
        return;
      }
      toast.success("Two-factor authentication disabled.");
      setDisableCode("");
      // Re-probe rather than assume "not_enabled" so the QR/secret shown
      // next reflects a freshly generated (post-disable) enrollment.
      await handleRetryProbe();
    } catch {
      toast.error("Something went wrong. Please try again.");
      setDisableCode("");
    }
  }

  if (status === "checking") {
    return (
      <div className="space-y-3">
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-10 w-1/2" />
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-lg">
      {status === "enabled" && (
        <div className="rounded-lg border p-5 space-y-4">
          <div className="flex items-center gap-3">
            <Badge>Enabled</Badge>
            <p className="text-sm text-muted-foreground">
              Two-factor authentication is protecting your account.
            </p>
          </div>
          <DisableForm
            code={disableCode}
            onCodeChange={setDisableCode}
            onSubmit={handleDisable}
            submitting={disableMutation.isPending}
          />
        </div>
      )}

      {status === "not_enabled" && enrollment && (
        <div className="rounded-lg border p-5 space-y-4">
          <div>
            <p className="font-medium text-sm">
              Two-factor authentication is not enabled
            </p>
            <p className="text-sm text-muted-foreground mt-1">
              Scan the QR code below with an authenticator app (Google
              Authenticator, 1Password, Authy, etc.), then enter the
              6-digit code it generates to turn it on.
            </p>
          </div>

          <TwoFactorQr value={enrollment.provisioningUri} />

          <div className="space-y-1">
            <p className="text-xs font-medium text-muted-foreground">
              Can&apos;t scan? Enter this key manually
            </p>
            <div className="flex items-center gap-2">
              <code className="block flex-1 select-all break-all rounded-md border bg-muted px-3 py-2 text-sm">
                {enrollment.secretB32}
              </code>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => copy(enrollment.secretB32, "Secret key")}
              >
                Copy
              </Button>
            </div>
          </div>

          <div className="space-y-2 rounded-lg border border-warning/50 bg-warning/10 p-3">
            <div className="flex items-center justify-between gap-2">
              <p className="text-xs font-semibold text-warning">
                Save these backup codes now — shown only once
              </p>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-auto shrink-0 px-2 py-1 text-xs"
                onClick={() =>
                  copy(enrollment.backupCodes.join("\n"), "Backup codes")
                }
              >
                Copy all
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              If you lose access to your authenticator app, each code can
              be used once in its place. They won&apos;t be shown again
              after this screen.
            </p>
            <ul className="grid grid-cols-2 gap-1 rounded-md border bg-muted p-3 font-mono text-sm">
              {enrollment.backupCodes.map((backupCode) => (
                <li key={backupCode} className="select-all">
                  {backupCode}
                </li>
              ))}
            </ul>
          </div>

          <form onSubmit={handleVerify} className="space-y-2">
            <Label htmlFor="twofa-settings-verify-code">
              Authentication code
            </Label>
            <Input
              id="twofa-settings-verify-code"
              name="code"
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="123456"
              disabled={verifyMutation.isPending}
              value={verifyCode}
              onChange={(e) => setVerifyCode(e.target.value)}
            />
            <Button
              type="submit"
              className="w-full"
              disabled={verifyMutation.isPending || !verifyCode}
            >
              {verifyMutation.isPending
                ? "Verifying…"
                : "Verify & enable two-factor authentication"}
            </Button>
          </form>
        </div>
      )}

      {status === "unknown" && (
        <div className="rounded-lg border p-5 space-y-4">
          <p className="text-sm text-muted-foreground">
            We couldn&apos;t confirm your current two-factor authentication
            status. If it&apos;s already on, disable it below with a
            current code; otherwise, try setting it up again.
          </p>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={handleRetryProbe}
          >
            Set up two-factor authentication
          </Button>
          <div className="pt-2 border-t">
            <DisableForm
              code={disableCode}
              onCodeChange={setDisableCode}
              onSubmit={handleDisable}
              submitting={disableMutation.isPending}
            />
          </div>
        </div>
      )}
    </div>
  );
}

function DisableForm({
  code,
  onCodeChange,
  onSubmit,
  submitting,
}: {
  code: string;
  onCodeChange: (next: string) => void;
  onSubmit: (e: React.FormEvent<HTMLFormElement>) => void;
  submitting: boolean;
}) {
  return (
    <form onSubmit={onSubmit} className="space-y-2">
      <Label htmlFor="twofa-settings-disable-code">
        Turn off two-factor authentication
      </Label>
      <p className="text-xs text-muted-foreground">
        Enter a current authenticator code or a backup code to confirm.
      </p>
      <Input
        id="twofa-settings-disable-code"
        name="code"
        inputMode="numeric"
        autoComplete="one-time-code"
        placeholder="123456"
        disabled={submitting}
        value={code}
        onChange={(e) => onCodeChange(e.target.value)}
      />
      <Button
        type="submit"
        variant="outline"
        size="sm"
        disabled={submitting || !code}
      >
        {submitting ? "Disabling…" : "Disable two-factor authentication"}
      </Button>
    </form>
  );
}
