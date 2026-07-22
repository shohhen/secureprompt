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
 * ---- How 2FA status is shown (no dedicated status endpoint, and no
 * ---- probing write on page load) ----
 * There is no `GET /v1/auth/2fa/status` (or similar) on the backend --
 * confirmed against `secureprompt-api/src/http/routes/dashboard/
 * twofactor.rs`. Inventing one is out of scope for this task.
 *
 * `POST /v1/auth/2fa/enroll` CANNOT be used as a passive status check: for
 * an unconfirmed account it's a real write on every call (generates a new
 * secret, re-encrypts it via KMS, and invalidates/regenerates all backup
 * codes) -- see the handler's doc comment. Calling it just to render the
 * page would silently invalidate a QR the user already scanned and cost a
 * DB write + KMS encrypt on every visit. So this panel does NOT probe on
 * mount. The default view is neutral -- "Enable 2FA" and "Disable 2FA" are
 * both offered up front, honestly reflecting that the client doesn't know
 * the status without asking. `enroll()` only fires when the user clicks
 * "Enable two-factor authentication", which is the point where a write is
 * actually intended:
 *   - 200  -> not yet enrolled; the same click's response supplies the QR
 *             data, so there's no extra round trip.
 *   - 409  -> already CONFIRMED (the backend's `enroll()` handler rejects
 *             re-enrolling a confirmed account: "2FA is already enabled;
 *             disable it first"), surfaced as `TwoFaAlreadyEnabledError`
 *             (twofa-api.ts) -- shown as an info toast, no QR, no side
 *             effect on the backend.
 *   - anything else (network, 500, ...) -> generic error toast; stays on
 *             the neutral view so the user can retry.
 * `disable()` never re-triggers `enroll()` -- a successful disable just
 * returns to the neutral view; a user who wants to re-enable clicks
 * "Enable 2FA" again (their own explicit action, a fresh write).
 */

import { useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { TwoFactorQr } from "@/components/two-factor/qr-code";
import { TwoFaAlreadyEnabledError, type EnrollResult } from "@/lib/twofa-api";
import {
  useEnroll2fa,
  useVerify2fa,
  useDisable2fa,
} from "@/lib/hooks/use-two-factor";

/**
 * "idle" is the default AND the post-disable view -- neutral, both actions
 * offered, no assumption about current status. "enrolling" only follows an
 * explicit Enable click that got a 200. "known_enabled" only follows either
 * an explicit Enable click that got a 409, or a successful verify.
 */
type Status = "idle" | "enrolling" | "known_enabled";

export function SecurityClient() {
  const [status, setStatus] = useState<Status>("idle");
  const [enrollment, setEnrollment] = useState<EnrollResult | null>(null);
  const [verifyCode, setVerifyCode] = useState("");
  const [disableCode, setDisableCode] = useState("");

  const enrollMutation = useEnroll2fa();
  const verifyMutation = useVerify2fa();
  const disableMutation = useDisable2fa();

  /** Fires ONLY on the explicit "Enable two-factor authentication" click --
   *  never on mount, never after a disable. See the file-level comment for
   *  why: `enroll()` is a write for an unconfirmed account, so it must only
   *  run when the user actually intends to start enrollment. */
  async function handleEnableClick() {
    try {
      const data = await enrollMutation.mutateAsync();
      if (data) {
        setEnrollment(data);
        setStatus("enrolling");
      } else {
        toast.error("Couldn't start setup. Please try again.");
      }
    } catch (err) {
      if (err instanceof TwoFaAlreadyEnabledError) {
        // No side effect on this path -- the backend rejected before
        // touching the account. Inform the user; the Disable form (always
        // visible on the idle view) is how they'd turn it off.
        toast("Two-factor authentication is already enabled.");
        setStatus("known_enabled");
      } else {
        toast.error("Something went wrong. Please try again.");
      }
    }
  }

  function handleCancelEnroll() {
    setEnrollment(null);
    setVerifyCode("");
    setStatus("idle");
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
      setStatus("known_enabled");
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
      // Return to the neutral view -- do NOT call enroll() here. A fresh
      // enrollment (and its fresh QR/backup codes) only happens if the
      // user explicitly clicks "Enable 2FA" again.
      setStatus("idle");
    } catch {
      toast.error("Something went wrong. Please try again.");
      setDisableCode("");
    }
  }

  return (
    <div className="space-y-6 max-w-lg">
      {status === "idle" && (
        <div className="rounded-lg border p-5 space-y-4">
          <div>
            <p className="font-medium text-sm">Two-factor authentication</p>
            <p className="text-sm text-muted-foreground mt-1">
              Add an extra layer of protection with an authenticator app, or
              turn it off below if you already have it enabled.
            </p>
          </div>
          <Button
            type="button"
            onClick={handleEnableClick}
            disabled={enrollMutation.isPending}
          >
            {enrollMutation.isPending
              ? "Starting setup…"
              : "Enable two-factor authentication"}
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

      {status === "known_enabled" && (
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

      {status === "enrolling" && enrollment && (
        <div className="rounded-lg border p-5 space-y-4">
          <div>
            <p className="font-medium text-sm">
              Set up two-factor authentication
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
            <div className="flex gap-2">
              <Button
                type="submit"
                className="flex-1"
                disabled={verifyMutation.isPending || !verifyCode}
              >
                {verifyMutation.isPending
                  ? "Verifying…"
                  : "Verify & enable two-factor authentication"}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={handleCancelEnroll}
                disabled={verifyMutation.isPending}
              >
                Cancel
              </Button>
            </div>
          </form>
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
