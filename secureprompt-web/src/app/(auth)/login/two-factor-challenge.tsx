"use client";

import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { challenge, TwoFaLockedError, type Tokens } from "@/lib/twofa-api";

interface TwoFactorChallengeProps {
  challengeToken: string;
  onSuccess: (tokens: Tokens) => void;
}

/**
 * The 2FA challenge screen (Task 5 of
 * docs/superpowers/plans/2026-07-22-2fa-console.md).
 *
 * `login-form.tsx` swaps this in for the password fields once `loginStep1`
 * returns `{ kind: "challenge" }` — the account has 2FA enabled and needs a
 * live TOTP or backup code before a session can be created. It renders
 * inside the SAME `<Card>` the login page already provides
 * (`src/app/(auth)/login/page.tsx`), so this component supplies only the
 * card's content, matching the login form's spacing/typography — no Card
 * chrome of its own.
 */
export function TwoFactorChallenge({
  challengeToken,
  onSuccess,
}: TwoFactorChallengeProps) {
  const [code, setCode] = useState("");
  const [submitting, setSubmitting] = useState(false);
  // Set only on a 429 (`TwoFaLockedError`) — a persistent inline banner is
  // more useful here than a transient toast, since the point is "don't
  // bother retrying immediately." Cleared as soon as the user edits the
  // code, which also lets them try again once the reason for the lockout
  // (e.g. a stale code) has passed; the server remains the real enforcer
  // of the rate limit either way.
  const [lockedMessage, setLockedMessage] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!code || submitting) return;

    setSubmitting(true);
    try {
      const tokens = await challenge(challengeToken, code);
      if (!tokens) {
        // Intentionally generic — parity with the login form's "Invalid
        // credentials" wording (no hint re: TOTP vs. backup code).
        toast.error("Invalid code. Please try again.");
        setCode("");
        return;
      }
      onSuccess(tokens);
    } catch (err) {
      if (err instanceof TwoFaLockedError) {
        setLockedMessage(err.message);
      } else {
        toast.error("Something went wrong. Please try again.");
      }
      setCode("");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <p id="twofa-challenge-hint" className="text-sm text-muted-foreground">
        Enter the 6-digit code from your authenticator app, or one of your
        saved backup codes.
      </p>

      <div className="space-y-2">
        <Label htmlFor="twofa-challenge-code">Authentication code</Label>
        <Input
          id="twofa-challenge-code"
          name="code"
          inputMode="numeric"
          autoComplete="one-time-code"
          placeholder="123456"
          autoFocus
          disabled={submitting}
          aria-invalid={!!lockedMessage}
          aria-describedby={
            lockedMessage
              ? "twofa-challenge-hint twofa-challenge-error"
              : "twofa-challenge-hint"
          }
          value={code}
          onChange={(e) => {
            setCode(e.target.value);
            setLockedMessage(null);
          }}
        />
      </div>

      {lockedMessage && (
        <div
          id="twofa-challenge-error"
          role="alert"
          className="rounded-lg border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive"
        >
          {lockedMessage}
        </div>
      )}

      <Button
        type="submit"
        className="w-full"
        disabled={submitting || !code || !!lockedMessage}
      >
        {submitting ? "Verifying…" : "Verify"}
      </Button>
    </form>
  );
}
