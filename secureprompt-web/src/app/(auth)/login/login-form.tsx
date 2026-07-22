"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { signIn } from "next-auth/react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import {
  loginStep1,
  challenge,
  enroll,
  verify2fa,
  TwoFaLockedError,
  type EnrollResult,
  type Tokens,
} from "@/lib/twofa-api";

const loginSchema = z.object({
  email: z.string().email("Enter a valid email address"),
  password: z.string().min(1, "Password is required"),
});

type LoginValues = z.infer<typeof loginSchema>;

interface LoginFormProps {
  callbackUrl: string;
}

/**
 * Which screen is currently shown. `password` is the normal email+password
 * form; `challenge`/`enroll` are the 2FA steps `loginStep1` can route into
 * (see docs/superpowers/plans/2026-07-22-2fa-console.md).
 */
type Step = "password" | "challenge" | "enroll";

export function LoginForm({ callbackUrl }: LoginFormProps) {
  const router = useRouter();
  const [submitting, setSubmitting] = useState(false);
  const [step, setStep] = useState<Step>("password");
  const [challengeToken, setChallengeToken] = useState<string | null>(null);
  const [enrollmentToken, setEnrollmentToken] = useState<string | null>(null);

  const form = useForm<LoginValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: "", password: "" },
  });

  /**
   * The shared "signIn with obtained tokens -> redirect" helper. Used by
   * the plain 200 path AND the challenge/enroll success callbacks
   * (`onSuccess` for Tasks 5/6's real components).
   *
   * NextAuth's `signIn("credentials", ...)` only accepts string field
   * values, so numeric fields (`accessExpiresAt`/`refreshExpiresAt`) are
   * stringified here and re-parsed with `Number(...)` on the
   * `authorize()` side (`src/lib/auth.ts`).
   */
  async function finishWithTokens(tokens: Tokens): Promise<void> {
    try {
      const result = await signIn("credentials", {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        user: JSON.stringify({ id: tokens.user?.id, email: tokens.user?.email }),
        workspaceId: tokens.workspaceId,
        role: tokens.role,
        accessExpiresAt: String(tokens.accessExpiresAt),
        refreshExpiresAt: String(tokens.refreshExpiresAt),
        redirect: false,
      });

      if (!result || result.error) {
        // Intentionally generic — parity with backend T-05-07.
        toast.error("Invalid credentials. Please try again.");
        return;
      }

      router.push(callbackUrl);
      router.refresh();
    } catch {
      toast.error("Something went wrong. Please try again.");
    }
  }

  async function onSubmit(values: LoginValues) {
    setSubmitting(true);
    try {
      const result = await loginStep1(values.email, values.password);

      switch (result.kind) {
        case "tokens":
          await finishWithTokens(result.tokens);
          return;
        case "challenge":
          setChallengeToken(result.challengeToken);
          setStep("challenge");
          return;
        case "enroll":
          setEnrollmentToken(result.enrollmentToken);
          setStep("enroll");
          return;
        case "error":
          // Intentionally generic — parity with backend T-05-07.
          toast.error("Invalid credentials. Please try again.");
          return;
      }
    } catch {
      toast.error("Something went wrong. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  if (step === "challenge" && challengeToken) {
    return (
      <TwoFactorChallenge
        challengeToken={challengeToken}
        onSuccess={finishWithTokens}
      />
    );
  }

  if (step === "enroll" && enrollmentToken) {
    return <TwoFactorEnroll bearer={enrollmentToken} onSuccess={finishWithTokens} />;
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
        <FormField
          control={form.control}
          name="email"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Email</FormLabel>
              <FormControl>
                <Input
                  type="email"
                  autoComplete="email"
                  autoFocus
                  disabled={submitting}
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="password"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Password</FormLabel>
              <FormControl>
                <Input
                  type="password"
                  autoComplete="current-password"
                  disabled={submitting}
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <Button type="submit" className="w-full" disabled={submitting}>
          {submitting ? "Signing in…" : "Sign in"}
        </Button>
      </form>
    </Form>
  );
}

// ---------------------------------------------------------------------------
// Temporary placeholders for Tasks 5 & 6
// (docs/superpowers/plans/2026-07-22-2fa-console.md).
//
// These are NOT the real challenge/enroll screens — just enough to compile,
// wire the branching above end-to-end, and exercise the real
// `challenge()`/`enroll()`/`verify2fa()` calls against the backend.
// `TwoFactorEnroll` calls `enroll(bearer)` on mount (the backend's
// `/2fa/verify` 401s until `/2fa/enroll` has created+stored a secret) and
// renders the raw `secretB32` for manual authenticator entry plus the
// backup codes — no QR yet, but a user CAN complete enrollment with it.
// Task 5 replaces `TwoFactorChallenge` with `./two-factor-challenge.tsx`
// (styled card, 429 lockout messaging via `TwoFaLockedError`); Task 6
// replaces `TwoFactorEnroll` with `./two-factor-enroll.tsx` (adds the
// `TwoFactorQr` QR code + nicer layout, same `enroll()`/`verify2fa()` calls).
// Both keep the SAME prop contract used here, so swapping in the real
// components is a one-line import change plus deleting these two stubs:
//
//   TwoFactorChallenge({ challengeToken, onSuccess }: { challengeToken: string; onSuccess: (t: Tokens) => void })
//   TwoFactorEnroll({ bearer, onSuccess }: { bearer: string; onSuccess: (t: Tokens) => void })
// ---------------------------------------------------------------------------

function TwoFactorChallenge({
  challengeToken,
  onSuccess,
}: {
  challengeToken: string;
  onSuccess: (t: Tokens) => void;
}) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    try {
      const tokens = await challenge(challengeToken, code);
      if (!tokens) {
        toast.error("Invalid code. Please try again.");
        setCode("");
        return;
      }
      onSuccess(tokens);
    } catch (err) {
      if (err instanceof TwoFaLockedError) {
        toast.error(err.message);
      } else {
        toast.error("Something went wrong. Please try again.");
      }
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Enter the 6-digit code from your authenticator app (or a backup code).
      </p>
      <Input
        inputMode="numeric"
        autoComplete="one-time-code"
        autoFocus
        disabled={busy}
        value={code}
        onChange={(e) => setCode(e.target.value)}
      />
      <Button
        type="button"
        className="w-full"
        disabled={busy || !code}
        onClick={submit}
      >
        {busy ? "Verifying…" : "Verify"}
      </Button>
    </div>
  );
}

function TwoFactorEnroll({
  bearer,
  onSuccess,
}: {
  bearer: string;
  onSuccess: (t: Tokens) => void;
}) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [enrollment, setEnrollment] = useState<EnrollResult | null>(null);
  const [loadError, setLoadError] = useState(false);
  // Guards against React strict-mode's dev double-invoke of effects, which
  // would otherwise fire `enroll()` twice (the backend allows re-enrolling
  // before verify, but there's no reason to burn two calls / two secrets).
  const startedRef = useRef(false);

  useEffect(() => {
    if (startedRef.current) return;
    startedRef.current = true;
    let cancelled = false;
    (async () => {
      const result = await enroll(bearer);
      if (cancelled) return;
      if (!result) {
        setLoadError(true);
        return;
      }
      setEnrollment(result);
    })();
    return () => {
      cancelled = true;
    };
  }, [bearer]);

  async function submit() {
    setBusy(true);
    try {
      const tokens = await verify2fa(bearer, code);
      if (!tokens) {
        toast.error("Invalid code. Please try again.");
        setCode("");
        return;
      }
      onSuccess(tokens);
    } catch {
      toast.error("Something went wrong. Please try again.");
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  if (loadError) {
    return (
      <p className="text-sm text-destructive">
        Something went wrong setting up two-factor authentication. Please try
        again.
      </p>
    );
  }

  if (!enrollment) {
    return (
      <p className="text-sm text-muted-foreground">
        Setting up two-factor authentication…
      </p>
    );
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Two-factor authentication is required for this account. Add the
        secret below to your authenticator app (Google Authenticator,
        1Password, etc. — manual entry; a scannable QR ships in a later
        update), then enter the code it generates to continue.
      </p>
      <div className="space-y-1">
        <p className="text-xs font-medium text-muted-foreground">
          Manual entry secret
        </p>
        <code className="block select-all break-all rounded-md border bg-muted px-3 py-2 text-sm">
          {enrollment.secretB32}
        </code>
      </div>
      <div className="space-y-1">
        <p className="text-xs font-medium text-muted-foreground">
          Backup codes — save these now, shown only once
        </p>
        <ul className="grid grid-cols-2 gap-1 rounded-md border bg-muted p-3 font-mono text-sm">
          {enrollment.backupCodes.map((backupCode) => (
            <li key={backupCode} className="select-all">
              {backupCode}
            </li>
          ))}
        </ul>
      </div>
      <Input
        inputMode="numeric"
        autoComplete="one-time-code"
        autoFocus
        disabled={busy}
        value={code}
        onChange={(e) => setCode(e.target.value)}
      />
      <Button
        type="button"
        className="w-full"
        disabled={busy || !code}
        onClick={submit}
      >
        {busy ? "Verifying…" : "Verify & continue"}
      </Button>
    </div>
  );
}
