"use client";

import { useState } from "react";
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
import { loginStep1, type Tokens } from "@/lib/twofa-api";
import { TwoFactorChallenge } from "./two-factor-challenge";
import { TwoFactorEnroll } from "./two-factor-enroll";

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
