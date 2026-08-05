import { redirect } from "next/navigation";
import { getTranslations } from "next-intl/server";
import { auth } from "@/lib/auth";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { LoginForm } from "./login-form";

interface LoginPageProps {
  // Next.js 16 App Router: searchParams is a Promise.
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}

function resolveCallbackUrl(
  params: Record<string, string | string[] | undefined>,
): string {
  const raw = params.callbackUrl;
  const value = Array.isArray(raw) ? raw[0] : raw;
  // Only accept relative paths to prevent open redirects.
  if (typeof value === "string" && value.startsWith("/") && !value.startsWith("//")) {
    return value;
  }
  return "/";
}

export default async function LoginPage({ searchParams }: LoginPageProps) {
  const t = await getTranslations("login");
  const params = await searchParams;
  const callbackUrl = resolveCallbackUrl(params);

  // Already signed in? Bounce to the callback URL.
  const session = await auth();
  if (session) {
    redirect(callbackUrl);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("title")}</CardTitle>
        <CardDescription>
          {t("subtitle")}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <LoginForm callbackUrl={callbackUrl} />
      </CardContent>
    </Card>
  );
}
