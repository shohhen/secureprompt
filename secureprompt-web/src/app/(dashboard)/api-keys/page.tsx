import { redirect } from "next/navigation";
import { getTranslations } from "next-intl/server";
import { getServerSession } from "@/lib/session";
import { KeysPanel } from "../settings/keys/keys-panel";

export default async function ApiKeysPage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");
  const t = await getTranslations("apiKeys");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("title")}</h1>
        <p className="text-sm text-muted-foreground mt-1">
          {t("description")}
        </p>
      </div>
      <KeysPanel workspaceId={session.workspaceId} />
    </div>
  );
}
