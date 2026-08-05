import { redirect } from "next/navigation";
import { getTranslations } from "next-intl/server";
import { getServerSession } from "@/lib/session";
import { SecureModeEditor } from "./secure-mode-editor";
import { TokenizePlayground } from "./tokenize-playground";

export default async function SecureModePage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");
  const t = await getTranslations("secureModePage");

  return (
    <div className="space-y-10">
      <div>
        <h1 className="text-2xl font-semibold">{t("title")}</h1>
        <p className="text-sm text-muted-foreground mt-1">
          {t("description")}
        </p>
      </div>
      <SecureModeEditor />
      <TokenizePlayground />
    </div>
  );
}
