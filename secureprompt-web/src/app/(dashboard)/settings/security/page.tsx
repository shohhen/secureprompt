import { getTranslations } from "next-intl/server";
import { SecurityClient } from "./security-client";

export default async function SecuritySettingsPage() {
  const t = await getTranslations("securitySettings");
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-medium">{t("title")}</h2>
        <p className="text-sm text-muted-foreground">
          {t("description")}
        </p>
      </div>
      <SecurityClient />
    </div>
  );
}
