import { getTranslations } from "next-intl/server";
import { ProfileForm } from "./profile-form";

export default async function ProfileSettingsPage() {
  const t = await getTranslations("profileSettings");
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-medium">{t("title")}</h2>
        <p className="text-sm text-muted-foreground">
          {t("description")}
        </p>
      </div>
      <ProfileForm />
    </div>
  );
}
