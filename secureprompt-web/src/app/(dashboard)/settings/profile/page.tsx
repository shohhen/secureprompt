import { ProfileForm } from "./profile-form";

export default function ProfileSettingsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-medium">Profile</h2>
        <p className="text-sm text-muted-foreground">
          Personal info displayed in the dashboard. Email and role are
          managed by the workspace owner — contact them to change either.
        </p>
      </div>
      <ProfileForm />
    </div>
  );
}
