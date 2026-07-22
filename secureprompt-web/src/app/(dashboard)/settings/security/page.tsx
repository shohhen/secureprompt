import { SecurityClient } from "./security-client";

export default function SecuritySettingsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-medium">Security</h2>
        <p className="text-sm text-muted-foreground">
          Manage two-factor authentication (2FA) for your own account.
        </p>
      </div>
      <SecurityClient />
    </div>
  );
}
