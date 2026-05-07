import { redirect } from "next/navigation";

export default function SettingsIndex() {
  // The settings section is tab-based; landing here is equivalent to the
  // first tab. Redirect so deep-links like `/settings` don't 404.
  redirect("/settings/keys");
}
