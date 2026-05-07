import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { MembersPanel } from "./members-panel";

export default async function MembersSettingsPage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  return <MembersPanel />;
}
