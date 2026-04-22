import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { ApiKeysTable } from "./api-keys-table";

export default async function ApiKeysPage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">API Keys</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Gateway access keys used by client applications to call SecurePrompt.
        </p>
      </div>
      <ApiKeysTable workspaceId={session.workspaceId} />
    </div>
  );
}
