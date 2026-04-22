import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { ProvidersTable } from "./providers-table";

export default async function ProvidersPage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Providers</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Configure LLM provider credentials. Credentials are encrypted at rest.
        </p>
      </div>
      <ProvidersTable workspaceId={session.workspaceId} />
    </div>
  );
}
