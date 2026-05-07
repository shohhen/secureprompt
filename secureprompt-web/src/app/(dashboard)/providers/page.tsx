import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { ProvidersPanel } from "../settings/providers/providers-panel";

export default async function ProvidersPage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Providers</h1>
        <p className="text-sm text-muted-foreground mt-1">
          LLM provider credentials used by the gateway. Credentials are
          encrypted at rest; only the prefix is ever returned.
        </p>
      </div>
      <ProvidersPanel />
    </div>
  );
}
