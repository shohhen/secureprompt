import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { SecureModeEditor } from "./secure-mode-editor";
import { TokenizePlayground } from "./tokenize-playground";

export default async function SecureModePage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  return (
    <div className="space-y-10">
      <div>
        <h1 className="text-2xl font-semibold">Secure Mode</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Workspace-level security controls applied to every LLM request routed
          through the gateway.
        </p>
      </div>
      <SecureModeEditor />
      <TokenizePlayground />
    </div>
  );
}
