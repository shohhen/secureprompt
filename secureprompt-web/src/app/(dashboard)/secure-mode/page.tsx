import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";

export default async function SecureModePage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Secure Mode</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Workspace-level security controls for all LLM traffic.
        </p>
      </div>
      <div className="rounded-lg border p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="font-medium">PII Redaction</p>
            <p className="text-sm text-muted-foreground">
              Automatically redact names, emails, phone numbers, and other PII before sending to LLM providers.
            </p>
          </div>
          <span className="rounded-full bg-green-100 px-3 py-1 text-xs font-medium text-green-800 dark:bg-green-900/30 dark:text-green-400">
            Active
          </span>
        </div>
        <hr />
        <div className="flex items-center justify-between">
          <div>
            <p className="font-medium">Secret Detection</p>
            <p className="text-sm text-muted-foreground">
              Block or redact API keys, tokens, and credentials from all prompts.
            </p>
          </div>
          <span className="rounded-full bg-green-100 px-3 py-1 text-xs font-medium text-green-800 dark:bg-green-900/30 dark:text-green-400">
            Active
          </span>
        </div>
        <hr />
        <div className="flex items-center justify-between">
          <div>
            <p className="font-medium">Prompt Injection Detection</p>
            <p className="text-sm text-muted-foreground">
              ML-based detection of adversarial prompt injection attempts.
            </p>
          </div>
          <span className="rounded-full bg-blue-100 px-3 py-1 text-xs font-medium text-blue-800 dark:bg-blue-900/30 dark:text-blue-400">
            When ML Sidecar Available
          </span>
        </div>
        <hr />
        <div className="flex items-center justify-between">
          <div>
            <p className="font-medium">Semantic Policy RAG</p>
            <p className="text-sm text-muted-foreground">
              Match prompts against semantically indexed policy rules via vector search.
            </p>
          </div>
          <span className="rounded-full bg-blue-100 px-3 py-1 text-xs font-medium text-blue-800 dark:bg-blue-900/30 dark:text-blue-400">
            When ML Sidecar Available
          </span>
        </div>
      </div>
    </div>
  );
}
