import { NumRow } from "@/components/NumRow";

export function Platform() {
  return (
    <section className="section" id="platform">
      <div className="numlist">
        <NumRow
          idx="[ 02·1 ]"
          defaultOpen
          heading={
            <>
              <span className="accent">gateway.</span>{" "}
              <span className="ital">drop-in</span> openai-compatible api.
            </>
          }
          points={[
            {
              title: "swap a base url",
              body: "Set OPENAI_API_BASE_URL to your gateway. One sp_… key works across every provider you've registered.",
            },
            {
              title: "six providers, one shape",
              body: "OpenAI, Anthropic, Google, Azure, vLLM, Ollama — same request, same audit row, same policy.",
            },
            {
              title: "streaming-safe",
              body: "Placeholder fragments straddling chunk boundaries are held in a request-scoped vault until they can be safely emitted or restored.",
            },
          ]}
        />
        <NumRow
          idx="[ 02·2 ]"
          heading={
            <>
              <span className="accent">chat.</span>{" "}
              <span className="ital">a chatgpt</span> tied to your idp.
            </>
          }
          points={[
            {
              title: "SSO from day one",
              body: "Per-user attribution. Every chat tied to a user and device in the audit log.",
            },
            {
              title: "same pipeline as the gateway",
              body: "PII tokenized upstream. Restored on return. The model never sees Alice's data.",
            },
            {
              title: "desktop & web",
              body: "Productivity surface that doesn't push your team back to shadow IT.",
            },
          ]}
        />
        <NumRow
          idx="[ 02·3 ]"
          heading={
            <>
              <span className="accent">console.</span>{" "}
              <span className="ital">the operator</span> surface.
            </>
          }
          points={[
            {
              title: "answer the auditor's question",
              body: "What got sent, by whom, to which model, and was anything sensitive in it.",
            },
            {
              title: "policy as code",
              body: "Workspace-scoped rules. Block, redact, flag, allow — configurable per route.",
            },
            {
              title: "analytics that map to spend",
              body: "Reconciled token counts. Per-user, per-workspace, per-model.",
            },
          ]}
        />
      </div>
    </section>
  );
}
