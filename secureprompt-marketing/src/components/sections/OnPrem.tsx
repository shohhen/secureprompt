import { NumRow } from "@/components/NumRow";

export function OnPrem() {
  return (
    <section className="section" id="onprem">
      <div className="section-head">
        <div className="section-num">
          [ 04 ]<span className="lbl">on-prem only</span>
        </div>
        <div>
          <div className="section-eyebrow-line">
            // not &quot;an on-prem option&quot; — the only deployment
          </div>
          <h2 className="editorial">
            <span className="row">
              <span className="word">the</span>{" "}
              <span className="word delay-1 ital">cloud</span>{" "}
              <span className="word delay-2">version</span>
            </span>
            <span className="row">
              <span className="word">does</span>{" "}
              <span className="word delay-1 accent">not</span>{" "}
              <span className="word delay-2">exist.</span>
            </span>
          </h2>
        </div>
      </div>

      <div className="numlist">
        <NumRow
          idx="[ 04·1 ]"
          defaultOpen
          heading={
            <>
              <span className="ital">air-gapped</span> capable.
            </>
          }
          points={[
            {
              title: "",
              body: "All required AI models pre-bundled or downloaded once at install. After that, runs without internet.",
            },
          ]}
        />
        <NumRow
          idx="[ 04·2 ]"
          heading={
            <>
              local <span className="accent">ai inference.</span>
            </>
          }
          points={[
            {
              title: "",
              body: "PII detection and injection classification stay inside your cluster. Sensitive data never leaves to be inspected.",
            },
          ]}
        />
        <NumRow
          idx="[ 04·3 ]"
          heading={<>minimal attack surface.</>}
          points={[
            {
              title: "",
              body: "Production binaries stripped of build tooling, runtimes, and shells. What ships is what runs.",
            },
          ]}
        />
        <NumRow
          idx="[ 04·4 ]"
          heading={
            <>
              license-gated, <span className="ital">fail-closed.</span>
            </>
          }
          points={[
            {
              title: "",
              body: "Signed license file controls activation. Expired licenses fail closed at the boundary, before any business logic runs.",
            },
          ]}
        />
        <NumRow
          idx="[ 04·5 ]"
          heading={
            <>
              no outbound telemetry. <span className="accent">by default.</span>
            </>
          }
          points={[
            {
              title: "",
              body: "Optional support tunnel — explicit opt-in, time-bounded, fully auditable. Off until you turn it on.",
            },
          ]}
        />
      </div>
    </section>
  );
}
