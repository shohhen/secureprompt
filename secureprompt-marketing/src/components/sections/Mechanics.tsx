import { NumRow } from "@/components/NumRow";

export function Mechanics() {
  return (
    <section className="section" id="mechanics">
      <div className="section-head">
        <div className="section-num">
          [ 03 ]<span className="lbl">mechanics</span>
        </div>
        <div>
          <div className="section-eyebrow-line">
            // honest mechanics. visible numbers. no magic.
          </div>
          <h2 className="editorial">
            <span className="row">
              <span className="word">we</span>{" "}
              <span className="word delay-1">show</span>{" "}
              <span className="word delay-2">our</span>{" "}
              <span className="word delay-3 accent">work.</span>
            </span>
          </h2>
        </div>
      </div>

      <div className="numlist">
        <NumRow
          idx="[ 03·1 ]"
          heading={
            <>
              pii <span className="ital">redaction</span> that{" "}
              <span className="accent">actually works.</span>
            </>
          }
          points={[
            {
              title: "structural matchers",
              body: "Card numbers, phone, email, IBAN, SSN — exact, deterministic.",
            },
            {
              title: "multilingual NER",
              body: "Names, organizations, addresses across English, Spanish, German, French, Russian, Uzbek.",
            },
            {
              title: "positional offsets",
              body: "Replacement happens on exact byte ranges. Never lazy substring substitution that mangles the rest of your prompt.",
            },
          ]}
        />
        <NumRow
          idx="[ 03·2 ]"
          heading={
            <>
              injection blocked at <span className="accent">≥ 0.99</span>.
            </>
          }
          points={[
            {
              title: "realistic threshold",
              body: "Every meta-prompt looks like injection at low confidence. We block at 0.99. Templating gets through. Real attempts don't.",
            },
            {
              title: "full audit context",
              body: "Every block records the score and the reason. Reviewers see exactly why.",
            },
          ]}
        />
        <NumRow
          idx="[ 03·3 ]"
          heading={
            <>
              three honest <span className="ital">numbers</span> for tokens.
            </>
          }
          points={[
            {
              title: "estimate, charged pre-flight",
              body: "So concurrent bursts can't slip past the budget.",
            },
            {
              title: "actual, from the provider",
              body: "The number your bill is based on.",
            },
            {
              title: "reconciled, in the dashboard",
              body: "What you charged minus what you used. Refunds applied automatically.",
            },
          ]}
          extra={
            <div className="tokrow" style={{ marginTop: 32 }}>
              <div className="tokcell">
                <div className="lbl">// estimate</div>
                <div className="num">247</div>
                <div className="sub">charged pre-flight</div>
              </div>
              <div className="tokcell">
                <div className="lbl">// actual</div>
                <div className="num">211</div>
                <div className="sub">from provider</div>
              </div>
              <div className="tokcell">
                <div className="lbl">// reconciled</div>
                <div className="num accent">−36</div>
                <div className="sub">refund applied</div>
              </div>
            </div>
          }
        />
        <NumRow
          idx="[ 03·4 ]"
          heading={
            <>
              two latency timers, <span className="ital">not one.</span>
            </>
          }
          points={[
            {
              title: "upstream TTFT",
              body: "Time-to-first-byte from the provider — the metric that matches user experience.",
            },
            {
              title: "gateway overhead",
              body: "Our pre-flight cost. When chat is slow, you know exactly which one is at fault.",
            },
          ]}
        />
      </div>
    </section>
  );
}
