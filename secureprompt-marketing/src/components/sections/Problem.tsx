export function Problem() {
  return (
    <section className="section" id="problem">
      <div className="section-head">
        <div className="section-num">
          [ 01 ]<span className="lbl">the problem</span>
        </div>
        <div>
          <div className="section-eyebrow-line">
            // every AI integration is a new exfiltration vector
          </div>
          <h2 className="editorial scroll-reveal">
            <span className="row">
              <span className="word">marketing</span>{" "}
              <span className="word delay-1">wired</span>{" "}
              <span className="word delay-2">a</span>{" "}
              <span className="word delay-3 accent">chatbot.</span>
            </span>
            <span className="row">
              <span className="word">sales</span>{" "}
              <span className="word delay-1">bought</span>{" "}
              <span className="word delay-2">a</span>{" "}
              <span className="word delay-3">notetaker.</span>
            </span>
            <span className="row">
              <span className="word">your</span>{" "}
              <span className="word delay-1 ital">copilot</span>{" "}
              <span className="word delay-2">is</span>{" "}
              <span className="word delay-3">logging</span>
            </span>
            <span className="row">
              <span className="word">prompts</span>{" "}
              <span className="word delay-1">to</span>{" "}
              <span className="word delay-2 accent">somewhere</span>{" "}
              <span className="word delay-3">else.</span>
            </span>
          </h2>
        </div>
      </div>

      <div className="pgrid">
        <div className="pcell bad">
          <span className="num">[ option a ]</span>
          <div className="title">block llms entirely</div>
          <p className="desc">
            Lose the productivity gains. Watch shadow IT route around you anyway.
          </p>
        </div>
        <div className="pcell bad">
          <span className="num">[ option b ]</span>
          <div className="title">trust each app to redact</div>
          <p className="desc">
            Marketing&apos;s chatbot, sales&apos; notetaker, and engineering&apos;s
            copilot each reinvent the same broken regex.
          </p>
        </div>
        <div className="pcell bad">
          <span className="num">[ option c ]</span>
          <div className="title">use a saas guardrail</div>
          <p className="desc">
            Add another vendor to your data flow, your audit scope, and your
            incident-response playbook.
          </p>
        </div>
        <div className="pcell bad">
          <span className="num">[ option d ]</span>
          <div className="title">tell the auditor &quot;we don&apos;t really know&quot;</div>
          <p className="desc">
            Watch them ask again next quarter, and the quarter after that.
          </p>
        </div>
        <div className="pcell good">
          <span className="num">[ secureprompt — the fourth option ]</span>
          <div className="title">
            one in-network gateway. owned by you. observable to your team.
          </div>
          <p className="desc">
            Every byte of AI-bound traffic in your network funnels through a
            single inspection point. Every request answered, attributed, and
            auditable.
          </p>
        </div>
      </div>
    </section>
  );
}
