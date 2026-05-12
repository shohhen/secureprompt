import { TalkToUsButton } from "../TalkToUsButton";

export function Hero() {
  return (
    <section className="hero" id="top">
      <div className="hero-eyebrow">
        <span className="tag">[ 00 ]&nbsp;&nbsp;intro</span>
        <span>v 1.0 · 2026</span>
      </div>
      <h1 className="hero-title" id="hero-title">
        <span className="row">
          <span className="word">the</span> <span className="word">security</span>{" "}
          <span className="word">gateway</span>
        </span>
        <span className="row">
          <span className="word">for</span>{" "}
          <span className="word ital">the</span>{" "}
          <span className="word accent">ai-native</span>
        </span>
        <span className="row">
          <span className="word underline">enterprise.</span>
        </span>
      </h1>
      <div className="hero-foot">
        <div className="col">
          <span className="k">// what it is</span>
          <span className="v">
            In-network gateway between every AI app, agent, copilot and the LLM
            provider
          </span>
        </div>
        <div className="col">
          <span className="k">// what it does</span>
          <span className="v">
            Redacts PII · blocks injection · enforces policy · ships an audit row
          </span>
        </div>
        <div className="col">
          <span className="k">// where it runs</span>
          <span className="v">
            Your VPC. Your hardware. Air-gap capable. No outbound telemetry.
          </span>
        </div>
        <div className="col cta">
          <span className="k">// next</span>
          <TalkToUsButton label="Talk to us" variant="link" />
        </div>
      </div>
      <div className="scroll-discover">scroll to discover</div>
    </section>
  );
}
