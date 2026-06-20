import { TalkToUsButton } from "../TalkToUsButton";

export function Hero() {
  return (
    <section className="hero" id="top">
      <div className="hero-eyebrow">
        <span>v 1.0 · 2026</span>
      </div>
      <h1 className="hero-title" id="hero-title">
        <span className="row">
          <span className="word">see</span> <span className="word">every</span>{" "}
          <span className="word">prompt</span>
        </span>
        <span className="row">
          <span className="word">your</span> <span className="word">team</span>{" "}
          <span className="word">sends</span> <span className="word">to</span>{" "}
          <span className="word ital">ai</span>
        </span>
        <span className="row">
          <span className="word">before</span> <span className="word">it</span>{" "}
          <span className="word underline">leaves.</span>
        </span>
      </h1>
      <div className="hero-actions">
        <div className="hero-pills">
          <span className="hero-pill">in-network gateway</span>
          <span className="hero-pill">redact · block · enforce · log</span>
          <span className="hero-pill">your vpc · air-gapped</span>
        </div>
        <TalkToUsButton label="talk to us ↗" variant="outline" />
      </div>
      <div className="scroll-cue">
        <span className="arrow">↓</span>
        scroll to follow one request
      </div>
    </section>
  );
}
