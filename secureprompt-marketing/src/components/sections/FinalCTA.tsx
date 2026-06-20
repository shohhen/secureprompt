import { TalkToUsButton } from "../TalkToUsButton";

export function FinalCTA() {
  return (
    <section className="final-cta" id="talk">
      <h2 className="editorial">
        <span className="row">
          <span className="word">you&apos;d</span>{" "}
          <span className="word delay-1 ital">build</span>{" "}
          <span className="word delay-2">it</span>
        </span>
        <span className="row">
          <span className="word">yourself.</span>{" "}
          <span className="word delay-1 accent">now</span>{" "}
          <span className="word delay-2">you</span>{" "}
          <span className="word delay-3">don&apos;t</span>{" "}
          <span className="word delay-4">have</span>{" "}
          <span className="word delay-5">to.</span>
        </span>
      </h2>
      <div className="ctas">
        <TalkToUsButton label="talk to us →" variant="outline" className="pill" />
      </div>
    </section>
  );
}
