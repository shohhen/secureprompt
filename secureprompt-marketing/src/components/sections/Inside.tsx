import { RedactionCard } from "./RedactionCard";
import { InjectionMeter } from "./InjectionMeter";

/** 03 · INSIDE — two live cards proving what the gateway does to a request. */
export function Inside() {
  return (
    <section className="section" id="inside">
      <div className="section-head">
        <div>
          <h2 className="editorial">
            <span className="row">
              <span className="word">we</span>{" "}
              <span className="word delay-1 accent">show</span>{" "}
              <span className="word delay-2">our</span>{" "}
              <span className="word delay-3">work.</span>
            </span>
          </h2>
        </div>
      </div>

      <div className="scene-grid">
        <RedactionCard />
        <InjectionMeter />
      </div>
    </section>
  );
}
