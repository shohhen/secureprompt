"use client";

import { useEffect, useRef } from "react";

/**
 * 02 · THE GATEWAY — the scroll-scrubbed centerpiece. The section is a tall
 * (600vh) scene with a sticky card; scroll progress maps to one of seven
 * pipeline steps. The tracer packet walks node-to-node, the fill grows, and
 * the payload chip + caption change to narrate what happens to the request.
 */
const STEPS: { pay: string; safe: boolean; cap: string }[] = [
  { pay: "Alice Chen · card 4242…", safe: false, cap: "request received at the gateway" },
  { pay: "alice@acme.com · macbook-pro", safe: false, cap: "tied to a user & device — every request has a name" },
  { pay: "{{Person_1}} · {{Card_1}}", safe: true, cap: "pii swapped for placeholders — the model never sees alice" },
  { pay: "injection score 0.06  ✓", safe: true, cap: "scored for injection · blocked only at ≥ 0.99" },
  { pay: "policy: workspace-strict", safe: true, cap: "workspace policy decides: block · redact · flag · allow" },
  { pay: "→ openai/gpt-4o · redacted", safe: true, cap: "only the redacted prompt crosses to the provider" },
  { pay: "req_8c2f3a91 · logged  ✓", safe: true, cap: "placeholders restored · one audit row written" },
];
const NODES = ["in", "auth", "redact", "scan", "policy", "send", "log"];

export function Gateway() {
  const sceneRef = useRef<HTMLDivElement | null>(null);
  const trackRef = useRef<HTMLDivElement | null>(null);
  const packetRef = useRef<HTMLDivElement | null>(null);
  const fillRef = useRef<HTMLDivElement | null>(null);
  const payloadRef = useRef<HTMLDivElement | null>(null);
  const captionRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const scene = sceneRef.current;
    const track = trackRef.current;
    const packet = packetRef.current;
    const fill = fillRef.current;
    const payload = payloadRef.current;
    const caption = captionRef.current;
    if (!scene || !track || !packet || !fill || !payload || !caption) return;

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const dots = Array.from(track.querySelectorAll<HTMLElement>("[data-dot]"));
    const lbls = Array.from(track.querySelectorAll<HTMLElement>("[data-lbl]"));
    let payTimer: number | null = null;

    const place = (idx: number, animate: boolean) => {
      const dot = dots[idx];
      if (!dot) return;
      const tr = track.getBoundingClientRect();
      const dr = dot.getBoundingClientRect();
      const cx = dr.left - tr.left + dr.width / 2;
      packet.style.transition = animate
        ? "transform 700ms cubic-bezier(.4,0,.2,1)"
        : "none";
      packet.style.transform = `translateX(${cx - packet.offsetWidth / 2}px)`;
      fill.style.width = `${Math.max(0, cx - 18)}px`;
      dots.forEach((d, j) => {
        const l = lbls[j];
        if (j === idx) {
          d.style.background = "#e30613";
          d.style.borderColor = "#e30613";
          d.style.color = "#fceee8";
          d.style.transform = "scale(1.1)";
          if (l) l.style.color = "#0e0e12";
        } else if (j < idx) {
          d.style.background = "#FFFFFF";
          d.style.borderColor = "#e30613";
          d.style.color = "#e30613";
          d.style.transform = "scale(1)";
          if (l) l.style.color = "#6a6573";
        } else {
          d.style.background = "#FFFFFF";
          d.style.borderColor = "#C9C8D2";
          d.style.color = "#6a6573";
          d.style.transform = "scale(1)";
          if (l) l.style.color = "#6a6573";
        }
      });
      const s = STEPS[idx];
      payload.style.opacity = "0";
      caption.style.opacity = "0";
      if (payTimer) window.clearTimeout(payTimer);
      payTimer = window.setTimeout(() => {
        payload.textContent = s.pay;
        if (s.safe) {
          payload.style.background = "rgba(227,6,19,0.06)";
          payload.style.borderColor = "rgba(227,6,19,0.3)";
          payload.style.color = "#e30613";
        } else {
          payload.style.background = "rgba(227,6,19,0.12)";
          payload.style.borderColor = "rgba(227,6,19,0.45)";
          payload.style.color = "#b00010";
        }
        payload.style.opacity = "1";
        caption.textContent = s.cap;
        caption.style.opacity = "1";
      }, 230);
    };

    let cur = -1;
    const render = (idx: number, animate: boolean) => {
      if (idx === cur) return;
      cur = idx;
      place(idx, animate);
    };

    requestAnimationFrame(() => render(0, false));

    const onResize = () => place(cur < 0 ? 0 : cur, false);
    window.addEventListener("resize", onResize);

    if (reduced) {
      render(STEPS.length - 1, false);
      return () => {
        window.removeEventListener("resize", onResize);
        if (payTimer) window.clearTimeout(payTimer);
      };
    }

    const onScroll = () => {
      const r = scene.getBoundingClientRect();
      const total = Math.max(1, scene.offsetHeight - window.innerHeight);
      const scrolled = Math.min(Math.max(-r.top, 0), total);
      const p = scrolled / total;
      let step = Math.floor(p * STEPS.length);
      if (step > STEPS.length - 1) step = STEPS.length - 1;
      if (step < 0) step = 0;
      render(step, true);
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });

    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onResize);
      if (payTimer) window.clearTimeout(payTimer);
    };
  }, []);

  return (
    <div className="gw-scene" ref={sceneRef}>
      <section className="gw-sticky" id="gateway">
        <div className="section-head">
          <div>
            <h2 className="editorial">
              <span className="row">
                <span className="word">one</span>{" "}
                <span className="word delay-1 accent">inspection</span>
              </span>
              <span className="row">
                <span className="word">point.</span>{" "}
                <span className="word delay-1">every</span>{" "}
                <span className="word delay-2">request.</span>
              </span>
            </h2>
          </div>
        </div>

        <div className="pipeline">
          <div className="pl-meta">
            <span className="acc">following</span> req_8c2f3a91…d44c{" "}
            <span>app → model → back</span>
          </div>

          <div className="pl-payload-wrap">
            <div className="pl-payload" ref={payloadRef}>
              Alice Chen · card 4242…
            </div>
          </div>

          <div className="pl-track" ref={trackRef}>
            <div className="pl-rail" />
            <div className="pl-fill" ref={fillRef} />
            <div className="pl-nodes">
              {NODES.map((label, i) => (
                <div className="pl-node" key={label}>
                  <div className="pl-dot" data-dot>
                    {String(i + 1).padStart(2, "0")}
                  </div>
                  <div className="pl-lbl" data-lbl>
                    {label}
                  </div>
                </div>
              ))}
            </div>
            <div className="pl-packet" ref={packetRef} />
          </div>

          <div className="pl-caption" ref={captionRef}>
            request received at the gateway
          </div>
        </div>
      </section>
    </div>
  );
}
