"use client";

import { useEffect, useRef } from "react";

/** 05 · ON-PREM — the data path. A packet cycles apps → secureprompt
 *  (checked & logged) → cloud model → secureprompt (pii restored), all but the
 *  tokenized hop staying inside the dashed network boundary. */
export function OnPrem() {
  const flowRef = useRef<HTMLDivElement | null>(null);
  const packetRef = useRef<HTMLDivElement | null>(null);
  const labelRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const flow = flowRef.current;
    const packet = packetRef.current;
    const label = labelRef.current;
    if (!flow || !packet || !label) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    const targets: Record<string, HTMLElement> = {};
    flow.querySelectorAll<HTMLElement>("[data-perim-target]").forEach((el) => {
      const key = el.getAttribute("data-perim-target");
      if (key) targets[key] = el;
    });

    const centerOf = (el: HTMLElement) => {
      const fr = flow.getBoundingClientRect();
      const r = el.getBoundingClientRect();
      return {
        x: r.left - fr.left + r.width / 2,
        y: r.top - fr.top + r.height / 2,
        top: r.top - fr.top,
      };
    };
    const moveTo = (key: string) => {
      const c = centerOf(targets[key]);
      packet.style.transform = `translate(${c.x - 8}px,${c.y - 8}px)`;
    };
    const showLabel = (text: string) => {
      const c = centerOf(targets.sp);
      label.textContent = text;
      label.style.transform = `translate(${c.x}px,${c.top}px) translate(-50%,-140%)`;
      label.style.opacity = "1";
    };
    const hideLabel = () => {
      label.style.opacity = "0";
    };

    const seq: { t: string; label: string | null }[] = [
      { t: "apps", label: null },
      { t: "sp", label: "checked & logged" },
      { t: "cloud", label: null },
      { t: "sp", label: "original pii restored" },
    ];
    let k = 0;
    const apply = (i: number) => {
      const s = seq[((i % seq.length) + seq.length) % seq.length];
      moveTo(s.t);
      if (s.label) showLabel(s.label);
      else hideLabel();
    };

    requestAnimationFrame(() => apply(0));
    const onResize = () => apply(k);
    window.addEventListener("resize", onResize);

    if (reduced) {
      apply(1);
      return () => window.removeEventListener("resize", onResize);
    }

    let timer: number | null = null;
    const start = () => {
      if (timer) return;
      timer = window.setInterval(() => {
        k++;
        apply(k);
      }, 1900);
    };
    const stop = () => {
      if (timer) {
        window.clearInterval(timer);
        timer = null;
      }
    };
    const obs = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) start();
          else stop();
        }
      },
      { threshold: 0.2 },
    );
    obs.observe(flow);
    return () => {
      obs.disconnect();
      stop();
      window.removeEventListener("resize", onResize);
    };
  }, []);

  return (
    <section className="section" id="onprem">
      <div className="section-head">
        <div>
          <h2 className="editorial">
            <span className="row">
              <span className="word">your</span>{" "}
              <span className="word delay-1">data</span>{" "}
              <span className="word delay-2">never</span>
            </span>
            <span className="row">
              <span className="word">leaves</span>{" "}
              <span className="word delay-1">your</span>{" "}
              <span className="word delay-2 accent">network.</span>
            </span>
          </h2>
        </div>
      </div>

      <div className="perim">
        <div className="perim-head">
          <span>the data path</span>
          <span>everything inspected in-cluster</span>
        </div>

        <div className="perim-flow" ref={flowRef}>
          <div className="perim-box">
            <div className="perim-glow" />
            <div className="perim-box-label">▢ your network · your hardware</div>
            <div className="perim-row">
              <div className="perim-rail" />
              <div className="perim-node" data-perim-target="apps">
                your apps
              </div>
              <div className="perim-node sp" data-perim-target="sp">
                secureprompt
              </div>
            </div>
          </div>

          <div className="perim-arrow">
            <span className="glyph">→</span>
            <span className="note">
              tokenized
              <br />
              only
            </span>
          </div>

          <div className="perim-cloud-wrap">
            <div className="perim-cloud" data-perim-target="cloud">
              ☁ cloud ai models
              <br />
              <span className="muted">openai · anthropic · google</span>
            </div>
          </div>

          <div className="perim-packet" ref={packetRef} />
          <div className="perim-tag" ref={labelRef} />
        </div>

        <div className="perim-bullets">
          <div className="perim-bullet">
            <span className="glyph">→</span>
            <div>
              only <span className="acc">tokenized text</span> ever crosses to a
              hosted model
            </div>
          </div>
          <div className="perim-bullet">
            <span className="glyph blink">✕</span>
            <div>
              nothing phones home —{" "}
              <span className="muted">no outbound telemetry</span>
            </div>
          </div>
        </div>

        <div className="perim-tags">
          <span>air-gap capable</span>
          <span className="dot">·</span>
          <span>local inference</span>
          <span className="dot">·</span>
          <span>fail-closed</span>
        </div>
      </div>
    </section>
  );
}
