"use client";

import { useEffect, useRef } from "react";

/** 04 · THE PROOF — the same request, written as one immutable audit row.
 *  Lines stagger in (and replay) while the section is in view. */
const LINES: { k: string; v: string; tone?: "ok" }[] = [
  { k: "request_id", v: "req_8c2f3a91…d44c" },
  { k: "workspace", v: "acme-prod" },
  { k: "user", v: "alice@acme.com" },
  { k: "budget_pre", v: "247 tokens" },
  { k: "redactions", v: "3 · {{Person_1}}, {{Email_1}}, {{Card_1}}" },
  { k: "injection_score", v: "0.06 — allow", tone: "ok" },
  { k: "policy_match", v: "workspace-strict" },
  { k: "upstream", v: "openai/gpt-4o" },
  { k: "ttft_ms", v: "318" },
  { k: "budget_actual", v: "211 · reconciled (−36)" },
  { k: "final_action", v: "allow", tone: "ok" },
];

export function Proof() {
  const wrapRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const wrap = wrapRef.current;
    if (!wrap) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const lineEls = Array.from(
      wrap.querySelectorAll<HTMLElement>(".audit-line"),
    );

    if (reduced) {
      lineEls.forEach((l) => l.classList.add("show"));
      return;
    }

    const play = () => {
      lineEls.forEach((l) => l.classList.remove("show"));
      lineEls.forEach((l, i) => {
        window.setTimeout(() => l.classList.add("show"), i * 120);
      });
    };

    let loop: number | null = null;
    const obs = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            play();
            if (loop === null) {
              loop = window.setInterval(play, lineEls.length * 120 + 4200);
            }
          } else if (loop !== null) {
            window.clearInterval(loop);
            loop = null;
          }
        }
      },
      { threshold: 0.3 },
    );
    obs.observe(wrap);
    return () => {
      obs.disconnect();
      if (loop !== null) window.clearInterval(loop);
    };
  }, []);

  return (
    <section className="section" id="proof">
      <div className="section-head">
        <div>
          <h2 className="editorial">
            <span className="row">
              <span className="word">now</span>{" "}
              <span className="word delay-1">you</span>{" "}
              <span className="word delay-2">can</span>
            </span>
            <span className="row">
              <span className="word">answer</span>{" "}
              <span className="word delay-1">the</span>{" "}
              <span className="word delay-2 accent">auditor.</span>
            </span>
          </h2>
        </div>
      </div>

      <div className="audit-demo" ref={wrapRef}>
        {LINES.map((l, i) => (
          <div key={i} className="audit-line">
            <span className="k">{l.k}</span>
            <span className={`v${l.tone ? ` ${l.tone}` : ""}`}>{l.v}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
