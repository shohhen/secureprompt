"use client";

import { useEffect, useRef } from "react";

const lines: { k: string; v: string; tone?: "ok" | "warn" | "bad" }[] = [
  { k: "request_id", v: "req_8c2f3a91…d44c" },
  { k: "workspace", v: "acme-prod" },
  { k: "user", v: "alice@acme.com" },
  { k: "budget_pre", v: "247 tokens" },
  { k: "redactions", v: "2 · {{Person_1}}, {{Email_1}}" },
  { k: "injection_score", v: "0.07 — allow", tone: "ok" },
  { k: "policy_match", v: "workspace-strict" },
  { k: "upstream", v: "openai/gpt-4o" },
  { k: "ttft_ms", v: "318" },
  { k: "overhead_ms", v: "42" },
  { k: "budget_actual", v: "211 · reconciled (−36)" },
  { k: "final_action", v: "allow", tone: "ok" },
];

export function AuditDemo() {
  const wrapRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const wrap = wrapRef.current;
    if (!wrap) return;
    const lineEls = Array.from(wrap.querySelectorAll<HTMLElement>(".audit-line"));

    const playOnce = () => {
      lineEls.forEach((l) => l.classList.remove("show"));
      lineEls.forEach((l, i) => {
        window.setTimeout(() => l.classList.add("show"), i * 120);
      });
    };

    let interval: number | null = null;
    const obs = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            playOnce();
            if (interval === null) {
              interval = window.setInterval(
                playOnce,
                lineEls.length * 120 + 4000,
              );
            }
          }
        }
      },
      { threshold: 0.3 },
    );
    obs.observe(wrap);
    return () => {
      obs.disconnect();
      if (interval !== null) window.clearInterval(interval);
    };
  }, []);

  return (
    <section className="section" id="audit-section">
      <div className="section-head">
        <div className="section-num">
          [ 03·a ]<span className="lbl">audit row</span>
        </div>
        <div>
          <div className="section-eyebrow-line">
            // every request, fully attributed
          </div>
          <h2 className="editorial">
            <span className="row">
              <span className="word">one</span>{" "}
              <span className="word delay-1 accent">row</span>{" "}
              <span className="word delay-2">per</span>{" "}
              <span className="word delay-3 ital">request.</span>
            </span>
            <span className="row">
              <span className="word">written</span>{" "}
              <span className="word delay-1">in</span>{" "}
              <span className="word delay-2">order.</span>
            </span>
          </h2>
        </div>
      </div>

      <div className="audit-demo" ref={wrapRef}>
        {lines.map((l, i) => (
          <div key={i} className="audit-line">
            <span className="k">{l.k}</span>
            <span className={`v${l.tone ? ` ${l.tone}` : ""}`}>{l.v}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
