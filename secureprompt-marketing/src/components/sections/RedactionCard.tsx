"use client";

import { useEffect, useRef } from "react";

/** Live PII redaction — each sensitive span tokenizes in turn, then resets. */
export function RedactionCard() {
  const cardRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const card = cardRef.current;
    if (!card) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const piis = Array.from(card.querySelectorAll<HTMLElement>("[data-token]"));
    piis.forEach((p) => {
      p.dataset.raw = p.textContent ?? "";
    });

    const raw = (p: HTMLElement) => {
      p.textContent = p.dataset.raw ?? "";
      p.style.background = "rgba(227,6,19,0.10)";
      p.style.color = "#b00010";
      p.style.fontWeight = "500";
      p.style.borderRadius = "3px";
      p.style.padding = "1px 4px";
      p.style.fontFamily = "inherit";
    };
    const tok = (p: HTMLElement) => {
      p.textContent = `{{${p.dataset.token}}}`;
      p.style.background = "rgba(227,6,19,0.12)";
      p.style.color = "#e30613";
      p.style.fontWeight = "500";
      p.style.borderRadius = "3px";
      p.style.padding = "1px 4px";
      p.style.fontFamily = "var(--font-jetbrains),'JetBrains Mono',monospace";
      p.style.transition = "background 300ms,color 300ms,transform 300ms";
      p.style.display = "inline-block";
      p.style.transform = "scale(1.1)";
      window.setTimeout(() => {
        p.style.transform = "scale(1)";
      }, 320);
    };
    const reset = () => piis.forEach(raw);

    let on = false;
    let i = 0;
    let t: number | null = null;
    const tick = () => {
      if (!on) return;
      if (i < piis.length) {
        tok(piis[i]);
        i++;
        t = window.setTimeout(tick, 820);
      } else {
        t = window.setTimeout(() => {
          reset();
          i = 0;
          t = window.setTimeout(tick, 820);
        }, 2800);
      }
    };

    reset();
    if (reduced) {
      piis.forEach(tok);
      return;
    }

    const obs = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            if (!on) {
              on = true;
              reset();
              i = 0;
              if (t) window.clearTimeout(t);
              t = window.setTimeout(tick, 700);
            }
          } else {
            on = false;
            if (t) {
              window.clearTimeout(t);
              t = null;
            }
          }
        }
      },
      { threshold: 0.3 },
    );
    obs.observe(card);
    return () => {
      obs.disconnect();
      on = false;
      if (t) window.clearTimeout(t);
    };
  }, []);

  return (
    <div className="icard" ref={cardRef}>
      <div className="icard-label">pii redaction · watch it tokenize</div>
      <p className="redact-msg">
        Hi, customer{" "}
        <span className="pii" data-token="Person_1">
          Alice Chen
        </span>{" "}
        (
        <span className="pii" data-token="Email_1">
          alice@acme.com
        </span>
        ) is disputing a charge on card{" "}
        <span className="pii" data-token="Card_1">
          4242 4242 4242 4242
        </span>
        . Draft a reply.
      </p>
      <div className="icard-foot">
        Tokenized on the way out · restored on the way back.{" "}
        <strong>The model never sees Alice.</strong>
      </div>
    </div>
  );
}
