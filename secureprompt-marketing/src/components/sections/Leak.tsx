"use client";

import { useEffect, useRef } from "react";

/**
 * 01 · THE LEAK — without a gateway, a pasted prompt walks straight across
 * the network edge into a vendor's logs, and your audit trail shows nothing.
 * The packet loops laptop → edge → vendor while the section is in view.
 */
export function Leak() {
  const stageRef = useRef<HTMLDivElement | null>(null);
  const packetRef = useRef<HTMLDivElement | null>(null);
  const laptopRef = useRef<HTMLDivElement | null>(null);
  const boundaryRef = useRef<HTMLDivElement | null>(null);
  const vendorRef = useRef<HTMLDivElement | null>(null);
  const trailRef = useRef<HTMLSpanElement | null>(null);

  useEffect(() => {
    const stage = stageRef.current;
    const packet = packetRef.current;
    const laptop = laptopRef.current;
    const boundary = boundaryRef.current;
    const vendor = vendorRef.current;
    const trail = trailRef.current;
    if (!stage || !packet || !laptop || !boundary || !vendor || !trail) return;

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const startX = () => laptop.offsetLeft + laptop.offsetWidth + 14;
    const endX = () => vendor.offsetLeft - packet.offsetWidth - 14;

    let on = false;
    let loop: number | null = null;
    let timers: number[] = [];
    const clearT = () => {
      timers.forEach((x) => window.clearTimeout(x));
      timers = [];
      if (loop) {
        window.clearTimeout(loop);
        loop = null;
      }
    };

    const run = () => {
      if (!on) return;
      clearT();
      packet.style.transition = "none";
      packet.style.left = `${startX()}px`;
      packet.style.opacity = "1";
      boundary.style.background = "#C9C8D2";
      boundary.style.boxShadow = "none";
      vendor.style.color = "#6a6573";
      vendor.style.borderColor = "#C9C8D2";
      trail.style.opacity = "0";
      requestAnimationFrame(() => {
        if (!on) return;
        packet.style.transition =
          "left 1600ms cubic-bezier(.4,0,.2,1), opacity 300ms";
        packet.style.left = `${endX()}px`;
        timers.push(
          window.setTimeout(() => {
            if (on) {
              boundary.style.background = "#e30613";
              boundary.style.boxShadow = "0 0 12px rgba(227,6,19,0.5)";
            }
          }, 720),
        );
        timers.push(
          window.setTimeout(() => {
            if (on) {
              vendor.style.color = "#b00010";
              vendor.style.borderColor = "#e30613";
            }
          }, 1500),
        );
        timers.push(
          window.setTimeout(() => {
            if (on) trail.style.opacity = "1";
          }, 1850),
        );
      });
      loop = window.setTimeout(run, 4400);
    };

    if (reduced) {
      packet.style.left = `${endX()}px`;
      vendor.style.color = "#b00010";
      vendor.style.borderColor = "#e30613";
      boundary.style.background = "#e30613";
      trail.style.opacity = "1";
      return;
    }

    const obs = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            if (!on) {
              on = true;
              run();
            }
          } else {
            on = false;
            clearT();
          }
        }
      },
      { threshold: 0.2 },
    );
    obs.observe(stage);
    return () => {
      obs.disconnect();
      on = false;
      clearT();
    };
  }, []);

  return (
    <section className="section" id="leak">
      <div className="section-head">
        <div>
          <h2 className="editorial">
            <span className="row">
              <span className="word">someone</span>{" "}
              <span className="word delay-1">pastes</span>{" "}
              <span className="word delay-2">a</span>
            </span>
            <span className="row">
              <span className="word">customer</span>{" "}
              <span className="word delay-1">into</span>{" "}
              <span className="word delay-2">the</span>{" "}
              <span className="word delay-3">chat.</span>
            </span>
            <span className="row">
              <span className="word">where</span>{" "}
              <span className="word delay-1">does</span>{" "}
              <span className="word delay-2">it</span>{" "}
              <span className="word delay-3 accent">go?</span>
            </span>
          </h2>
        </div>
      </div>

      <div className="leak-card">
        <div className="leak-meta">
          <span className="muted">support agent · 9:42</span>
          <span className="acc">without a gateway</span>
        </div>
        <p className="leak-msg">
          Hi, customer <span className="leak-pii">Alice Chen</span> (
          <span className="leak-pii">alice@acme.com</span>) is disputing a charge
          on card <span className="leak-pii">4242 4242 4242 4242</span>.
        </p>

        <div className="leak-stage" ref={stageRef}>
          <div className="leak-rail" />
          <div className="leak-boundary" ref={boundaryRef} />
          <div className="leak-edge">network edge</div>
          <div className="leak-node laptop" ref={laptopRef}>
            your laptop
          </div>
          <div className="leak-node vendor" ref={vendorRef}>
            vendor&apos;s logs
          </div>
          <div className="leak-packet" ref={packetRef}>
            Alice · 4242…
          </div>
        </div>

        <div className="leak-foot">
          <span className="muted">your audit trail</span>
          <span className="leak-trail" ref={trailRef}>
            — nothing —
          </span>
        </div>
      </div>
    </section>
  );
}
