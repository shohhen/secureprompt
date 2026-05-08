"use client";

import { useEffect, useRef } from "react";

/**
 * Scroll-progress word reveal — the Revelo signature scene.
 * Words light up green/red sequentially as the section travels through
 * the viewport. The strikethrough words light up to mean "wrong answer".
 */
export function RevealShow() {
  const sectionRef = useRef<HTMLElement | null>(null);
  const stageRef = useRef<HTMLDivElement | null>(null);
  const progressRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const section = sectionRef.current;
    const stage = stageRef.current;
    const progressBar = progressRef.current;
    if (!section || !stage || !progressBar) return;

    const words = Array.from(stage.querySelectorAll<HTMLElement>(".word"));

    const tick = () => {
      const r = section.getBoundingClientRect();
      const vh = window.innerHeight;
      const total = r.height + vh;
      const traveled = vh - r.top;
      const p = Math.max(0, Math.min(1, traveled / total));
      progressBar.style.width = `${p * 100}%`;
      const idx = Math.floor(p * words.length * 1.4);
      words.forEach((w, i) => {
        if (i < idx) w.classList.add("on");
        else w.classList.remove("on");
      });
    };

    tick();
    window.addEventListener("scroll", tick, { passive: true });
    window.addEventListener("resize", tick);
    return () => {
      window.removeEventListener("scroll", tick);
      window.removeEventListener("resize", tick);
    };
  }, []);

  return (
    <section className="reveal-show" id="platform-intro" ref={sectionRef}>
      <div className="progress" ref={progressRef} />
      <div className="label">
        [ 02 ]&nbsp;&nbsp;<span className="acc">// the platform</span>
      </div>
      <div className="reveal-stage" ref={stageRef}>
        <span className="line">
          <span className="word">three</span> <span className="word">products.</span>
        </span>
        <span className="line">
          <span className="word">one</span>{" "}
          <span className="word acc">inspection</span>{" "}
          <span className="word">point.</span>
        </span>
        <span className="line">
          <span className="word strike">multiple</span>{" "}
          <span className="word strike">vendors.</span>
        </span>
        <span className="line">
          <span className="word strike">multiple</span>{" "}
          <span className="word strike">audit</span>{" "}
          <span className="word strike">trails.</span>
        </span>
        <span className="line">
          <span className="word strike">multiple</span>{" "}
          <span className="word strike">surfaces</span>{" "}
          <span className="word strike">to</span>{" "}
          <span className="word strike">defend.</span>
        </span>
      </div>
    </section>
  );
}
