"use client";

import { useEffect } from "react";

/**
 * Bidirectional `.editorial` reveal — toggles `.in` based on viewport
 * intersection so words rise on scroll-down AND sink back on scroll-up.
 *
 * Single global observer for all `.editorial` blocks on the page; mounts
 * once at the layout root and self-cleans on unmount.
 */
export function EditorialObserver() {
  useEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) {
      document
        .querySelectorAll<HTMLElement>(".editorial,.hero-title")
        .forEach((el) => el.classList.add("in"));
      return;
    }

    // Hero rises on mount with a tiny delay
    const heroTimer = window.setTimeout(() => {
      document.getElementById("hero-title")?.classList.add("in");
    }, 200);

    const obs = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          e.target.classList.toggle("in", e.isIntersecting);
        }
      },
      { threshold: 0.2, rootMargin: "0px 0px -60px 0px" },
    );

    document.querySelectorAll(".editorial").forEach((el) => obs.observe(el));

    // Smooth-scroll for in-page anchors
    const onAnchorClick = (e: Event) => {
      const a = (e.target as HTMLElement).closest<HTMLAnchorElement>(
        'a[href^="#"]',
      );
      if (!a) return;
      const id = a.getAttribute("href");
      if (!id || id.length <= 1) return;
      const target = document.querySelector(id);
      if (!target) return;
      e.preventDefault();
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    };
    document.addEventListener("click", onAnchorClick);

    return () => {
      window.clearTimeout(heroTimer);
      obs.disconnect();
      document.removeEventListener("click", onAnchorClick);
    };
  }, []);

  return null;
}
