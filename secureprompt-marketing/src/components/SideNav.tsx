"use client";

import { useEffect, useRef } from "react";

const links: { href: string; num: string; label: string }[] = [
  { href: "#problem", num: "01", label: "problem" },
  { href: "#platform", num: "02", label: "platform" },
  { href: "#mechanics", num: "03", label: "mechanics" },
  { href: "#onprem", num: "04", label: "on-prem" },
  { href: "#audience", num: "05", label: "who" },
];

export function SideNav() {
  const ref = useRef<HTMLElement | null>(null);

  useEffect(() => {
    const root = ref.current;
    if (!root) return;
    const linkEls = Array.from(
      root.querySelectorAll<HTMLAnchorElement>(".sn-link"),
    );
    const sections = linkEls
      .map((a) => document.querySelector(a.getAttribute("href") ?? ""))
      .filter((n): n is HTMLElement => Boolean(n));

    const onScroll = () => {
      const mid = window.scrollY + window.innerHeight * 0.4;
      let current = "";
      sections.forEach((s) => {
        if (s.offsetTop <= mid) current = `#${s.id}`;
      });
      linkEls.forEach((a) => {
        a.classList.toggle("active", a.getAttribute("href") === current);
      });
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <nav className="sidenav" aria-label="primary" ref={ref}>
      <a className="sn-logo" href="#top" aria-label="SecurePrompt">
        <svg viewBox="0 0 64 64" fill="none">
          <defs>
            <linearGradient
              id="hg-side"
              x1="0"
              y1="0"
              x2="64"
              y2="64"
              gradientUnits="userSpaceOnUse"
            >
              <stop offset="0" stopColor="#ff1a28" />
              <stop offset="1" stopColor="#b00010" />
            </linearGradient>
          </defs>
          <path d="M32 4 L56 18 L56 46 L32 60 L8 46 L8 18 Z" fill="url(#hg-side)" />
          <path
            d="M32 12 L48 21 L48 43 L32 52 L16 43 L16 21 Z"
            fill="rgba(0,0,0,0.3)"
          />
        </svg>
      </a>
      <div className="sn-links">
        {links.map((l) => (
          <a key={l.href} className="sn-link" href={l.href} data-num={l.num}>
            {l.label}
          </a>
        ))}
      </div>
      <a className="sn-cta" href="#talk" title="Talk to us">
        ↗
      </a>
    </nav>
  );
}
