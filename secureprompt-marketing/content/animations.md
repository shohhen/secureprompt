# SecurePrompt — Marketing Site Animation Spec

> **Source of truth.** This documents the motion system **as actually shipped** in `secureprompt-marketing/`. The behavior lives in `src/app/globals.css` + `src/app/scenes.css` (keyframes + transitions) and a handful of small `"use client"` components. If this doc and the code disagree, the code wins.

The site is a **"follow one request" narrative that animates on scroll**. The visitor watches a single support prompt — full of a customer's PII — travel from a laptop into the gateway, get inspected and tokenized, reach a model, and come back as one audit row. The dominant motion is **type that rises into place** (headlines), and each section carries one focused scene that visualizes what the gateway does. The language is consistent: **crisp, type-led, matte. No particles, no 3D, no canvas.**

Page order (from `app/page.tsx`): **SideNav · Marquee · Hero · Leak · Gateway · Inside · Proof · OnPrem · FinalCTA · Footer · EditorialObserver**.

---

## 1. Tech stack (what's actually used)

| Layer | Tool | Notes |
|---|---|---|
| Framework | **Next.js 16 (App Router) + React 19** | Server components by default; motion lives in small client islands. |
| Styling | **Tailwind v4** (`@import "tailwindcss"`) + hand-written CSS in `globals.css` and `scenes.css` | All keyframes/transitions are plain CSS. |
| Fonts | **`next/font/google`** (Inter, JetBrains Mono, Instrument Serif, VT323, Silkscreen) | `display: swap`, exposed as `--font-*` variables. |
| Scroll | **Native browser scroll** | No smooth-scroll library. In-page anchor clicks use `scrollIntoView({ behavior: "smooth" })`. |
| Scroll-driven motion | **Plain `IntersectionObserver` + `scroll` listeners + `requestAnimationFrame`** in the section components | No GSAP, no ScrollTrigger, no Lenis. |
| Component motion | **CSS transitions/keyframes + imperative ref updates** | No `motion`/Framer Motion, no Lottie. |

**Deliberately not used:** GSAP, ScrollTrigger, Lenis, Three.js, Canvas, Framer Motion, Lottie. The whole system is CSS plus a few small effects components. This keeps the bundle small and the page fast.

### The motion components

Each scene is its own `"use client"` component that drives a looping or scrubbed animation imperatively through refs, started/stopped by an `IntersectionObserver` so nothing animates off-screen.

| Component | File | What it does |
|---|---|---|
| `EditorialObserver` | `components/EditorialObserver.tsx` | One global `IntersectionObserver` that toggles `.in` on every `.editorial` block (bidirectional). Also raises `#hero-title` ~200ms after mount and wires smooth-scroll for `#` anchors. |
| `Leak` | `components/sections/Leak.tsx` | A packet (`Alice · 4242…`) travels laptop → network edge → vendor's logs; the boundary reddens, the vendor highlights, "audit trail — nothing —" appears. Loops every 4.4s while in view. |
| `Gateway` | `components/sections/Gateway.tsx` | The **scroll-scrubbed** centerpiece: a 600vh sticky scene whose scroll progress maps to one of 7 pipeline steps. Drives the tracer packet, fill, payload chip, and caption. |
| `RedactionCard` | `components/sections/RedactionCard.tsx` | The three PII spans tokenize one-by-one (`Alice Chen → {{Person_1}}`, …), then reset and loop while in view. |
| `InjectionMeter` | `components/sections/InjectionMeter.tsx` | A score animates (via `requestAnimationFrame`) toward the `0.99` block threshold, cycling a blocked attempt (0.99) and an allowed request (0.06); verdict badge resolves. |
| `Proof` | `components/sections/Proof.tsx` | Audit-log rows stagger in (`.audit-line` → `.show`) and replay on an interval while visible. |
| `OnPrem` | `components/sections/OnPrem.tsx` | A packet cycles apps → secureprompt (checked & logged) → cloud → secureprompt (pii restored) on a 1.9s interval while in view, inside the dashed network boundary. |
| `SideNav` | `components/SideNav.tsx` | A `scroll` scroll-spy that lights the active rail link (`#leak #gateway #inside #proof #onprem`). |

---

## 2. Motion tokens (as implemented)

There's no formal token block; these are the values that recur. If you add motion, reuse them.

### Easing

```css
/* House curve — snappy "out" for every type reveal + the modal */
cubic-bezier(0.2, 0.9, 0.25, 1)

/* Transport curve — for packets, fills, and meter motion in the scenes */
cubic-bezier(0.4, 0, 0.2, 1)
```

The **house curve** drives the hero/editorial word reveals and the contact-modal slide-up. The **transport curve** drives the moving parts in the scenes (Leak packet, Gateway packet/fill, OnPrem packet). Continuous loops use `linear` (marquee) or `ease-in-out` (scroll-cue bob, perimeter glow pulse, blink).

### Durations that recur

| Duration | Where |
|---|---|
| `200ms` | Hover color/border/background (buttons, links, nav, hero-cta-secondary) |
| `300ms` | Leak boundary/vendor, pipeline dot/label state, redaction token swap, meter fill, perimeter label |
| `320ms` | Audit-row entrance (`opacity` + `translateX`) |
| `700ms` | Gateway packet + fill transition (transport curve) |
| `1000ms` | Editorial headline word reveal |
| `1100ms` | Hero word reveal · OnPrem perimeter packet hop |
| `1300ms` | Injection meter score animation (rAF) |
| `1600ms` | Leak packet travel across the edge |
| `1900ms` | OnPrem perimeter cycle interval |
| `2.2s` | Scroll-cue bob (continuous) |
| `3.4s` | Perimeter inner glow pulse (continuous) |
| `4.4s` | Leak loop interval |
| `40s` | Marquee scroll (continuous) |

Continuous loops (marquee, bob, glow, blink) are infinite CSS keyframes; everything else is a one-shot transition or a JS-timed step gated by an observer.

---

## 3. The signature move — type that rises (`.editorial` / `.hero-title`)

The page's primary animation — every headline and the hero.

**Markup pattern**

```html
<h2 class="editorial">
  <span class="row">
    <span class="word">we</span>
    <span class="word delay-1 accent">show</span>
    <span class="word delay-2">our</span>
    <span class="word delay-3">work.</span>
  </span>
</h2>
```

**Mechanics**

- Each `.row` is `overflow: hidden` (the clipping mask / press bed).
- Each `.word` starts at `transform: translateY(110%)` (hidden below the mask).
- When the block gets `.in`, words slide to `translateY(0)` over **1000ms** (`.editorial`) / **1100ms** (`.hero-title`), house curve.
- Stagger is per-word via `.delay-1 … .delay-6` (80ms → 480ms) on editorial, and `nth-child` (80/160/240/320ms) on the hero.
- `.accent` words are red; `.ital` words render as **skewed red VT323** — and `scenes.css` preserves that `skewX(-10deg)` through the rise (`translateY(110%) skewX(-10deg)` → `translateY(0) skewX(-10deg)`); `.underline` adds a red underline.

**Triggering (`EditorialObserver`)**

- Mounts once at the layout root. A single `IntersectionObserver` (`threshold: 0.2`, `rootMargin: 0px 0px -60px 0px`) toggles `.in` on **every** `.editorial` element. It is **bidirectional** — words rise on scroll-down and sink back on scroll-up.
- The hero (`#hero-title`) is **not** observed; it's special-cased to receive `.in` ~200ms after mount, so it animates on load and never sinks.
- All in-page `a[href^="#"]` clicks are intercepted for smooth-scroll.
- Under reduced motion the observer short-circuits: it adds `.in` to every `.editorial` / `.hero-title` immediately and registers nothing.

---

## 4. Section-by-section choreography

### Marquee (top ticker)
CSS `sp-scrollx` (`translateX(0 → -50%)`), **40s linear infinite**. The item list is duplicated in markup so the translate loops seamlessly. Accent items are red; the rest muted.

### Hero `#top`
- Eyebrow + `.hero-title` word-rise on mount: *"see every prompt your team sends to `ai` before it `leaves.`"* (`ai` = skewed red VT323, `leaves.` = red underline).
- `.hero-actions`: three static mono pills + an outline `talk to us ↗` CTA.
- `.scroll-cue` at the bottom: a `↓` (`.arrow`) with the `sp-bob` keyframe (`translateY 0 → 5px`, **2.2s ease-in-out infinite**) above the text *"scroll to follow one request"*.

### 01 · Leak `#leak`
Headline *"someone pastes a customer into the chat. where does it go?"* rises. Below, a `.leak-card` shows the support message with PII highlighted, then a `.leak-stage`: a packet leaves `your laptop`, crosses the dashed `network edge` to `vendor's logs`; at ~720ms the boundary turns red, at ~1500ms the vendor reddens, at ~1850ms the audit trail reads "— nothing —". Resets and loops every **4.4s** while in view (`IntersectionObserver`, packet `left` transition **1600ms**, transport curve).

### 02 · Gateway `#gateway` — the scroll-scrubbed scene
The centerpiece. The outer `.gw-scene` is **600vh** tall; the `.gw-sticky` card pins (`position: sticky; top: 0`) while you scroll through it. A passive `scroll` listener maps progress to one of **7 steps** mapped to nodes `in · auth · redact · scan · policy · send · log`. Per step it moves the tracer `.pl-packet` to the node center (measured via `getBoundingClientRect`), grows the `.pl-fill`, recolors the dots (`done` = red outline, `active` = red fill, scale 1.1), and swaps the payload chip + caption (e.g. step 3 → `{{Person_1}} · {{Card_1}}` / "pii swapped for placeholders — the model never sees alice"). Packet/fill use the transport curve over **700ms**.

### 03 · Inside `#inside`
Headline *"we show our work."* rises. A responsive `.scene-grid` holds two live cards:
- **`RedactionCard`** — the prompt's three PII spans tokenize in turn (`Alice Chen → {{Person_1}}`, email → `{{Email_1}}`, card → `{{Card_1}}`), each with a brief `scale(1.1)` pop, then resets after 2.8s and loops.
- **`InjectionMeter`** — the score animates (rAF, **1300ms**) toward the `0.99` threshold marker; a blocked attempt fills to 0.99 (verdict "blocked", red), an allowed request to 0.06 (verdict "allowed"); the two scenarios cycle.

### 04 · Proof `#proof`
Headline *"now you can answer the auditor."* rises. The `.audit-demo` log writes itself: each `.audit-line` gets `.show` staggered by **120ms** (`opacity 0 → 1` + `translateX(-8px) → 0`, 320ms), and replays on an interval (`lines × 120ms + 4200ms`) while visible. Corner label `// audit_log :: req_8c2f3a91 :: live`; `.ok` values are red.

### 05 · OnPrem `#onprem`
Headline *"your data never leaves your network."* rises. A `.perim` diagram: a dashed red boundary (`your network · your hardware`, with a pulsing inner glow) holds `your apps` and `secureprompt`; an arrow ("tokenized only") points out to `cloud ai models`. A `.perim-packet` cycles apps → secureprompt ("checked & logged") → cloud → secureprompt ("original pii restored") on a **1.9s** interval while in view (hop transition **1100ms**, transport curve). A `✕` bullet blinks (`sp-blink`, 1.8s).

### 06 · FinalCTA `#talk`
Headline *"you'd `build` it yourself. now you don't have to."* rises (`build` = skewed red VT323). A single outline red pill CTA `talk to us →`.

### SideNav (persistent)
Scroll-spy: on each scroll the active section is the last one whose `offsetTop ≤ scrollY + 0.4 × viewportHeight`; that rail link goes red. Hover transitions color over 200ms.

---

## 5. Micro-interactions

| Element | Effect |
|---|---|
| **Outline CTA** (`.talk-btn-outline`, + `.pill` on the final CTA) | Transparent red-bordered button; hover fills red with `--color-ink-on-accent` text (200ms). |
| **Secondary hero link** (`.hero-cta-secondary`) | Muted text with a hairline underline; hover → red (200ms). |
| **Nav rail** (`.sn-link`) | Color → fg on hover, → red when `.active`. |
| **PII span** (`.pii`) | Raw red-tint → token (`{{…}}`) in JetBrains Mono with a `scale(1.1)` pop (RedactionCard). |
| **Verdict badge** (`.verdict`) | "scanning…" → "blocked" (red fill) / "allowed" (outline) over 240ms (InjectionMeter). |
| **Pipeline node** (`.pl-dot` / `.pl-lbl`) | done/active/upcoming color + scale states over 300ms (Gateway). |
| **Contact modal** | Overlay `fadeIn` (200ms); content `slideUp` (`translateY(20px) → 0`, 300ms, house curve); submit button `spin` loader. |

---

## 6. Reduced motion

`@media (prefers-reduced-motion: reduce)` is honored as a contract:

- A global rule forces **all** `animation-duration` / `transition-duration` to `0.01ms`; `scenes.css` also disables the continuous loops (bob, glow pulse, blink).
- `.hero-title .word` and `.editorial .word` get `transform: none` (no rise — text is simply present).
- `EditorialObserver` short-circuits: it adds `.in` to every `.editorial` / `.hero-title` immediately and registers no observer or handlers.
- Each scene component checks `matchMedia('(prefers-reduced-motion: reduce)')` and renders a meaningful **final** frame instead of looping: Leak shows the packet arrived at the vendor with "— nothing —"; Gateway renders the last pipeline step; RedactionCard shows everything tokenized; InjectionMeter shows the blocked verdict; Proof shows all rows; OnPrem rests at "checked & logged".

Net effect: the page is fully readable and complete, just static.

---

## 7. Performance notes

The motion system is cheap by construction:

- **CSS on the hot paths.** Reveals animate `transform` + `opacity`; hovers animate `color` / `background` / `border`. Scene packets move via `transform`; the Gateway fill animates `width` (a short, throttled, one-per-step transition).
- **Observer-gated loops.** Every looping scene (`Leak`, `RedactionCard`, `InjectionMeter`, `Proof`, `OnPrem`) starts its `setInterval` / `requestAnimationFrame` / timeout chain **only while in view** and tears it down on exit — nothing runs off-screen.
- **Native scroll**, passive listeners. The Gateway scrubber and SideNav scroll-spy read layout in a `scroll` handler; the only always-on motion is CSS keyframes (marquee, bob, glow, blink).
- **Small JS, mostly server-rendered.** No animation libraries in the bundle. `next/font` with `display: swap` — type never blocks paint.

### If you add motion

- Reuse the house curve `cubic-bezier(0.2, 0.9, 0.25, 1)` (reveals) or transport curve `cubic-bezier(0.4, 0, 0.2, 1)` (moving parts), and the durations in §2.
- Prefer `transform` / `opacity` / color. Gate any loop behind an `IntersectionObserver` and tear it down on exit.
- Add a `prefers-reduced-motion` final-state fallback in the same change.
- Keep it type-led and matte. No glows on type, no shadows, no parallax on text, no canvas. One dominant motion per section.
