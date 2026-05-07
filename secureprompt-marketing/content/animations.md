# SecurePrompt — Marketing Site Animation & Scroll Spec

A high-end product page for an AI security gateway should feel like a **signal traversing a network** — controlled, instrumented, and reactive to the visitor's input. Every animation on this page is metaphorically tied to what the product does: traffic flowing into an inspection point, sensitive content being identified and replaced, decisions being logged, responses returning sanitized.

This document defines the full motion system: tech stack, principles, the hero scene, every scroll-pinned section, micro-interactions, performance budget, and the reduced-motion fallback path.

---

## 1. Principles

### Motion language

| Principle | What it means here |
|---|---|
| **Signal, not decoration** | Every animation visualizes something the product actually does. No purely aesthetic motion. If a viewer asks "why is that moving?", the answer is always a product concept. |
| **Cause-and-effect** | Scroll input maps directly to a visible transformation in the same frame. No delays between input and response — the page should feel as responsive as a NOC console. |
| **One motion per scene** | Each section has one dominant motion at any moment. Nothing competes for attention. Sub-motions are sub-200ms and feel like consequences of the dominant one. |
| **Steady state, not loops** | Long-running animations (hero packet flow, ambient grid pulse) are continuous, not loops. Looping animations announce themselves; steady-state ones recede. |
| **Respect the request** | `prefers-reduced-motion: reduce` disables every continuous animation and converts all scroll-driven scenes to instant fade-in. Detailed in §7. |

### Easing tokens

These are the only curves used on the site. Naming them removes per-component bikeshedding.

```css
--ease-signal:  cubic-bezier(0.16, 1, 0.3, 1);     /* "out-expo" — incoming traffic, snappy reveals */
--ease-decision: cubic-bezier(0.65, 0, 0.35, 1);    /* "in-out-cubic" — policy decisions, balanced */
--ease-restore: cubic-bezier(0.34, 1.56, 0.64, 1); /* "back-out" — placeholder→original restoration overshoot */
--ease-deny:    cubic-bezier(0.55, 0, 1, 0.45);    /* "in-quint" — abrupt halt for blocked traffic */
--ease-ambient: cubic-bezier(0.45, 0, 0.55, 1);    /* "in-out-sine" — background grid, idle pulses */
```

### Duration tokens

```css
--dur-instant: 90ms;    /* Button press, focus ring */
--dur-quick:   180ms;   /* Hover state, badge swap */
--dur-base:    280ms;   /* Card lift, inline reveals */
--dur-scene:   600ms;   /* Section entry, stat counters */
--dur-cinema:  1200ms;  /* Hero element entry, big number reveals */
```

Anything longer than `--dur-cinema` is a continuous animation, not a transition.

---

## 2. Tech stack

| Layer | Library | Why |
|---|---|---|
| Smooth scroll baseline | **Lenis** | Replaces native browser scroll with a lerp'd virtual scroll position. Without it, scroll-pinned sections judder on trackpad and feel like 2018. With it, the entire page becomes one continuous timeline. |
| Scroll-driven animation | **GSAP + ScrollTrigger** | Best-in-class for pinned sections, scrubbable timelines, and "scroll = playhead" mechanics. Framer/motion is fine for in-view reveals but ScrollTrigger is the right tool for the workflow scrubber and the section-pin sequences described below. |
| Component-level motion | **motion** (formerly Framer Motion) | Used for entrance reveals on cards, micro-interactions, and orchestration of sequential reveals via the variant system. |
| Hero canvas scene | **Custom Canvas 2D** (no Three.js) | The hero is a 2D node-graph + particle simulation. Three.js would overspec it and add ~150KB. A 6KB Canvas implementation hits 60fps on integrated GPUs. WebGL is reserved for if/when we add a 3D globe later. |
| Number rollups | **motion `useTransform` + `animate`** | Rolling counters for "redacted entities", "policy violations caught", etc. |
| Code-typing effect | **Custom hook** | A 50-line `useTypewriter` that respects reduced-motion and supports cancel/restart. No external dep. |

**No Lottie.** Every "Lottie" we'd use can be done in 30 lines of motion or CSS, and Lottie's runtime is heavier than the rest of the page combined.

---

## 3. Hero scene — "Signal Through the Gateway"

The hero is the page's centerpiece. It runs from page load and continues animating until the user scrolls past 100vh, at which point it freezes (ScrollTrigger pauses the canvas loop).

### Visual composition

```
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│   [client]                                                  [GPT model]  │
│      ●────────╮                                          ╭────────●      │
│   [agent]      │                                         │     [Claude]  │
│      ●─────────┤              ╔══════════╗               ├────────●      │
│   [browser]    ├─────────────▶║ HEXAGON  ║──────────────▶│     [Gemini]  │
│      ●─────────┤              ║  ⬡⬢⬡    ║               ├────────●      │
│   [desktop]    │              ╚══════════╝               │  [Llama-self] │
│      ●─────────╯                                         ╰────────●      │
│                                                                          │
│    ← inbound packets converge       outbound packets diverge →          │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

- Background: slate-950 (`#020617`) with a faint orthogonal grid (slate-800 `#1E293B` at 4% opacity, 32px cell size). The grid has a single radial mask centered on the hexagon so cells closer to center are slightly more visible — visually weights the eye toward the inspection point.
- Four client glyphs anchored on the left edge, four upstream-provider glyphs on the right.
- The SecurePrompt hexagon (cyan gradient `#22D3EE → #0891B2`, 96px diameter) at center.
- Particles flow along curved bezier paths from clients → hexagon → providers, and a return path provider → hexagon → client.

### Particle behavior

```ts
type Packet = {
  id: number;
  origin: ClientNode;
  destination: ProviderNode;
  state: 'inbound' | 'inspecting' | 'forwarded' | 'returning' | 'restored' | 'denied';
  position: vec2;        // current xy
  bezier: [vec2, vec2, vec2, vec2];  // cubic bezier control points
  t: number;             // 0..1 along bezier
  speed: number;         // 0.0008–0.0015 per frame (varied for life)
  hue: 'cyan' | 'amber' | 'red';     // amber while in vault, red when denied
  containsPii: boolean;
};
```

**Lifecycle of a single packet** (~3.5–4.5s end-to-end):

1. **Spawn** at a client glyph with state `inbound`, `hue = cyan`, `containsPii = random()<0.35`. Bezier path arcs into the hexagon; control points generate a slight S-curve so paths from neighboring clients don't lay perfectly on top of each other.
2. **Inbound** — position lerps along bezier. Trailing afterimage rendered with 6 historical positions, alpha-decayed, simulating packet streak. Duration `~700ms` to reach the hexagon.
3. **Inspecting** — once `t >= 1`, packet snaps to hexagon center and enters a 280ms inspection mini-state:
   - If `containsPii`: a small amber chip detaches from the packet at offset `(rand(-12,12), rand(-12,12))px`, shrinks into the hexagon over 180ms (visual: PII pulled into the vault). Main packet shifts slightly (signifies redaction). Easing: `--ease-decision`.
   - Roll a `denyChance = 0.05`. If denied: packet pulses red (`#EF4444`), 280ms ease `--ease-deny`, then accelerates back along its inbound path with state `denied`. Stops before reaching the client and dissolves. **Important:** this happens roughly once every 20 packets — denials are visible but rare. The page reads as "the gateway works", not "the gateway constantly blocks".
4. **Forwarded** — if not denied, packet leaves the hexagon along a fresh bezier toward a randomly chosen provider node. State `forwarded`, hue stays cyan but with a subtle amber inner core if it had PII (visual: token fragment substituted in). Duration `~700ms`.
5. **Returning** — particle reaches provider, flips, and travels back along a parallel bezier offset by `(0, -8px)`. State `returning`, hue cyan. Duration `~700ms`.
6. **Restoration** — second pass through hexagon. If the original `containsPii` was true, the amber chip that was earlier sucked in flies out and rejoins the packet (180ms, ease `--ease-restore` — overshoots then settles). Visual reads as "placeholder restored".
7. **Final delivery** — packet returns to its origin client and dissolves over 120ms.

### Density and tempo

- Spawn rate: **6 packets/second** at peak. Phasing-in: ramp from 0 → 6 over the first 1.6 seconds after page mount. Provides visual "warm-up".
- Total live packets at steady state: **20–28**. Beyond that, the canvas reads as noise. Hard cap at 32 to bound CPU.
- Packets are spawned using a weighted distribution favoring the bottom-left clients early in the page lifetime, then equalizing — gives a subtle "first impression" that the page is starting from one source and growing.

### The hexagon itself

- **Idle state**: gradient fill, gentle inner glow that pulses on `--ease-ambient` over 3.4s (`box-shadow: 0 0 60px rgba(34, 211, 238, 0.18)` peaking at 0.28 then back).
- **On packet inspection**: micro-jitter — translate `(0, ±0.5px)` over 60ms — so the hexagon visibly "registers" each request. Capped at 5Hz so it never strobes.
- **On denial**: outer ring flashes red over 240ms, then returns. Synchronous with the packet's red pulse.

### Hero typography overlay

The wordmark **"SecurePrompt"** sits over the canvas at `top: 18%`, centered horizontally. Below it, the tagline:

> The security gateway for the AI-native enterprise.

Reveal sequence on initial mount:

1. `t=0ms`: page is blank slate-950. Canvas is initialized but no particles yet.
2. `t=120ms`: ambient grid fades in over 480ms (`--ease-ambient`).
3. `t=600ms`: hexagon scales from 0 to 1 with `--ease-restore` (back-out). Subtle overshoot makes it land confidently. Duration 700ms.
4. `t=900ms`: client and provider glyphs fade in left-to-right, staggered by 80ms each (4 clients = 320ms total). At the same start time, the inverse stagger runs on the right.
5. `t=1300ms`: first inbound packet spawns. Spawn rate ramps as described.
6. `t=1300ms`: wordmark fades in (`--dur-cinema`, `--ease-signal`) with a slight upward translation (`translateY(8px → 0)`).
7. `t=1900ms`: tagline fades in (`--dur-scene`, `--ease-signal`).
8. `t=2400ms`: primary CTA button enters from below (`translateY(16px → 0)` + opacity, `--dur-scene`, `--ease-signal`).

Total cinematic intro: ~3 seconds. Visitors who scroll early get an interrupted-but-graceful intro — ScrollTrigger checks scroll position on every frame and snaps remaining intro elements to their final state if `scrollY > 80px`.

---

## 4. Section-by-section scroll choreography

The page is structured as **eight scroll scenes**, with section 5 (Workflow) being a pinned scrubber and the rest using progressive in-view reveals. Total document height: **~700vh**.

### Section 1 — Hero (0vh → 100vh)

Behavior already specified in §3. As the user begins to scroll past `0.85 * vh`, the canvas begins to compress vertically (`scaleY: 1 → 0.6`) and fade (`opacity 1 → 0`). At `1.0vh` the canvas is hidden and its render loop is paused (saves CPU for the rest of the page).

The hexagon detaches from the canvas at `0.7vh` and enters a "shrinking" sub-animation: it scales to 24px and translates to the top-left of the next section, where it becomes a persistent indicator that "you are inside the gateway." This anchor stays fixed at the top-left of the viewport for sections 2–7 and animates out in section 8.

### Section 2 — The Problem (100vh → 180vh)

**Concept**: scattered chaos collapsing into a single inspection point — visualizes the value prop "one gateway, every integration".

Mechanics:

- Section is `min-height: 80vh`. Pinned for the duration via ScrollTrigger.
- 24 small "logo chips" (representing internal teams' AI integrations: marketing chatbot, sales tool, HR copilot, customer support, etc.) are placed at randomized positions across a 60vw × 60vh region.
- At `progress = 0`, chips are scattered. Each has a small dotted line trying to reach an offscreen "LLM" icon — illustrating chaos.
- As `progress` advances 0 → 1:
  - Chips lerp along a bezier toward a single funnel point at the right edge.
  - Their dotted lines fade and are replaced by a single solid cyan line entering from the funnel.
  - The funnel resolves into a stylized hexagon icon at `progress >= 0.85`.
- Headline (`The problem`) and copy fade in alongside, with the chips finishing their convergence as the bottom paragraph completes its reveal.

Easing: chip lerp uses `--ease-decision`. Headline fade uses `--ease-signal`.

### Section 3 — Three Products (180vh → 280vh)

**Concept**: three cards revealed with staggered entrance, each carrying a unique micro-animation that demonstrates the product.

- Cards enter via `motion`'s variants:
  - `hidden`: `opacity: 0`, `translateY: 32px`, `scale: 0.96`
  - `shown`: `opacity: 1`, `translateY: 0`, `scale: 1`
  - Stagger: 140ms between cards, beginning when the section's top crosses 65% of viewport.

Per-card micro-animation (runs once when card enters view, loops subtly on hover):

- **Gateway card** — A representation of an HTTP request URL types itself character by character at 28ms/char:
  ```
  POST https://gateway.your-co.internal/v1/chat/completions
  ```
  Once typed, the cursor blinks 3 times, then the URL crossfades into a pretty-printed JSON request body. On hover, the JSON's `messages` field has its content tokenized live: text strings have `{{Person_1}}`, `{{Email_Address_1}}` substitutions visibly swap in over 1.6s. Reverse on hover-out.
- **Chat card** — Three chat bubbles appear in sequence:
  1. User bubble (right-aligned, slate-800 surface): "Send this contract to alice@bigco.com" — types in over 800ms.
  2. The text re-paints itself with `alice@bigco.com` replaced by `{{Email_Address_1}}` (each character swap is a 40ms color-flash to amber, then settle to brand-cyan). Total 480ms.
  3. AI bubble (left-aligned, slate-700 surface): "Sure, sending the contract to alice@bigco.com now." — types in. Notice: the response shown to the user already has the email **restored** (placeholder → original). A small footer caption reads "PII tokenized upstream, restored on return".
- **Console card** — A miniature dashboard mockup:
  - A horizontal bar chart (4 bars) draws left-to-right with `--ease-decision` over 800ms, staggered by 120ms.
  - Below, three audit-row badges flicker in: `allow` (success-green), `redact` (brand-cyan), `deny` (destructive-red), each appearing with a `scale: 0.6 → 1` + opacity fade.
  - Hover: a hairline brand-cyan vertical line scrubs across the bar chart, simulating "selecting a time range". Bars below the cursor grow 1.05x with a 120ms transition.

### Section 4 — Why this is different (280vh → 460vh)

The four sub-sections are presented as **horizontally scrubbed mini-scenes**. Each sub-section is `min-height: 45vh` and uses a slim ScrollTrigger range to animate one focused mechanic.

#### 4a. PII redaction that actually works

A single sentence is rendered in monospace at large size:

> Hi, my name is Alice Johnson, my email is alice@bigco.com, and my card 4242-4242-4242-4242 expires 04/27.

As scroll progresses through this sub-section's range:

- **0% → 25%**: a horizontal cyan "scanner" line moves left-to-right across the sentence at the same vertical level. As it passes each PII span, that span's underline glows brand-cyan for 200ms then fades.
- **25% → 60%**: each detected span is replaced by its placeholder, **with a flip animation**: the span's text rotates `rotateY` from 0° to 90°, the placeholder rotates from -90° to 0°, total 280ms per span. Spans flip in source order, staggered by 140ms. Easing `--ease-restore`.
- **60% → 100%**: the now-tokenized sentence visually slides upward into a stylized "to upstream" pipe. A second line appears below, in cyan: "The model never sees Alice's data."

Reverse on scroll-up — restore the sentence by reversing the flip sequence, useful for visitors who scrub.

#### 4b. Prompt injection — realistic tradeoffs

A horizontal axis labeled "Confidence" runs left to right (0.0 → 1.0). A vertical dashed line marks the threshold at 0.99 — labeled "Block threshold".

A "ball" (small filled cyan circle, 10px) bounces along the axis, randomly placed each cycle. As scroll progresses:

- **0% → 40%**: the ball does 3 representative jumps to scores 0.32, 0.61, 0.84 — all below threshold. Each jump 260ms, hold 240ms, ease `--ease-decision`. Above each landing, a small audit-row materializes: `flag · score 0.32 · allow`, `flag · 0.61 · allow`, `flag · 0.84 · allow`. Three rows accumulate in a stack on the right.
- **40% → 80%**: a fourth jump to 0.992 — past the threshold. The ball flashes red, an angry buzzer pulse on the threshold line. Audit row appears: `block · score 0.992 · deny`.
- **80% → 100%**: a small caption fades in below: "Genuine attempts score 0.99+. Meta-prompts and templating live below. We block precisely, not eagerly."

#### 4c. Per-request token economics

Three counters are arranged in a row:
- `Estimate`: fast char-count approximation
- `Actual`: input + output reported by upstream
- `Reconciled`: final bookkeeping

Scroll progress drives the counters in sequence:

- **0% → 33%**: Estimate counter rolls from 0 → 247 over 1.4s. Below it, a subtitle types: "Charged before the call".
- **33% → 66%**: Actual counter rolls from 0 → 211 (smaller than estimate). Subtitle: "Reported by the provider".
- **66% → 100%**: Reconciled counter shows "−36" briefly in amber, then settles to "211" in brand-cyan. A subtle dashed arrow connects Estimate → Reconciled. Subtitle: "Counter corrected. Dashboard shows real usage."

The point: **operators see honest numbers**. The counter sequence makes that point in 4 seconds without explaining how Postgres works.

#### 4d. Latency you can act on

Two miniature "stopwatches" (animated SVG circular gauges):

- **TTFT** stopwatch: fills from 0 to 318ms over 1.0s as scroll progresses. Cyan stroke. Label: "Upstream model started responding".
- **Gateway overhead** stopwatch: fills from 0 to 18ms over 1.0s, in parallel. Brand-cyan-light stroke. Label: "Our pre-flight work".

Below: a single sentence types in: "When chat is slow, you know exactly which one it is."

### Section 5 — Workflow (460vh → 580vh) — **Pinned Scrubber**

This is the centerpiece scroll mechanic. The 11-step gateway lifecycle is rendered as a horizontal timeline. The section is **pinned for 120vh of scroll**, meaning the user scrolls 120% of viewport height while the section stays fixed and only the diagram advances.

Mechanics:

- 11 station nodes placed along a horizontal cyan rail at `y = 50%`. Each station is a labeled hexagon (label text below).
- A single "tracer" packet enters from the left at `progress = 0`. As scroll advances:
  - **0% → 91%**: tracer position lerps station-to-station. At each station crossing, the station node fills with brand-cyan, the prior station's fill softens to brand-700.
  - The label of the active station appears in a fixed text panel below the rail (replaces the previous label with a vertical-flip animation, 240ms).
  - For stations with sub-actions (Detect, Tokenize, Restore), a tiny secondary chip (`{{Person_1}}`, `412.32 tokens`, etc.) flies out from the node and lands in a side panel that accumulates over the scrub.
  - **91% → 100%**: tracer exits to the right toward an upstream provider glyph; immediately a return tracer enters from the right and walks back through stations 8–11.

- The accumulated side panel by the end of the scrub looks like a real audit row: `request_id`, `redacted prompt`, `latency_ms`, `cost`, `final_action`. This is the page's payoff — the visitor literally watched a request become an audit log entry.

Scrub UX:

- ScrollTrigger `scrub: 1` (1s catch-up) so the scrub feels weighted, not snappy.
- If user reverses scroll, tracer reverses fluidly. The audit-row builder unbuilds in reverse — chips fly back to their stations.
- A small progress indicator at the top of the section (`Step 4 of 11 · Detect PII`) updates in lockstep.

### Section 6 — On-prem (580vh → 660vh)

**Concept**: data sovereignty visualized as a sealed perimeter.

A large rounded rectangle ("Your Network") is drawn with a slightly luminous cyan border. Inside, four small icons: dashboard, gateway, ML inference, data store.

Outside: three upstream-provider icons (OpenAI, Anthropic, Google), placed on the right.

Animation on enter:

1. The perimeter rectangle's border draws itself in clockwise from the top-left corner over 900ms (`stroke-dasharray` trick). Easing `--ease-decision`.
2. Internal icons fade in with stagger (140ms each).
3. A single arrow exits the rectangle on the right and reaches one upstream provider — labeled "Authorized upstream call".
4. Three "potential leak" arrows attempt to exit at random other points (top, bottom, left) and are interrupted: each one collides with the perimeter, ripples cyan, and dissolves. Sequence runs once on enter, then steady state.

Bullet list on the right reveals with stagger (`--ease-signal`, 200ms apart) — same content as the landing page's on-prem bullets.

### Section 7 — Who this is for (660vh → 700vh)

Five identity cards (Security, Platform Eng, Regulated Industries, On-prem mandates, Self-hosted models). Cards stack diagonally with subtle 3D depth (`perspective: 1200px`, each card rotated `rotateX: 6deg, rotateY: -4deg` and offset down-right by 12px from the previous).

On scroll into view, cards animate from a gathered stack (all overlapping at center) into their fanned positions, with overlap on the back-left fading to 20% opacity. Total animation 1.1s, staggered 80ms per card, ease `--ease-decision`.

Hover on any card lifts it forward (`translateZ: 24px`) and dims the others to 40% opacity.

### Section 8 — CTA (700vh → end)

The page closes on a single CTA: "Talk to us." The button has a continuous breathing pulse (subtle `box-shadow` scale, 4s cycle, ease `--ease-ambient`).

Above the button, the same hexagon from the hero re-emerges (since section 1) and animates from its top-left anchor into a centered position with a sweep — the visual loop closes. The hexagon expands back to its original 96px size and rejoins the wordmark, which has been hidden since section 2.

Sub-text: a small "© SecurePrompt" footer with subtle cyan-on-slate links.

---

## 5. Micro-interactions inventory

These are the building blocks reused across the page.

### Buttons

| State | Effect |
|---|---|
| **Default** | Brand-500 fill, white text, subtle inner highlight (`inset 0 1px 0 rgba(255,255,255,0.08)`) |
| **Hover** | Background fill transitions to brand-400 over `--dur-quick`. A 1px brand-300 glow ring expands from the button by 4px and fades over 320ms — visualizes "outgoing signal" |
| **Active** | Scale `0.97` for 90ms with `--ease-decision`. Inner highlight inverts briefly. |
| **Focus-visible** | 2px brand-400 outline at 2px offset, no fill change. |
| **Disabled** | `opacity: 0.4`, no hover, cursor `not-allowed` |

### Links

Underline is a pseudo-element scaled from `0 → 100%` left-to-right on hover (`--ease-signal`, `--dur-quick`). On unhover the underline scales back to 0 from the right, creating a "swept" feel that doesn't reverse the original direction — same metaphor as a packet leaving.

### Card hover

Cards lift `translateY: -4px` over `--dur-base`, border transitions from slate-800 to brand-400@30% opacity. The card's inner content does NOT shift; only the card frame moves. Avoids the cheap "everything wiggles" feel.

### Code-block reveal on view

When a code block enters viewport, its lines reveal from top to bottom with stagger 60ms each, opacity 0 → 1 + slight `translateX(-8px)`. Total 480ms regardless of line count (cap at line 8 — beyond that, lines reveal simultaneously to avoid waiting).

### Number counters

Use `motion`'s `animate(count, target, { duration: 1.6, ease: --ease-decision })` with a `useTransform` that pipes the changing value through a formatter. Always show **trailing zero suppression** for integers, **2 decimal places** for currency. Counters never count down on enter — they always count up from 0 (or from a baseline). Counting down looks like an error.

### Form inputs (contact form in §8)

- Default: 1px slate-700 border, slate-900 fill.
- Focus: border transitions to brand-400, plus a 2px brand-400@20% outer glow expands and stays. Transition `--dur-base`, ease `--ease-signal`.
- Invalid: border destructive-500, label text slides up + tints destructive over 240ms.
- Valid (after blur): a small cyan checkmark fades in at the right edge of the input over 200ms.

---

## 6. Performance budget

Marketing-site visitors are evaluating us partially on perceived performance. A laggy page from a security company is fatal.

| Metric | Target | Measurement |
|---|---|---|
| **First Contentful Paint** | ≤ 1.4s on Fast 3G simulation | Hero typography appears before any animation runs |
| **Largest Contentful Paint** | ≤ 2.4s | Hero canvas fully painted |
| **Cumulative Layout Shift** | < 0.05 | Reserve all dimensions; no late-loading images |
| **Hero canvas FPS** | ≥ 58 fps median on M1 / Ryzen 5800X | Profile in DevTools, log in dev mode |
| **Hero canvas FPS** (mid-range laptop) | ≥ 50 fps median | Tested on integrated graphics; if below 50, drop particle cap to 18 |
| **Total JS** (parsed) | ≤ 280KB gzipped on initial load | Lazy-load Lenis + GSAP. Defer Lottie/heavy libs (we don't ship Lottie) |
| **Long tasks during scroll** | None > 50ms | All scroll-driven work in `requestAnimationFrame`, never in `scroll` event handlers directly |

### Hard rules

- **No `layout`-triggering CSS animations.** Only `transform` and `opacity` on the hot path. `width`/`height`/`top`/`left` animate **never**.
- **`will-change` discipline.** Apply only during the animation, remove on completion. Persistent `will-change` on dozens of elements regresses LCP.
- **Hero canvas pauses when not in viewport.** ScrollTrigger fires `enter`/`leave` events that toggle the canvas's `requestAnimationFrame` loop.
- **Reduced-motion path is the fast path.** Reduced-motion users get instant fades and zero canvas work.
- **Pre-render fonts.** `font-display: swap` already configured. The wordmark uses `Inter SemiBold` which is in the local font pack — never blocks paint.
- **No autoplaying video.** If we ever add a product walkthrough, it's a click-to-play poster image, not autoplay.

---

## 7. Reduced motion

`@media (prefers-reduced-motion: reduce)` is treated as a contract, not a suggestion. The site stays expressive but stops moving on its own.

### What changes

| Element | Default | Reduced |
|---|---|---|
| Hero canvas | Animated particle flow | Single static frame: hexagon centered, 4 dim cyan lines representing "paths" radiating to clients/providers, no motion |
| Section reveals | `opacity 0 → 1 + translateY` over `--dur-scene` | `opacity` only, instant (`--dur-instant`) |
| Workflow scrubber | Pin + scrub | Section unpinned. All 11 stations rendered statically with the audit-row payoff visible from the start |
| Number counters | Roll up over 1.6s | Render final value immediately |
| Card hover lifts | `translateY: -4px` | Border color change only |
| Link underline sweep | Scale 0 → 1 | Underline always present at full width; opacity 0.6 → 1 on hover |
| Hexagon ambient pulse | Continuous box-shadow oscillation | Static glow at the midpoint value |
| Background body gradient (radial cyan glows) | Subtle parallax on scroll | Fixed |

### Detection

- Single source of truth: a `useReducedMotion()` hook that reads the media query and exposes a boolean. All animation components consume it; no scattered `if`s.
- The Lenis smooth-scroll is **disabled** under reduced motion — native scroll is the user's preference there.
- GSAP timelines are wrapped: `if (reduced) tl.progress(1).pause();` snaps to end-state.

### Don't punish reduced-motion users

The reduced-motion variant is **not** a stripped-down ugly fallback. It still uses the cyan/slate brand palette, retains all typography hierarchy, and presents the workflow as a static infographic that's arguably more readable than the scrubbed version. A reviewer running with reduced-motion sees a calmer but equally complete page.

---

## 8. Mobile considerations

### Screen-size breakpoints

- `< 768px` (phone): hero canvas replaced by a static SVG illustration of the hexagon + 2 client paths + 2 provider paths. No scrubbing, no pinning. Workflow section becomes a vertical step list with mini-icons; each step has a small ✓ that pops in on view (single-shot motion, not scroll-scrubbed).
- `768px – 1023px` (tablet): canvas runs at half particle density (12 max). Workflow is pinned but with simplified rail. Other sections behave normally.
- `≥ 1024px` (desktop): full experience.

### Touch-specific

- Pinned scrubber sections feel terrible on iOS Safari with native scroll bouncing. Lenis fixes this; ScrollTrigger pinning is fine when paired with Lenis.
- Hover-only states (card lift, button glow ring) are converted to **active states** on touch — applied during press, removed on release. No "stuck hover" after tap.

### Bandwidth

- The hero canvas is JS, no images. Mobile static SVG is < 4KB inline. We never pay an image-download cost for the hero.
- Fonts are preloaded with `<link rel="preload">` for Inter Regular, SemiBold, and JetBrains Mono Regular. Other weights load on demand.

---

## 9. Implementation order

A suggested build sequence so something demoable exists at every checkpoint.

1. **Static page first.** Render the entire page in its final layout with no animation, just typography and layout. Confirm the content tells the story before adding motion.
2. **Reduced-motion path.** Build the reduced-motion version of every section. This is faster, becomes the fallback for performance issues, and forces us to confirm the page works animation-free.
3. **Section reveals.** Add the in-view fade/translate entrance animations on every section. This is 80% of the perceived "polish" for 10% of the work.
4. **Hero canvas.** Build the Canvas 2D particle simulation. Start with the static elements (hexagon, grid, glyphs), then add a single animated packet, then scale up to the full sim.
5. **Workflow scrubber.** The most complex single section. Build last because it's the most likely to expose timing/Lenis bugs.
6. **Micro-interactions.** Buttons, cards, links, form inputs.
7. **Performance pass.** Profile on mid-range hardware, drop particle counts if needed, confirm CLS budget, audit JS bundle size.
8. **Reduced-motion final QA.** Re-test the reduced-motion path now that everything else is wired — make sure no animation snuck through.

---

## 10. Anti-patterns to avoid

- **No parallax on entire sections.** Parallax on hero backgrounds is fine; parallax that moves text relative to its section is dated and breaks accessibility.
- **No long pinned scrubbers.** §5 (Workflow) is the only pinned scrubber. More than one feels like the page is fighting the user.
- **No autoplaying motion that "shouldn't move yet."** Sections out of viewport never animate. Avoids drained battery and "is something happening?" confusion.
- **No motion as the primary content carrier.** Every animation has a static text equivalent in the same section. Someone reading the page in a screen-reader gets the full message.
- **No "wow" canvas demos that don't relate to the product.** The hero is a packet flow because that's what the product does. We don't add globes, fancy 3D models, or generative shaders just because.

---

This spec defines the motion contract for the marketing site. Implementation across `secureprompt-marketing/components/`, `secureprompt-marketing/lib/animations/`, and the canvas hero in `secureprompt-marketing/components/HeroSignal.tsx` should follow it directly.
