# SecurePrompt — Brand Color System

> **Scope.** This palette applies to the **marketing site only** (`secureprompt-marketing/`). The operator dashboard (`secureprompt-web/`) keeps its existing monochrome theme — do not swap dashboard tokens. Two separate visual systems by design: the dashboard is a tool (calm, neutral, gets out of the operator's way); the marketing site is a sales surface (expressive, brand-forward, drives a buying decision).

---

## Direction

**Slate-near-black canvas + deep electric blue accent.**

- **Deep electric blue** is the universal cybersecurity brand color. It carries the trust and authority enterprise security buyers expect (the visual language of every NOC console, SIEM dashboard, and security vendor pitch they've seen for the last decade), while staying sharp enough to read as modern AI tooling rather than legacy infrastructure software.
- **Slate** (cool dark gray, almost-black with a perceivable blue undertone) is the modern enterprise-software canvas. It pairs cleanly with electric blue and reads as serious, technical, and intentional. Avoids both the warm "developer terminal" aesthetic and the bright SaaS look.

The combination signals one thing clearly: **this is a security platform a CISO would put on the production network**, not a startup demo.

### What we deliberately avoid

| Color | Used by | Why we skip it |
|---|---|---|
| Purple / violet | Datadog, SentinelOne, Stability, Vercel AI | Saturated AI-startup cliché — the look the founder explicitly moved past |
| Cyan / teal | Cloud-dev tools, generic AI UIs | Reads as soft / consumer-grade for an enterprise security buyer |
| Saturated red | CrowdStrike, Trellix | Reads as "intrusion alert", not "platform"; conflicts with our destructive accent |
| Saturated orange | Cloudflare, Palo Alto | Already owned at scale by network-security incumbents |
| Lime green | Norton, McAfee | Carries "consumer antivirus" baggage |

---

## Primary brand palette (deep electric blue)

The brand color is a **single deep blue**, with two adjacent shades for hover/depth and a brighter shade for focus rings, links, and highlights on dark surfaces.

| Token | Hex | HSL | Use |
|---|---|---|---|
| `brand-50` | `#EFF6FF` | `hsl(214 100% 97%)` | Tint backgrounds, hover wash on light surfaces |
| `brand-100` | `#DBEAFE` | `hsl(214 95% 93%)` | Light surfaces with brand tint |
| `brand-200` | `#BFDBFE` | `hsl(213 97% 87%)` | Subtle borders, secondary action surfaces |
| `brand-300` | `#93C5FD` | `hsl(212 96% 78%)` | Highlighted text on dark, links on dark |
| `brand-400` | `#60A5FA` | `hsl(213 94% 68%)` | **Highlight glow on dark surfaces, focus rings on dark** |
| `brand-500` | `#3B82F6` | `hsl(217 91% 60%)` | **Brand on dark surfaces — chips, accents, button hover** |
| `brand-600` | `#2563EB` | `hsl(221 83% 53%)` | **Canonical brand color — primary buttons, logo gradient stop** |
| `brand-700` | `#1D4ED8` | `hsl(224 76% 48%)` | **Primary button hover, deep accent, logo gradient stop** |
| `brand-800` | `#1E40AF` | `hsl(226 71% 40%)` | Active/pressed state, deep brand-tinted surface |
| `brand-900` | `#1E3A8A` | `hsl(224 64% 33%)` | Brand-tinted near-black panel |
| `brand-950` | `#172554` | `hsl(226 57% 21%)` | Deepest brand tint, used over slate-950 for layered depth |

### When to use which shade

- **`brand-600`** — the canonical brand color. Use anywhere a single blue is needed: primary CTAs, the logo's hexagon, the underline accent on links.
- **`brand-700`** — primary CTA hover state on light surfaces. Pairs cleanly with `brand-600` because the hue is constant.
- **`brand-500`** — primary brand on dark surfaces (better contrast against slate-900 than `brand-600`).
- **`brand-400`** — focus rings on dark, in-text accent links on dark, chart highlights.
- **`brand-300`** — soft accents and quote marks on dark surfaces.

---

## Surface palette (cool slate)

The supporting neutrals come from the **slate** scale — cool gray with a perceivable blue undertone. Slate pairs naturally with deep blue; warm grays (zinc, stone) would clash.

The marketing site is **dark-first by default** — the hero and primary scroll experience are on dark slate. Light variants exist for sections where high contrast helps copy readability.

### Dark canvas (canonical)

| Token | Hex | HSL | Role |
|---|---|---|---|
| `bg` | `#020617` | `hsl(222 47% 5%)` | Page background — near-black with blue tint |
| `bg-elevated` | `#0F172A` | `hsl(222 47% 11%)` | Cards, raised panels |
| `bg-floating` | `#1E293B` | `hsl(217 33% 17%)` | Popovers, dropdowns, modals |
| `border` | `#1E293B` | `hsl(217 33% 17%)` | Subtle dividers |
| `border-strong` | `#334155` | `hsl(215 25% 27%)` | Card edges, table separators |
| `text-primary` | `#F8FAFC` | `hsl(210 40% 98%)` | Body copy, headings |
| `text-secondary` | `#CBD5E1` | `hsl(213 27% 84%)` | Subtitles, secondary copy |
| `text-muted` | `#94A3B8` | `hsl(215 20% 65%)` | Captions, labels, disabled text |

### Light canvas (used for select copy-heavy sections)

| Token | Hex | HSL | Role |
|---|---|---|---|
| `bg` | `#FFFFFF` | `hsl(0 0% 100%)` | Page background |
| `bg-elevated` | `#F8FAFC` | `hsl(210 40% 98%)` | Cards |
| `border` | `#E2E8F0` | `hsl(215 28% 91%)` | Subtle dividers |
| `border-strong` | `#CBD5E1` | `hsl(213 27% 84%)` | Card edges |
| `text-primary` | `#0F172A` | `hsl(222 47% 11%)` | Body copy |
| `text-secondary` | `#334155` | `hsl(215 25% 27%)` | Subtitles |
| `text-muted` | `#64748B` | `hsl(215 16% 47%)` | Captions, labels |

---

## Semantic / status colors

Independent of the brand color. Picked to remain distinguishable from each other and from brand blue at small chart sizes and badge sizes.

| Token | Hex | HSL | Used for |
|---|---|---|---|
| `success` | `#10B981` | `hsl(160 84% 39%)` | "Allowed", "Healthy", positive metrics in chart annotations |
| `warning` | `#F59E0B` | `hsl(38 92% 50%)` | "Flagged", "Approaching limit" |
| `destructive` | `#EF4444` | `hsl(0 84% 60%)` | "Denied", "Violation", error states |

Keep these in semantic contexts only. Do **not** use them as decorative accents on the landing page — they should feel meaningful when they appear.

---

## Chart palette (for the marketing animations only)

The animated dashboard mockup in the **Three Products → Console card** (see `animations.md` §4) and the workflow scrubber (§5) need to look like real product UI. Use this five-color sequence on those mockups:

| Slot | Hex | Pairs with |
|---|---|---|
| `chart-1` | `#3B82F6` (brand-500) | Primary metric — usually p50 / median / "this workspace" |
| `chart-2` | `#10B981` (emerald) | Comparator — p95 / mean / "all workspaces" |
| `chart-3` | `#F59E0B` (amber) | Tertiary — p99, warning bands |
| `chart-4` | `#94A3B8` (slate-400) | Neutral baseline — historical / reference data |
| `chart-5` | `#EF4444` (red) | Denials, errors, destructive metrics |

This palette is for **marketing-side mockups only** — the actual dashboard charts in `secureprompt-web/` are unchanged.

---

## Logo treatment

The current logo's hexagon uses a purple gradient. Replace with a deep blue gradient that flows from upper-left to lower-right.

### Proposed gradient

```
linear-gradient(135deg, #3B82F6 0%, #1D4ED8 100%)
```

- `#3B82F6` (`brand-500`) at the top-left — the bright "incoming light" face of the hexagon
- `#1D4ED8` (`brand-700`) at the bottom-right — the deeper, grounded face

The wordmark stays white on dark backgrounds and `slate-900` (`#0F172A`) on light backgrounds.

### Alternate: solid fill

For favicons, app icons, and other small-size contexts where gradients muddy, use solid `brand-600` (`#2563EB`) for the hexagon with no gradient.

### Things to avoid

- Don't tint the hexagon with anything from the semantic palette (no green hexagon to mean "secure", no red for "alert"). The hexagon is identity, not status.
- Don't use the brand blue as a wordmark fill at body sizes. Blue-on-white at small sizes reads as a hyperlink. Wordmark stays slate or white.
- A subtle blue glow (`box-shadow: 0 0 32px rgba(59, 130, 246, 0.22)`) on the hexagon is acceptable for the hero treatment only — never on smaller instances.

---

## Marketing-site CSS variables

Drop into the marketing app's root stylesheet. **Do not paste these into the dashboard's `globals.css`** — the dashboard keeps its own theme.

```css
:root {
  /* Brand deep blue ramp */
  --m-brand-50:  #EFF6FF;
  --m-brand-100: #DBEAFE;
  --m-brand-200: #BFDBFE;
  --m-brand-300: #93C5FD;
  --m-brand-400: #60A5FA;
  --m-brand-500: #3B82F6;
  --m-brand-600: #2563EB;   /* canonical brand */
  --m-brand-700: #1D4ED8;
  --m-brand-800: #1E40AF;
  --m-brand-900: #1E3A8A;
  --m-brand-950: #172554;

  /* Dark canvas (default) */
  --m-bg:           #020617;   /* slate-950 hero */
  --m-bg-elevated:  #0F172A;   /* slate-900 sections / cards */
  --m-bg-floating:  #1E293B;   /* slate-800 popovers / modals */
  --m-border:       #1E293B;
  --m-border-strong:#334155;

  --m-text:         #F8FAFC;
  --m-text-secondary: #CBD5E1;
  --m-text-muted:   #94A3B8;

  /* Brand application aliases */
  --m-brand-on-dark:  var(--m-brand-500);   /* primary brand on slate-900 */
  --m-brand-deep:     var(--m-brand-700);   /* hover / pressed state */
  --m-brand-glow:     rgba(59, 130, 246, 0.22);  /* box-shadow tint */
  --m-brand-fg:       #FFFFFF;              /* text on solid brand fill */

  /* Semantic */
  --m-success:     #10B981;
  --m-warning:     #F59E0B;
  --m-destructive: #EF4444;

  /* Focus ring — applied to interactive elements on dark surfaces */
  --m-focus-ring:  #60A5FA;   /* brand-400 */
}
```

### Suggested visual treatments

- **Hero section**: `--m-bg` background. A subtle radial brand-blue gradient at top-left at ~12% opacity suggests "signal arriving" without literally drawing packets. (See `animations.md` §3 for the actual canvas spec.)
- **Section cards**: `--m-bg-elevated` with a 1px `--m-border-strong` edge. On hover, the border transitions to `--m-brand-500` at 50% opacity. No drop shadows (looks dated on dark UI).
- **Primary CTAs**: solid `--m-brand-600` button with white text. Hover transitions to `--m-brand-700`. Focus ring is 2px `--m-focus-ring` at 50% opacity, 2px offset.
- **Code blocks**: `--m-bg` background, slate-300 text. Syntax highlighting limited to two colors — `--m-brand-500` for keywords, `--m-success` for strings — keeps blocks visually quiet on a content-heavy page.
- **Inline links**: `--m-brand-400` text. Underline appears on hover, swept in left-to-right per the animation spec.

---

## Do / Don't

**Do**
- Use `brand-600` for primary CTAs on light backgrounds, `brand-500` on dark backgrounds
- Keep semantic tokens (`success`, `warning`, `destructive`) reserved for actual status — never decorative
- Pair brand blue with cool slate backgrounds; never with warm grays
- Use the deep-blue gradient on the hexagon for hero contexts; solid `brand-600` for favicons and small sizes

**Don't**
- Don't introduce new blue shades outside the eleven-stop ramp. If you need a tint, mix with `--m-bg` or `--m-bg-elevated`.
- Don't use brand blue for negative states — that's `destructive`. Blue is informational, positive, and brand-coded only.
- Don't combine brand blue with violet or purple as a primary pairing — visually re-introduces the cliché the rebrand is moving past.
- Don't apply hero glow treatments to anything other than the hero hexagon. Subtle ambient glow loses meaning when used everywhere.
- Don't touch the dashboard. The dashboard's existing monochrome palette stays; this spec is marketing-only.
