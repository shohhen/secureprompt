# SecurePrompt — Brand Color System

> **Scope.** This palette applies to the **marketing site only** (`secureprompt-marketing/`). The operator dashboard (`secureprompt-web/`) keeps its existing monochrome theme — do not swap dashboard tokens. Two separate visual systems by design: the dashboard is a tool (calm, neutral, gets out of the operator's way); the marketing site is a sales surface (expressive, brand-forward, drives a buying decision).

---

## Direction

**Pure black canvas + deep emerald accent.**

- **Pure black** is the canvas of operations centers, terminal interfaces, dark-mode trading desks, and serious technical software. Cleaner and more confident than off-black slate, and gives the brand accent maximum contrast to land.
- **Deep emerald** carries the visual language of operational green ("status ok", "operations active") and the modern terminal/red-team aesthetic (Wireshark capture displays, Burp Suite, Linux consoles). Avoids the SaaS-blue cliché the rest of the security-vendor field has converged on, and reads as both AI-native and security-coded.

The combination signals one thing clearly: **a serious technical product owned and operated by the team using it**, not a polished marketing surface for a black-box service.

### What we deliberately avoid

| Color | Used by | Why we skip it |
|---|---|---|
| Purple / violet | Datadog, SentinelOne, Stability, Vercel AI | Saturated AI-startup cliché — what the founder explicitly moved past |
| Cyan / sky blue | Cloud-dev tools, generic AI UIs | Soft / consumer-grade for an enterprise security buyer |
| Deep enterprise blue | IBM, Microsoft Security, Cloudflare's enterprise palette | Generic cybersec — every vendor in the space |
| Saturated red | CrowdStrike, Trellix | "Intrusion alert" coded; conflicts with our destructive accent |
| Saturated orange | Cloudflare, Palo Alto | Already owned at scale by network-security incumbents |
| Lime / kelly green | Norton, McAfee, Wireshark | Carries either consumer-antivirus baggage or hobbyist-tool feel |

---

## Primary brand palette (deep emerald)

The brand color is a **single deep emerald**, with two adjacent shades for hover/depth and a brighter shade for focus rings, links, and highlights against pure black.

| Token | Hex | HSL | Use |
|---|---|---|---|
| `brand-50` | `#ECFDF5` | `hsl(152 81% 96%)` | Tint backgrounds, hover wash on light surfaces |
| `brand-100` | `#D1FAE5` | `hsl(149 80% 90%)` | Light surfaces with brand tint |
| `brand-200` | `#A7F3D0` | `hsl(152 76% 80%)` | Subtle borders, secondary action surfaces |
| `brand-300` | `#6EE7B7` | `hsl(156 72% 67%)` | Highlighted text on dark, links on dark |
| `brand-400` | `#34D399` | `hsl(158 64% 52%)` | **Brand on dark — chips, accents, focus rings, logo gradient stop** |
| `brand-500` | `#10B981` | `hsl(160 84% 39%)` | **Canonical brand color — primary surface fill** |
| `brand-600` | `#059669` | `hsl(161 94% 30%)` | **Primary CTA hover state, deep accent** |
| `brand-700` | `#047857` | `hsl(163 94% 24%)` | **Logo gradient deep stop, active/pressed** |
| `brand-800` | `#065F46` | `hsl(163 88% 20%)` | Brand-tinted dark surface |
| `brand-900` | `#064E3B` | `hsl(164 86% 16%)` | Brand-tinted near-black panel |
| `brand-950` | `#022C22` | `hsl(166 88% 9%)` | Deepest brand tint over pure black |

### When to use which shade

- **`brand-500`** — the canonical brand color. Default fill for CTAs, focus rings, the logo's hexagon canonical stop.
- **`brand-400`** — bright accents on pure black: links, focus rings on dark surfaces, glow halos.
- **`brand-600`** — primary CTA hover state. Pairs cleanly with `brand-500` because the hue is constant.
- **`brand-700`** — logo gradient deep stop, deepest brand-tinted button surfaces.

---

## Surface palette (pure black + neutral grays)

The supporting neutrals are intentionally **pure black** and **near-black grays** rather than slate or zinc. Pure black gives emerald maximum contrast and reinforces the "operations console" aesthetic. Tinting the dark grays neutral (rather than blue-tinted slate) keeps the green accent dominant.

### Dark canvas (canonical — the only canvas the marketing site uses)

| Token | Hex | Role |
|---|---|---|
| `bg` | `#000000` | Page background — pure black |
| `bg-elevated` | `#0A0A0A` | Cards, raised panels — barely-perceivable lift from black |
| `bg-floating` | `#141414` | Popovers, dropdowns, modals |
| `border` | `#1F1F1F` | Subtle dividers |
| `border-strong` | `#2A2A2A` | Card edges, table separators |
| `text-primary` | `#F4F4F5` | Body copy, headings |
| `text-secondary` | `#C4C4C7` | Subtitles, secondary copy |
| `text-muted` | `#8A8A8E` | Captions, labels, disabled text |

The marketing site does **not** ship a light variant. Pure black + emerald is the entire visual identity.

---

## Semantic / status colors

Picked to remain distinguishable from each other and from emerald at small chart sizes and badge sizes.

| Token | Hex | Used for |
|---|---|---|
| `success` | `#34D399` | "Allowed", "Healthy" — overlaps brand on purpose; success IS the brand state |
| `warning` | `#F59E0B` | "Flagged", "Approaching limit" |
| `destructive` | `#EF4444` | "Denied", "Violation", error states |

Use these in semantic contexts only. Do **not** use them as decorative accents — they should feel meaningful when they appear.

---

## Logo treatment

The current PNG logo at `secureprompt-marketing/logo_without_bg.png` uses a purple gradient. The site already renders an SVG `HexLogo` component with the new emerald gradient — the PNG is no longer referenced. Regenerate the PNG if you need it for OG images, app icons, or social avatars.

### Gradient

```
linear-gradient(135deg, #34D399 0%, #047857 100%)
```

- `#34D399` (`brand-400`) at top-left — bright "incoming light" face
- `#047857` (`brand-700`) at bottom-right — deeper, grounded face

### Solid alternative for small sizes

For favicons, app icons, and contexts under 32px where gradients muddy: solid `brand-500` (`#10B981`).

### Things to avoid

- Don't tint the hexagon with anything from the semantic palette except `success` (which is already the brand color). No red hexagon for "alert".
- Don't use brand emerald as a wordmark fill at body sizes — green-on-black at small text reads as terminal output rather than identity. Wordmark stays white (`#F4F4F5`).
- Subtle emerald glow (`box-shadow: 0 0 32px rgba(16, 185, 129, 0.28)`) on the hexagon is acceptable for the hero CTA only, never for repeating instances on the page.

---

## CSS variable block

These are the variables wired into `secureprompt-marketing/src/app/globals.css`. **Do not paste into the dashboard's `globals.css`** — the dashboard keeps its own theme.

```css
@theme {
  /* Brand emerald ramp */
  --color-brand-50:  #ECFDF5;
  --color-brand-100: #D1FAE5;
  --color-brand-200: #A7F3D0;
  --color-brand-300: #6EE7B7;
  --color-brand-400: #34D399;   /* dark-canvas primary */
  --color-brand-500: #10B981;   /* canonical brand */
  --color-brand-600: #059669;   /* hover / pressed */
  --color-brand-700: #047857;   /* logo deep stop */
  --color-brand-800: #065F46;
  --color-brand-900: #064E3B;
  --color-brand-950: #022C22;

  /* Surface — pure black + neutral grays */
  --color-bg:           #000000;
  --color-bg-elevated:  #0A0A0A;
  --color-bg-floating:  #141414;
  --color-border:       #1F1F1F;
  --color-border-strong:#2A2A2A;

  --color-fg:           #F4F4F5;
  --color-fg-secondary: #C4C4C7;
  --color-fg-muted:     #8A8A8E;

  /* Semantic */
  --color-success:     #34D399;
  --color-warning:     #F59E0B;
  --color-destructive: #EF4444;
}
```

### Suggested visual treatments

- **Hero**: pure black background. Subtle radial emerald glow at top-left (10% opacity) suggests "signal arriving". Particle simulation runs in emerald against the black canvas.
- **Section cards**: `--color-bg-elevated` (#0A0A0A) with a 1px `--color-border-strong` edge. On hover, the border transitions to `--color-brand-400` at 40% opacity. No drop shadows.
- **Primary CTAs**: solid `--color-brand-600` button with white text. Hover transitions to `--color-brand-500` and adds a soft emerald glow (`box-shadow: 0 0 24px rgba(16, 185, 129, 0.40)`). Focus ring: 2px `--color-brand-400`, 2px offset.
- **Code blocks**: `--color-bg` background, light gray text. Syntax highlighting limited to two colors — `--color-brand-400` for keywords, `--color-success` for strings (same color, intentionally — emerald IS the language of "operational" output here).
- **Inline links**: `--color-brand-300` text. Underline appears on hover, swept in left-to-right.

---

## Do / Don't

**Do**
- Use `brand-500` for primary CTAs, `brand-400` for accents/focus on pure black
- Pair brand emerald with pure black backgrounds; never dilute with slate or warm gray
- Treat `success` as overlapping with the brand — they're the same color by design
- Use the gradient hexagon for hero contexts; solid `brand-500` for favicons

**Don't**
- Don't introduce new green shades outside the eleven-stop ramp
- Don't use brand emerald for negative states — that's `destructive`. Emerald means "operational", not "alert"
- Don't combine brand emerald with blue or purple as a primary pairing — the emerald is the entire brand identity, no second hue competing for attention
- Don't apply hero glow treatments to anything other than the hero hexagon and the CTA section
- Don't touch the dashboard. Marketing-only.
