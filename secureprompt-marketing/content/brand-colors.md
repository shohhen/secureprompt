# SecurePrompt — Brand Color System

> **Scope.** This palette applies to the **marketing site only** (`secureprompt-marketing/`). The operator dashboard (`secureprompt-web/`) keeps its own theme — do not swap dashboard tokens. Two separate visual systems by design: the dashboard is a tool (calm, neutral, gets out of the operator's way); the marketing site is a sales surface (expressive, brand-forward, drives a buying decision).
>
> **Source of truth.** The live values live in `secureprompt-marketing/src/app/globals.css` under the Tailwind v4 `@theme` block. This document describes what is implemented there. If the two ever disagree, the CSS wins — update this doc to match.

---

## Direction

**Ghost-white canvas + bloody-red accent. An editorial, print-broadsheet aesthetic.**

The marketing site reads like a **technical broadsheet** — near-black type on an almost-white page, hairline rules, monospaced captions, and a single saturated red that behaves like a redaction mark or an editor's correction pen. The red is the product metaphor made visible: SecurePrompt *redacts*, and redaction has always been rendered in heavy ink.

- **Ghost-white (`#F8F8FF`)** — not pure white. A barely-perceptible cool tint keeps the page from glaring and reads as "paper", not "app chrome". It gives the near-black type and the red accent room to land.
- **Bloody red (`#e30613`)** — a classic Swiss/editorial red. It is the *only* hue on the page. Used for accents, the logo, CTAs, active states, strike-throughs, and "this is the important word" emphasis in the big editorial headlines.

The combination signals: **a serious, opinionated technical product with a point of view** — closer to a printed manifesto than a typical SaaS landing page.

### What we deliberately avoid

| Color | Used by | Why we skip it |
|---|---|---|
| Purple / violet | Datadog, SentinelOne, Vercel AI | Saturated AI-startup cliché |
| Cyan / sky blue | Cloud-dev tools, generic AI UIs | Soft / consumer-grade for an enterprise security buyer |
| Emerald / kelly green | Norton, McAfee, Wireshark | "Operational green" is overused in security; reads hobbyist |
| Deep enterprise blue | IBM, Microsoft Security, Cloudflare | Generic cybersec — every vendor in the space |
| A second accent hue | — | The red is the entire identity. Nothing competes with it. |

> **Note:** the red sits adjacent to the territory CrowdStrike/Trellix occupy ("intrusion red"), but the editorial, near-white context reads as *print/redaction*, not *alert*. The page is calm and bookish, not a klaxon. That context is what keeps the red on-brand — do not pair it with a dark "alert" canvas.

---

## Canonical tokens (as implemented)

These are the exact variables in `globals.css` `@theme`. Tailwind v4 exposes each as a utility (e.g. `bg-bg`, `text-fg`, `text-accent`).

### Surface + ink (light, the only theme)

| Token | Hex | Role |
|---|---|---|
| `--color-bg` | `#F8F8FF` | Page background — ghost white |
| `--color-bg-2` | `#EFEFF6` | Nested / secondary surface |
| `--color-card` | `#FFFFFF` | Card background (pure white, lifts off the ghost-white page) |
| `--color-fg` | `#0e0e12` | Body copy + headings — near-black |
| `--color-muted` | `#6a6573` | Captions, mono labels, secondary copy |
| `--color-line` | `#E2E1EA` | Subtle hairline — section rules, card edges |
| `--color-line-2` | `#C9C8D2` | Stronger hairline — toggles, stronger borders |

The marketing site does **not** ship a dark variant. Ghost-white + red is the entire identity.

### Accent (bloody red)

| Token | Hex | Use |
|---|---|---|
| `--color-accent` | `#e30613` | **Canonical accent** — CTAs, emphasized words, active nav, logo, `//` mono labels |
| `--color-accent-deep` | `#b00010` | Hover / pressed state, logo gradient deep stop |
| `--color-accent-warm` | `#ff1a28` | Logo gradient bright stop, warm highlight |
| `--color-ink-on-accent` | `#fceee8` | Text/icon color on a filled red surface (warm off-white, not pure white) |
| `--color-destructive` | `#e30613` | Error / "denied" states — intentionally the same hex as the accent |

> `destructive` and `accent` are the **same red** by design. On this site the accent already carries the "redact / block / strike" meaning, so error states don't need a separate hue.

---

## Typography tokens

The type system is as load-bearing as the color. Five families, wired in `layout.tsx` via `next/font/google` and exposed as `@theme` variables.

| Token | Family | Role |
|---|---|---|
| `--font-sans` | **Inter** | Editorial headlines (`.hero-title`, `.editorial`), body copy. Heavy weights (800), tight tracking, lowercase. |
| `--font-mono` | **JetBrains Mono** | Captions, eyebrow labels, `//` annotations, the audit log, all small structural text. |
| `--font-serif` | **Instrument Serif** (italic) | The pull-quote and accented italic words. The "human voice" in a technical page. |
| `--font-pixel` | **VT323** | Pixel display accent — the skewed red `.ital` words inside headlines. |
| `--font-pixel-sm` | **Silkscreen** | Small pixel label accents. |

The signature headline treatment: **Inter 800, lowercase, tight negative tracking (`-0.04em`)**, with the occasional word swapped to skewed-red `VT323` (`.ital`) or italic `Instrument Serif`, and key words colored `--color-accent`.

---

## Logo treatment

The logo is an inline SVG hexagon (`HexLogo`, rendered in `SideNav`), **not** an image file. It uses a red gradient with a darkened inner hexagon for depth.

### Gradient

```
linear-gradient(135deg, #ff1a28 0%, #b00010 100%)
```

- `#ff1a28` (`--color-accent-warm`) at top-left — bright face
- `#b00010` (`--color-accent-deep`) at bottom-right — grounded face
- Inner hexagon: `rgba(0,0,0,0.3)` overlay for a faceted, minted look

### Things to avoid

- Don't recolor the hexagon to any non-red hue.
- Don't fill the **wordmark** with red at body sizes — red-on-white small text reads as redacted/struck, not as identity. Wordmark ink stays `--color-fg`.
- Keep the logo flat. No glow halos — the editorial aesthetic is matte, like print.

---

## CSS variable block (current `globals.css` `@theme`)

```css
@theme {
  --font-sans:  var(--font-inter), Inter, system-ui, sans-serif;
  --font-mono:  var(--font-jetbrains), "JetBrains Mono", ui-monospace, monospace;
  --font-serif: var(--font-serif), "Instrument Serif", serif;
  --font-pixel: var(--font-pixel), "VT323", ui-monospace, monospace;
  --font-pixel-sm: var(--font-pixel-sm), "Silkscreen", monospace;

  /* Ghost-white bg + bloody red accent (light theme) */
  --color-bg:    #F8F8FF;
  --color-bg-2:  #EFEFF6;   /* card / nested surface */
  --color-fg:    #0e0e12;   /* near-black text */
  --color-muted: #6a6573;   /* dimmed text */
  --color-line:  #E2E1EA;   /* subtle hairline */
  --color-line-2:#C9C8D2;   /* stronger hairline / borders */
  --color-card:  #FFFFFF;   /* card background */

  --color-accent:      #e30613;
  --color-accent-deep: #b00010;
  --color-accent-warm: #ff1a28;
  --color-destructive: #e30613;
  --color-ink-on-accent:#fceee8;
}
```

### How the tokens are actually used on the page

- **Page canvas**: `--color-bg` ghost-white. No gradients, no glows — flat paper.
- **Sections**: separated by 1px `--color-line` top rules. Generous vertical padding (80–140px).
- **Cards** (`.pcell`, `.tokcell`, `.acell`, `.audit-demo`, `.nrow`): `--color-bg` or `--color-card` on a 1px `--color-line` / `--color-line-2` grid. No drop shadows.
- **Primary CTA** (`.talk-btn-primary`): solid `--color-accent` pill, `--color-ink-on-accent` text; hover → `--color-accent-deep`.
- **Mono labels / eyebrows** (`.section-eyebrow-line`, `.section-num .lbl`, marquee `.acc`): `--color-accent` or `--color-muted`, JetBrains Mono, uppercase, wide tracking.
- **Emphasis in headlines**: `.accent` word → `--color-accent`; `.ital` word → skewed red VT323; `.underline` → red underline.
- **Reveal "wrong answer" words** (`.reveal-stage .word.strike.on`): red strike-through — literal redaction of the bad options.

---

## Do / Don't

**Do**
- Keep the page light. Ghost-white is the canvas; near-black is the ink; red is the one accent.
- Use red for the things that matter: CTAs, the one emphasized word per headline, active nav, strike-throughs.
- Lean on the mono/serif/pixel type mix for texture instead of reaching for more color.
- Keep surfaces flat — hairlines and type carry the hierarchy, not shadows or glows.

**Don't**
- Don't introduce a second accent hue, a dark canvas, or gradients on the page background.
- Don't use red as large fields of color — it's an accent and an editor's mark, not a wash.
- Don't add glow/box-shadow treatments — the aesthetic is matte print.
- Don't recolor the logo or fill the wordmark red at small sizes.
- Don't touch the dashboard. Marketing-only.
