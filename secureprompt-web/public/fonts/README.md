# Self-hosted fonts

These fonts are served from `/fonts/**` to satisfy the air-gap constraint
(UI-SPEC §11). No runtime fetch hits `fonts.googleapis.com` or any CDN.

## Source

- **Inter** — Copyright (c) 2016–present, The Inter Project Authors.
  SIL Open Font License (OFL-1.1). https://rsms.me/inter/
- **JetBrains Mono** — Copyright (c) JetBrains s.r.o.
  SIL Open Font License (OFL-1.1). https://www.jetbrains.com/lp/mono/

Binary `.woff2` files were fetched from the Fontsource CDN
(`https://cdn.jsdelivr.net/fontsource/fonts/{inter,jetbrains-mono}@latest/latin-{400,500,600,700}-normal.woff2`)
for initial bootstrap; the files themselves are distributed under the OFL
license terms listed above and are committed to the repo for
reproducibility and air-gap builds.

## Files

| File | Weight | License |
|------|--------|---------|
| `Inter/Inter-Regular.woff2` | 400 | OFL-1.1 |
| `Inter/Inter-Medium.woff2` | 500 | OFL-1.1 |
| `Inter/Inter-SemiBold.woff2` | 600 | OFL-1.1 |
| `Inter/Inter-Bold.woff2` | 700 | OFL-1.1 |
| `JetBrainsMono/JetBrainsMono-Regular.woff2` | 400 | OFL-1.1 |
| `JetBrainsMono/JetBrainsMono-Medium.woff2` | 500 | OFL-1.1 |

@font-face rules live in `src/app/globals.css`.
