# SOCDesk — Design references & animation libraries

Owner-provided references for elevating the site — especially the **globe hero + glassmorphism + Apple-style scroll**. Persisted here so they are never lost again (owner had to supply these ≥2× before they were saved — 2026-08-11).

## Constraint lens — READ FIRST
SOCDesk is **vanilla ES-modules, NO build step**, under a **strict CSP**: `default-src 'none'; script-src 'self'; style-src 'self'` — no external requests, no CDN, no `unsafe-inline`. Therefore:
- **Directly usable** libraries must be **vanilla JS + self-hostable (vendored locally) + CSP-safe** (no `eval`/`new Function`/inline injection CSP blocks).
- **React/Tailwind** component libs are **inspiration-only** — their effects get **reimplemented in vanilla JS/CSS**.
- Prefer **native CSS scroll-driven animations** (`animation-timeline: view()/scroll()`) where they suffice.

## Animation engines / tools
- **anime.js** — https://animejs.com — lightweight vanilla JS animation engine. Self-hostable, CSP-safe. Candidate for direct use.
- **Motion** — https://motion.dev — animation library; has a vanilla core ("Motion One") + a React layer. Vanilla core self-hostable. Candidate for direct use.
- **swishy.ai** — https://swishy.ai — motion/animation tool (verify exact offering during research).
- **Motion Primitives** — https://motion-primitives.com — motion component collection (React/Framer). Inspiration-only → reimplement patterns in vanilla.

## UI / effect galleries (inspiration → reimplement in vanilla)
- **React Bits** — https://reactbits.dev — animated components/backgrounds/text effects (React). Steal the effects, rebuild vanilla + CSP-safe.
- **KokonutUI** — https://kokonutui.com — animated Tailwind/React UI components. Inspiration-only.
- **bklit.ui** → resolved to **bklit-ui** (github.com/bklit/bklit-ui · bklit.com/docs) — a **charts / data-viz registry** (shadcn-based: line/area/ring/radar). **NOT an effects gallery** — low relevance to the globe/glass/scroll hero; **parked as a reference for future CTI metrics dashboards**. If a *glass* library was intended, the closest real one is **GlinUI** (liquid-glass primitives) — confirm with owner.

## Reference sites
- **Vantage CTI** — captured locally: `design/reference/vantage-source.html` + `vantage-styles.css` — a polished CTI site (Geist fonts, acid-green accent, `backdrop-filter` sticky header, smooth-scroll sections). Layout + interaction reference.
- **Apple product pages** — the scroll-melt / glassmorphism / depth feel; hero-to-content scroll choreography.

## Additional resources (owner-provided 2026-08-19) — reviewed + fit-assessed

**Directly usable (CSP-safe output tools, no runtime dep):**
- **fffuel.co** — suite of free SVG generators (gradients, mesh/blob, patterns, noise/grain, color tools). Output is static SVG/CSS → self-host the generated asset; **good fit** for hero backgrounds/texture.
- **uicolors.app** — Tailwind shade-scale palette generator. **Good fit** for palette/token work (the periwinkle ramp, new accents).

**High-relevance inspiration (React/Tailwind → reimplement vanilla/CSP-safe):**
- **Magic UI** — https://magicui.design — animated components incl. an **animated globe** and **"animated beam"** (curved connector arcs), particles/meteors. **Highest fit of this batch** — the animated-beam IS the arc-connector pattern we just built; a reference for future arc/globe motion. Inspiration-only (reimplement in the three.js loop / CSS).
- **Shader Gradient** — https://shadergradient.co — WebGL/R3F animated gradient tool. Relevant to hero-background depth, but heavy (WebGL + R3F); treat as **inspiration**, not a drop-in (adopting R3F conflicts with the hand-wired three.js globe + CSP).

**General inspiration galleries (React → reimplement):**
- **componentry.fun**, **Skiper UI** (skiper-ui.com), **Watermelon UI** — animated component/effect galleries. Steal effects, rebuild vanilla + CSP-safe. Same lens as React Bits / KokonutUI above.

**Not a design reference:**
- **bolt.new** — StackBlitz AI full-stack app builder; a prototyping/dev tool, not an effects/design library. Parked (could prototype a UI idea, but nothing to vendor).

## Notes
- Owner also mentioned "**and others**" that were lost before being saved — add them here as they are recalled.
- Companion cross-session memory: `socdesk-design-references`.
