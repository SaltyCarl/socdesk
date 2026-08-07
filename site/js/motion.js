// motion.js — GSAP wiring, motion tokens, shared primitives.
// GSAP arrives as classic-script globals. If the CDN failed or the reader
// prefers reduced motion, `g` is null and every primitive below falls through
// to its correct FINAL state — the page is never dependent on animation.
export const motionOK = matchMedia("(prefers-reduced-motion: no-preference)").matches;
export const g = (typeof gsap !== "undefined" && motionOK) ? gsap : null;

export const DUR = { tap: .15, enter: .6, draw: 1.1 };   // mirrors css tokens
export const EASE = "expo.out", EASE_INOUT = "power2.inOut";
const SCRAM = "!<>-_\\/[]{}—=+*^?#";

if (g) {
  const plugins = [
    typeof ScrollTrigger !== "undefined" && ScrollTrigger,
    typeof SplitText !== "undefined" && SplitText,
    typeof ScrambleTextPlugin !== "undefined" && ScrambleTextPlugin,
    typeof DrawSVGPlugin !== "undefined" && DrawSVGPlugin,
    typeof MotionPathPlugin !== "undefined" && MotionPathPlugin,
    typeof Flip !== "undefined" && Flip,
  ].filter(Boolean);
  if (plugins.length) g.registerPlugin(...plugins);
}

const hasScramble = () => !!(g && typeof ScrambleTextPlugin !== "undefined");

/** Decode text into place. Falls back to plain assignment. */
export function decode(el, text, dur = .9) {
  if (!el) return null;
  if (!hasScramble()) { el.textContent = text; return null; }
  return g.to(el, { duration: dur, ease: "none",
    scrambleText: { text, chars: SCRAM, speed: .4 } });
}

/** Count a numeral up once, expo-out, tabular. */
export function countUp(el, target, dur = DUR.draw) {
  if (!el) return;
  const fmt = n => Math.round(n).toLocaleString("en-US");
  if (!g) { el.textContent = fmt(target); return; }
  const o = { n: 0 };
  g.to(o, { n: target, duration: dur, ease: EASE,
    onUpdate: () => { el.textContent = fmt(o.n); } });
}

/** Fire once when an element scrolls into view (or immediately without GSAP). */
export function onEnter(el, fn) {
  if (!el) return;
  if (!g || typeof ScrollTrigger === "undefined") { fn(); return; }
  ScrollTrigger.create({ trigger: el, start: "top 85%", once: true, onEnter: fn });
}

/**
 * Vermilion seal-stroke framing a card (replaces the old conic sweep).
 * Semantic: the red stroke appears only while a malicious verdict is shown.
 */
export function sealStroke(card, cssColor = "var(--mark)") {
  if (!card || !g || typeof DrawSVGPlugin === "undefined") return;
  card.querySelector(":scope > .seal")?.remove();
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("class", "seal");
  svg.setAttribute("preserveAspectRatio", "none");
  const r = document.createElementNS(ns, "rect");
  r.setAttribute("x", "1"); r.setAttribute("y", "1");
  r.setAttribute("width", "calc(100% - 2px)");
  r.setAttribute("height", "calc(100% - 2px)");
  r.style.stroke = cssColor;
  svg.append(r); card.append(svg);
  g.fromTo(r, { drawSVG: "0%" },
    { drawSVG: "100%", duration: DUR.draw, ease: EASE_INOUT });
}

/** Marquee with real velocity: fast entry settling to cruise, slow on hover. */
export function startTicker(track) {
  if (!track) return;
  if (!g) { track.classList.add("css-tick"); return; }
  const loop = g.to(track, { xPercent: -50, duration: 46, ease: "none", repeat: -1 });
  loop.timeScale(3);
  g.to(loop, { timeScale: 1, duration: 1.6, ease: "power2.out" });
  const view = track.parentElement;
  view?.addEventListener("pointerenter", () => g.to(loop, { timeScale: .15, duration: .4 }));
  view?.addEventListener("pointerleave", () => g.to(loop, { timeScale: 1, duration: .4 }));
}

/** One composed entrance per section: kicker decode -> slab -> rule wipe -> body. */
export function sectionTimeline(sec) {
  const head = sec?.querySelector(".sec-head");
  if (!head) return null;
  if (!g || typeof ScrollTrigger === "undefined") { head.classList.add("in"); return null; }
  const kicker = head.querySelector(".sec-kicker");
  const rule = head.querySelector(".rule");
  const tl = g.timeline({ defaults: { ease: EASE },
    scrollTrigger: { trigger: sec, start: "top 78%", once: true } });
  if (kicker) tl.add(decode(kicker, kicker.textContent, .6));
  tl.from(head.querySelector("h2"), { yPercent: 24, opacity: 0, duration: .55 }, "-=.35")
    .from(head.querySelector(".sec-desc"), { opacity: 0, y: 12, duration: .4 }, "-=.3");
  if (rule) tl.fromTo(rule, { scaleX: 0 }, { scaleX: 1, duration: .7, ease: EASE_INOUT }, "<");
  return tl;
}

/** Reflow a list honestly when it filters — FLIP, or a View Transition. */
export function reflow(selector, render) {
  if (g && typeof Flip !== "undefined") {
    const snap = Flip.getState(selector);
    render();
    Flip.from(snap, { duration: .45, ease: EASE, stagger: .015, absolute: true,
      onEnter: els => g.fromTo(els, { opacity: 0, y: 12 },
                               { opacity: 1, y: 0, duration: .3 }),
      onLeave: els => g.to(els, { opacity: 0, duration: .2 }) });
    return;
  }
  if (document.startViewTransition) { document.startViewTransition(render); return; }
  render();
}

/** Cursor-tracked bone wash on hoverable rows (flat, 5% — no glow). */
export function trackPointer(container, rowSelector) {
  container?.addEventListener("pointermove", e => {
    const row = e.target.closest?.(rowSelector);
    if (!row) return;
    const b = row.getBoundingClientRect();
    row.style.setProperty("--rx", (e.clientX - b.left) + "px");
    row.style.setProperty("--ry", (e.clientY - b.top) + "px");
  });
}

/** Tick a live clock element every second (honest liveness — our clock). */
export function tick(el, fn) {
  if (!el) return;
  const run = () => { el.textContent = fn(); };
  run();
  setInterval(run, 1000);
}
