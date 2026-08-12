// motion.js — CSP-safe motion primitives. No JS animation library.
//
// The animation library (and its three CDN <script> tags) has been removed: the
// policy is `script-src 'self'`, so nothing external loads. Every primitive here
// is native: requestAnimationFrame tweens, IntersectionObserver reveals, and
// CSSOM writes (`element.style.setProperty` / `element.style.foo` — NEVER
// `setAttribute('style', …)`, which `style-src 'self'` blocks; that is exactly
// what killed the old library-driven Flip layout path). Each primitive degrades
// to its correct FINAL state under `prefers-reduced-motion`, so the page never
// depends on animation.
export const motionOK = matchMedia("(prefers-reduced-motion: no-preference)").matches;

// Retained for parity with the CSS motion tokens; consumed by the helpers below.
export const DUR = { tap: .15, enter: .6, draw: 1.1 };   // seconds

const rafOK = typeof requestAnimationFrame === "function";
const easeOutCubic = p => 1 - Math.pow(1 - p, 3);

/** Set text into place.
 *
 * The old library-driven scramble/decode effect is RETIRED — a decrypt-rain on display
 * type is on the anti-slop reject list. This is now a plain, CSP-safe
 * assignment kept under its original name so callers (the verdict word fill and
 * the live-enrich re-fire) need no change. `_decodeTarget` still records the
 * newest requested text so the newest write always wins on any settle. */
export function decode(el, text) {
  if (!el) return null;
  const finalText = String(text);
  el._decodeTarget = finalText;   // newest intent wins
  el.textContent = finalText;
  return null;
}

/** Count a numeral up once, ease-out, tabular. Reduced motion / no rAF lands on
 *  the final value instantly. Writes textContent only — no style, CSP-clean.
 *  Mirrors the `runCount` pattern in verdict.js. */
export function countUp(el, target, dur = DUR.draw) {
  if (!el) return;
  const to = Number(target);
  const fmt = n => Math.round(n).toLocaleString("en-US");
  if (!Number.isFinite(to)) { el.textContent = String(target); return; }
  if (!motionOK || !rafOK) { el.textContent = fmt(to); return; }
  const ms = dur * 1000, t0 = performance.now();
  el.textContent = fmt(0);
  const step = now => {
    const p = Math.min(1, (now - t0) / ms);
    el.textContent = fmt(easeOutCubic(p) * to);
    if (p < 1) requestAnimationFrame(step); else el.textContent = fmt(to);
  };
  requestAnimationFrame(step);
}

/** Fire `fn` once when `el` first scrolls into view.
 *
 * Replaces the old library scroll-trigger with a native IntersectionObserver:
 * class-toggle or callback reveals with zero library. The `-15%` bottom
 * root-margin ≈ the old "top 85%" trigger (fires as the element's top passes
 * 85% of the viewport). Reduced
 * motion / no IO → fire now, so the count-up simply lands on its final value. */
export function onEnter(el, fn) {
  if (!el) return;
  if (!motionOK || typeof IntersectionObserver !== "function") { fn(); return; }
  const io = new IntersectionObserver((entries, obs) => {
    for (const e of entries) if (e.isIntersecting) { obs.disconnect(); fn(); return; }
  }, { rootMargin: "0px 0px -15% 0px", threshold: 0 });
  io.observe(el);
}

/**
 * Seal-stroke framing a card. Semantic: the stroke appears only while a
 * malicious verdict (or the escalation console) is shown.
 *
 * Native CSS stroke-dashoffset draw — no draw-SVG library. `pathLength="100"`
 * normalises the perimeter so the dasharray/offset are size- and
 * theme-independent. All runtime writes are CSSOM property writes
 * (`r.style.…`), never an inline `style` attribute, so the policy is honoured.
 * Reduced motion → the rect is simply appended fully drawn (the global
 * reduced-motion rule in base.css also flattens the transition as a backstop).
 */
export function sealStroke(card, cssColor = "var(--mark)") {
  if (!card) return;
  card.querySelector(":scope > .seal")?.remove();
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("class", "seal");
  svg.setAttribute("preserveAspectRatio", "none");
  const r = document.createElementNS(ns, "rect");
  r.setAttribute("x", "1"); r.setAttribute("y", "1");
  r.setAttribute("width", "calc(100% - 2px)");
  r.setAttribute("height", "calc(100% - 2px)");
  r.setAttribute("pathLength", "100");   // presentation attr, not `style` — CSP-safe
  r.style.stroke = cssColor;             // CSSOM write — allowed under style-src 'self'
  svg.append(r); card.append(svg);
  if (!motionOK || !rafOK) return;       // reduced motion: stroke stays fully drawn
  r.style.strokeDasharray = "100";
  r.style.strokeDashoffset = "100";
  // Two frames so the browser records the hidden start value before we animate;
  // end state is offset 0 (fully drawn) even if the transition never fires.
  requestAnimationFrame(() => requestAnimationFrame(() => {
    r.style.transition = `stroke-dashoffset ${DUR.draw}s var(--ease-inout, ease-in-out)`;
    r.style.strokeDashoffset = "0";
  }));
}

/**
 * Reflow a list honestly when it filters — View Transition, or a plain render.
 *
 * The animation library's Flip plugin used to drive this and was REMOVED
 * deliberately: it applies
 * layout by calling `setAttribute("style", …)`, which our shipped policy
 * (`style-src 'self'` — no 'unsafe-inline') blocks, producing a dead animation
 * plus a securitypolicyviolation on every filter click. The View Transition
 * below reads the same and needs no inline style.
 */
export function reflow(render) {
  if (document.startViewTransition) { document.startViewTransition(render); return; }
  render();
}

/** Cursor-tracked wash on hoverable rows — CSSOM custom-property writes only. */
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
