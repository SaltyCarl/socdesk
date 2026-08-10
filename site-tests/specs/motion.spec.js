// motion.spec.js — the tagline decode must ALWAYS resolve to its final text.
//
// It shipped frozen on scramble glyphs on the live masthead: a scramble tween
// that never lands (a starved ticker, a killed or re-fired tween) left gibberish
// on screen forever. These tests pin the guarantee in decode() — the resolved
// text is written on completion, on interruption, and by a timeout backstop —
// without depending on the real GSAP CDN.
const { test, expect } = require("@playwright/test");

const FINAL = "TRACK · VERIFY · VERDICT · PIVOT — REFRESHED EVERY 30 MINUTES";

test.describe("tagline decode never strands gibberish", () => {
  test("a scramble that never completes is still forced to the final text", async ({ page }) => {
    // Real GSAP must not load, or it would resolve the tween on its own and the
    // test would prove nothing.
    await page.route(/cdn\.jsdelivr\.net/, r => r.abort());

    // A minimal GSAP stand-in whose scramble tween FREEZES: it paints gibberish
    // and never fires onComplete/onInterrupt. Everything else boot touches is a
    // no-op that returns a chainable stub, so the page reaches the tagline line.
    await page.addInitScript(() => {
      const tween = new Proxy(function () {}, { get: () => () => tween });
      window.ScrambleTextPlugin = { name: "scrambleText" };
      window.gsap = {
        registerPlugin() {}, killTweensOf() {}, fromTo() { return tween; },
        timeline() { const tl = new Proxy(function () {}, { get: () => () => tl }); return tl; },
        to(target, vars) {
          if (vars && vars.scrambleText) {
            if (target) target.textContent = "▓▒░ FROZEN ░▒▓";
            // deliberately never resolve — this is the freeze
          } else if (vars && typeof vars.onUpdate === "function") {
            try { vars.onUpdate(); } catch (e) {}
          }
          return tween;
        },
      };
    });

    await page.goto("/index.html");
    await page.waitForFunction(() => document.querySelectorAll("#feedRows .row").length > 0);

    // the scramble path really is live (not the no-GSAP fallback)
    expect(await page.evaluate(() => window.ScrambleTextPlugin && window.ScrambleTextPlugin.name))
      .toBe("scrambleText");
    // it is frozen at first — then the backstop must land the real text
    await expect(page.locator("#tagline")).toHaveText(FINAL, { timeout: 5000 });
  });

  test("under prefers-reduced-motion the tagline is the plain final text, no scramble", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/index.html");
    await page.waitForFunction(() => document.querySelectorAll("#feedRows .row").length > 0);
    await expect(page.locator("#tagline")).toHaveText(FINAL, { timeout: 5000 });
  });
});
