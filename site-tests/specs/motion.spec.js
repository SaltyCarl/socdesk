// motion.spec.js — the decode() scramble must ALWAYS resolve to its final text.
//
// It shipped frozen on scramble glyphs on the live masthead tagline: a scramble
// tween that never lands (a starved ticker, a killed or re-fired tween) left
// gibberish on screen forever. The masthead is gone in the re-layout, but the
// same decode() primitive still animates the verdict word (#vword) on every
// lookup — so the guarantee is pinned there instead: the resolved text is
// written on completion, on interruption, and by a timeout backstop, without
// depending on the real GSAP CDN.
const { test, expect } = require("@playwright/test");

// An out-of-window CVE resolves to the router miss word — deterministic, and
// not enrichable, so nothing re-decodes #vword out from under the assertion.
const PROBE = "CVE-1999-0001";
const FINAL = "NOT IN CORPUS";

async function lookup(page) {
  await page.fill("#q", PROBE);
  await page.press("#q", "Enter");
}

test.describe("verdict-word decode never strands gibberish", () => {
  test("a scramble that never completes is still forced to the final text", async ({ page }) => {
    // Real GSAP must not load, or it would resolve the tween on its own and the
    // test would prove nothing.
    await page.route(/cdn\.jsdelivr\.net/, r => r.abort());

    // A minimal GSAP stand-in whose scramble tween FREEZES: it paints gibberish
    // and never fires onComplete/onInterrupt. Everything else the app touches is
    // a no-op that returns a chainable stub, so the lookup path is reached.
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
    await lookup(page);

    // the scramble path really is live (not the no-GSAP fallback)
    expect(await page.evaluate(() => window.ScrambleTextPlugin && window.ScrambleTextPlugin.name))
      .toBe("scrambleText");
    // it is frozen at first — then the backstop must land the real text
    await expect(page.locator("#vword")).toHaveText(FINAL, { timeout: 5000 });
  });

  test("under prefers-reduced-motion the word is the plain final text, no scramble", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/index.html");
    await page.waitForFunction(() => document.querySelectorAll("#feedRows .row").length > 0);
    await lookup(page);
    await expect(page.locator("#vword")).toHaveText(FINAL, { timeout: 5000 });
  });
});
