// degrade.spec.js — the page must be readable when the motion CDN is gone and
// when a data file has not been published. Both have shipped broken before:
// a percentage IntersectionObserver threshold can never be satisfied by an
// element taller than the viewport (the feed is hundreds of rows), which left
// the whole section at opacity 0 with no error anywhere.
const { test, expect } = require("@playwright/test");
const R = require("../lib/real");

const CDN_BLOCKED = [/cdn\.jsdelivr\.net/i, /ERR_FAILED/i, /net::/i,
                     /Failed to load resource/i];

test.describe("degraded operation", () => {
  test("everything renders with GSAP blocked, and nothing is left invisible", async ({ page }) => {
    const errors = R.watchConsole(page, CDN_BLOCKED);
    await page.route(/cdn\.jsdelivr\.net/, route => route.abort());
    await page.goto("/index.html");
    await page.waitForFunction(() => document.querySelectorAll("#feedRows .row").length > 0);

    // GSAP really is absent — otherwise this test proves nothing
    expect(await page.evaluate(() => typeof window.gsap)).toBe("undefined");

    await expect(page.locator("#feedRows .row"))
      .toHaveCount(Math.min(25, R.feed().items.length));

    // vulnerabilities live in their own view now — switch to it in place
    await page.click("nav [data-view=vulns]");
    const cveTotal = R.cves().cves.length;
    const shown = Math.min(100, cveTotal);   // views.js renders in pages of 100
    await expect(page.locator("#cveRows tr")).toHaveCount(shown);
    await expect(page.locator("#cveCount")).toHaveText(`${cveTotal.toLocaleString("en-US")} tracked`);
    if (cveTotal > shown) {
      await expect(page.locator("#showMore")).toBeVisible();
      await page.click("#showMore");
      await expect(page.locator("#cveRows tr")).toHaveCount(Math.min(200, cveTotal));
    }

    // the counters that GSAP would have animated must still land on their value
    await expect(page.locator("#mastCount")).toHaveText(R.trackedTotal().toLocaleString("en-US"));
    await expect(page.locator("#tagline")).not.toHaveText("");

    // THE REGRESSION: no content block may sit at opacity 0 in the active view
    // (.rv hover affordances are opacity-0 by design and are excluded)
    const hidden = await page.evaluate(() =>
      [...document.querySelectorAll(
        ".reveal, .view.active .sec-head, .view.active .row, .view.active .rail, " +
        ".view.active .feed, .view.active .ops-tools")]
        .filter(el => Number(getComputedStyle(el).opacity) === 0)
        .map(el => el.className + " :: " + (el.id || el.tagName)));
    expect(hidden, "nothing may be hidden when motion is unavailable").toEqual([]);

    // every view has real height when switched to, not a collapsed shell
    const views = { feed: "#operations", vulns: "#vulns", health: "#health",
                    sources: "#registry", toolbelt: "#toolbelt" };
    for (const [view, id] of Object.entries(views)) {
      await page.click(`nav [data-view=${view}]`);
      const h = await page.locator(id).evaluate(el => el.getBoundingClientRect().height);
      expect(h, `${id} must have rendered content`).toBeGreaterThan(200);
    }
    expect(errors()).toEqual([]);
  });

  test("the feed stays visible after scrolling the whole page with GSAP blocked", async ({ page }) => {
    await page.route(/cdn\.jsdelivr\.net/, route => route.abort());
    await page.goto("/index.html");
    await page.waitForFunction(() => document.querySelectorAll("#feedRows .row").length > 0);
    // step by less than a viewport, or a short element can slip through the gap
    // between two scroll positions and never intersect anything
    await page.evaluate(async () => {
      const step = Math.floor(innerHeight / 2);
      for (let y = 0; y < document.body.scrollHeight; y += step) {
        window.scrollTo(0, y);
        await new Promise(r => requestAnimationFrame(r));
      }
    });
    const invisible = await page.evaluate(() =>
      [...document.querySelectorAll(".reveal")]
        .filter(el => Number(getComputedStyle(el).opacity) === 0).length);
    expect(invisible).toBe(0);
    await expect(page.locator("#feedRows .row").first()).toBeVisible();
  });

  test("an unpublished brief.json shows the designed absent state, not an error", async ({ page }) => {
    const errors = R.watchConsole(page);
    // this is brief.json's real state today; the route makes the test honest
    // even after Phase C publishes it.
    await page.route("**/data/brief.json", route => route.fulfill({ status: 404, body: "not found" }));
    await page.goto("/index.html");
    await page.waitForFunction(() => document.querySelectorAll("#feedRows .row").length > 0);

    // an unpublished brief never earns prime navigation
    await expect(page.locator("#navBrief")).toBeHidden();
    await expect(page.locator("#briefGenerated")).toHaveText("not yet published");
    await expect(page.locator("#briefList")).toContainText("No brief published yet");
    await expect(page.locator("#briefList")).toContainText("written on local hardware", { ignoreCase: true });
    await expect(page.locator("#briefList")).not.toContainText(/error|failed|undefined|NaN/i);
    await expect(page.locator("#briefList .bitem")).toHaveCount(1);
    // an absent optional payload is not a stale payload
    await expect(page.locator("#staleChips")).not.toContainText("BRIEF STALE");
    expect(errors()).toEqual([]);
  });

  test("a missing feed.json degrades to the offline row, not a blank page", async ({ page }) => {
    await page.route("**/data/feed.json", route => route.fulfill({ status: 503, body: "down" }));
    await page.goto("/index.html");
    await expect(page.locator("#feedRows")).toContainText("No collected data available");
    // the rest of the console must still work — switch views in place
    await page.click("nav [data-view=vulns]");
    await expect(page.locator("#cveRows tr").first()).toBeVisible();
    await expect(page.locator("#regRows tr")).toHaveCount(R.sources().sources.length);
    await expect(page.locator("#healthGrid .hcell")).toHaveCount(R.health().sources.length);
  });
});
