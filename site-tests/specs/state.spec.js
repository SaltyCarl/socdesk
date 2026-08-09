// state.spec.js — per-analyst state lives in localStorage only. Two things have
// to be true at once: it must survive a reload (or triage is worthless), and
// "Clear analyst state" must actually leave nothing behind (or the workstation
// hygiene control is a lie).
const { test, expect } = require("@playwright/test");
const R = require("../lib/real");

const NS = "socdesk:v1:";
const keys = page => page.evaluate(ns =>
  Object.keys(localStorage).filter(k => k.startsWith(ns)).sort(), NS);

test.use({ permissions: ["clipboard-read", "clipboard-write"] });

test.describe("analyst state", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/index.html");
    await page.waitForFunction(() => document.querySelectorAll("#feedRows .row").length > 0);
  });

  test("flagging two items produces a handoff markdown with both titles", async ({ page }) => {
    const picked = [];
    for (const n of [0, 3]) {
      const row = page.locator("#feedRows .row").nth(n);
      picked.push((await row.locator(".t").innerText()).trim());
      await row.click();
      await expect(page.locator("#rail .rail-title")).toBeVisible();
      await page.click("#rail [data-copy=notable]");
    }
    await expect(page.locator("#handoffBtn")).toHaveText("Handoff (2) ↗");

    await page.click("#handoffBtn");
    await expect(page.locator("#handoffBtn")).toHaveText("COPIED ✓");
    const md = await page.evaluate(() => navigator.clipboard.readText());

    expect(md).toContain("# SOCDESK shift handoff");
    for (const title of picked) expect(md).toContain(title);
    expect(md).toContain("2 item(s) flagged.");
    expect(md).toMatch(/flagged \d{4}-\d{2}-\d{2}T\d{2}:\d{2}Z/);
    // the digest carries the reference URL for each flagged item
    expect((md.match(/^\s+https?:\/\//gm) || []).length).toBe(2);
  });

  test("an empty handoff says so rather than producing a misleading blank", async ({ page }) => {
    await page.click("#handoffBtn");
    const md = await page.evaluate(() => navigator.clipboard.readText());
    expect(md).toContain("No items flagged notable this shift");
  });

  test("'Clear analyst state' removes every socdesk:v1:* key", async ({ page }) => {
    // build state across all four stores
    await page.locator("#feedRows .row").nth(1).locator("[data-act=review]").click();
    await page.locator("#feedRows .row").nth(2).click();
    await page.click("#rail [data-copy=notable]");
    await page.click("nav [data-view=vulns]");        // the watchlist lives there
    await page.fill("#wlInput", R.busiestVendor()[0]);
    await page.press("#wlInput", "Enter");
    await page.fill("#q", "8.8.8.8");
    await page.press("#q", "Enter");
    await expect(page.locator("#vword")).toHaveText("NOT IN CORPUS", { timeout: 8000 });

    const before = await keys(page);
    for (const k of ["reviewed", "notable", "watchlist", "history", "sessionStart"])
      expect(before, `state must include ${k} before clearing`).toContain(NS + k);

    await page.click("#clearState");
    // clearAll() runs synchronously on click; the reload is 800ms later
    expect(await keys(page), "nothing may survive the hygiene control").toEqual([]);

    // wait for the RELOAD, not for rows — the pre-reload document already has them
    await page.waitForFunction(
      ns => Object.keys(localStorage).includes(ns + "sessionStart"), NS);
    await page.waitForFunction(() => document.querySelectorAll("#feedRows .row").length > 0);
    const after = await keys(page);
    expect(after, "only a fresh session marker after reload").toEqual([NS + "sessionStart"]);
    await expect(page.locator("#feedRows .row.reviewed")).toHaveCount(0);
    await expect(page.locator("#wlChips .wlchip")).toHaveCount(0);
    await expect(page.locator("#handoffBtn")).toHaveText("Handoff ↗");
    await expect(page.locator("#histRow")).toBeEmpty();
  });

  test("the vendor watchlist persists across reload and filters the CVE table", async ({ page }) => {
    const [vendor, hits] = R.busiestVendor();
    expect(hits).toBeGreaterThan(0);
    const total = R.cves().cves.length;
    const expected = R.cves().cves.filter(c =>
      [...(c.vendors ?? []), ...(c.products ?? [])].filter(Boolean)
        .join(" ").toLowerCase().includes(vendor)).length;

    await page.click("nav [data-view=vulns]");
    await page.fill("#wlInput", vendor);
    await page.press("#wlInput", "Enter");
    await expect(page.locator("#wlChips .wlchip")).toHaveCount(1);
    await expect(page.locator("#wlChips .wlchip")).toContainText(vendor);
    await expect(page.locator("#wlInput")).toHaveValue("");

    await page.reload();
    await page.waitForFunction(() => document.querySelectorAll("#cveRows tr").length > 0);
    await page.click("nav [data-view=vulns]");        // a reload lands on the feed
    await expect(page.locator("#wlChips .wlchip")).toContainText(vendor);

    await page.click("#wlOnly");
    await expect(page.locator("#cveCount"))
      .toHaveText(`${expected.toLocaleString("en-US")} tracked`, { timeout: 8000 });
    expect(expected, "the watchlist must actually narrow the table").toBeLessThan(total);
    expect(expected).toBeGreaterThan(0);
    // every visible row is a watchlist hit and is badged as one
    const shown = Math.min(100, expected);
    await expect(page.locator("#cveRows tr")).toHaveCount(shown);
    await expect(page.locator("#cveRows tr .wl")).toHaveCount(shown);

    await page.click("#wlOnly");
    await expect(page.locator("#cveCount"))
      .toHaveText(`${total.toLocaleString("en-US")} tracked`, { timeout: 8000 });

    // removing the chip clears the filter source
    await page.locator("#wlChips [data-rm]").click();
    await expect(page.locator("#wlChips .wlchip")).toHaveCount(0);
    await page.reload();
    await page.waitForFunction(() => document.querySelectorAll("#cveRows tr").length > 0);
    await page.click("nav [data-view=vulns]");
    await expect(page.locator("#wlChips .wlchip")).toHaveCount(0);
  });

  test("copy buttons report the truth when the clipboard is available", async ({ page }) => {
    await page.locator("#feedRows .row").first().click();
    await page.click("#rail [data-copy=blurb]");
    await expect(page.locator("#rail [data-copy=blurb]")).toHaveText("COPIED ✓");
    const text = await page.evaluate(() => navigator.clipboard.readText());
    expect(text).toContain("Open-source reporting; shared for awareness.");
  });

  test("lookup history persists and replays", async ({ page }) => {
    await page.fill("#q", "8.8.8.8");
    await page.press("#q", "Enter");
    await expect(page.locator("#vword")).toHaveText("NOT IN CORPUS", { timeout: 8000 });
    await page.reload();
    await page.waitForFunction(() => document.querySelectorAll("#feedRows .row").length > 0);

    const chip = page.locator("#histRow [data-h='8.8.8.8']");
    await expect(chip).toBeVisible();
    await chip.click();
    // the console prints the indicator DEFANGED — safe to screen-share and paste
    await expect(page.locator("#console #vq")).toHaveText("8[.]8[.]8[.]8");
  });
});

// A denied clipboard is the normal case in a hardened browser. It must not
// raise an unhandled rejection, and the button must not claim a copy happened.
test.describe("clipboard denied", () => {
  test.use({ permissions: [] });

  test("a blocked copy fails loudly on the button and silently in the console",
    async ({ page }) => {
      const errors = R.watchConsole(page);
      await page.goto("/index.html");
      await page.waitForFunction(() => document.querySelectorAll("#feedRows .row").length > 0);
      await page.evaluate(() => {
        // deny at the source: some browsers reject rather than prompt
        navigator.clipboard.writeText = () => Promise.reject(new Error("denied"));
      });

      await page.locator("#feedRows .row").first().click();
      await page.click("#rail [data-copy=raw]");
      await expect(page.locator("#rail [data-copy=raw]")).toHaveText("COPY BLOCKED");
      await expect(page.locator("#rail [data-copy=raw]")).toHaveText("Copy raw", { timeout: 4000 });

      await page.click("#handoffBtn");
      await expect(page.locator("#handoffBtn")).toHaveText("COPY BLOCKED");

      await page.waitForTimeout(400);
      expect(errors(), "a denied clipboard must not raise an unhandled rejection")
        .toEqual([]);
    });
});
