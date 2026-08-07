// escaping.spec.js — THE CRITICAL ONE.
//
// The pipeline sanitizes, but the site must STILL escape at render: a collector
// pulls attacker-authored text (RSS titles, leak-site claims) and one bad
// interpolation turns a threat-intel page into the delivery mechanism. Two of
// these vectors are regressions of bypasses that actually shipped:
//   * an UNTERMINATED <img> tag, which borrows the `>` from the markup after it
//   * an attribute breakout through a URL that passes a naive scheme check
// Every payload sets a distinct window.__pwnedN so a partial failure is
// attributable to the exact vector that got through.
const { test, expect } = require("@playwright/test");

const ISO = new Date(Date.now() - 3600e3).toISOString();

const HOSTILE = [
  {
    id: "hostile-1", source: "evil-feed", category: "vulnerability",
    title: "<img src=x onerror=window.__pwned=1>",
    summary: "classic terminated image tag",
    url: "https://example.com/1", severity: "high",
    entities: { actors: [], malware: [], vendors: [], cves: [] },
    iocs: [], published_at: ISO, collected_at: ISO,
  },
  {
    id: "hostile-2", source: "evil-feed", category: "ransomware",
    // UNTERMINATED: relies on borrowing the next `>` in the surrounding markup
    title: "<img src=x onerror=window.__pwned2=1//",
    summary: "unterminated tag borrowing a closing bracket",
    url: "https://example.com/2", severity: "high",
    entities: { actors: [], malware: [], vendors: [], cves: [] },
    iocs: [], published_at: ISO, collected_at: ISO,
  },
  {
    id: "hostile-3", source: "evil-feed", category: "apt",
    title: "attribute breakout via url",
    summary: "the href is the payload",
    // breaks out of href="..." if the URL is trusted after a scheme prefix check
    url: 'http://x/" onmouseover="window.__pwned3=1',
    severity: "high",
    entities: { actors: ['" onfocus="window.__pwned5=1'], malware: [], vendors: [], cves: [] },
    iocs: [], published_at: ISO, collected_at: ISO,
  },
  {
    id: "hostile-4", source: "evil-feed", category: "report",
    title: "script element smuggled through a summary",
    summary: "benign lead-in </script><script>window.__pwned4=1</script> trailing text",
    url: "https://example.com/4", severity: "medium",
    entities: { actors: [], malware: [], vendors: [], cves: [] },
    iocs: [], published_at: ISO, collected_at: ISO,
  },
  {
    id: "hostile-5", source: '"><img src=x onerror=window.__pwned6=1>',
    // category lands inside a class attribute — a quote here is an attribute break
    category: 'apt" onanimationstart="window.__pwned7=1',
    title: "class-attribute breakout via category",
    summary: "category and source are attacker-controlled too",
    url: "https://example.com/5", severity: "low",
    entities: { actors: [], malware: [], vendors: [], cves: [] },
    iocs: [], published_at: ISO, collected_at: ISO,
  },
];

const GLOBALS = ["__pwned", "__pwned2", "__pwned3", "__pwned4",
                 "__pwned5", "__pwned6", "__pwned7"];

const pwned = page => page.evaluate(
  names => names.filter(n => typeof window[n] !== "undefined"), GLOBALS);

// NOTE: .row uses content-visibility:auto and .row .s is -webkit-line-clamped,
// so innerText() is empty or truncated for off-screen rows. textContent is both
// exact and the right question here: did the markup ever become DOM?

test.describe("hostile feed content cannot execute or break out", () => {
  test.beforeEach(async ({ page }) => {
    await page.route("**/data/feed.json", route => route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        generated_at: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
        schema_version: 1, items: HOSTILE,
      }),
    }));
    await page.goto("/index.html");
    await page.waitForFunction(
      () => document.querySelectorAll("#feedRows .row").length === 5);
  });

  test("no payload executes on render", async ({ page }) => {
    expect(await pwned(page)).toEqual([]);
    // nothing attacker-authored became live DOM
    await expect(page.locator("#feedRows img, #feedRows script")).toHaveCount(0);
    await expect(page.locator("#tickTrack img, #tickTrack script")).toHaveCount(0);
    await expect(page.locator("#rail img, #rail script")).toHaveCount(0);
  });

  test("the terminated <img> payload renders as literal, visible text", async ({ page }) => {
    const t = page.locator('#feedRows .row[data-id="hostile-1"] .t');
    await expect(t).toBeVisible();
    expect(await t.textContent()).toBe(HOSTILE[0].title);
    expect(await t.evaluate(el => el.children.length)).toBe(0);
    expect(await pwned(page)).toEqual([]);
  });

  test("the UNTERMINATED <img> payload cannot borrow a closing bracket", async ({ page }) => {
    const t = page.locator('#feedRows .row[data-id="hostile-2"] .t');
    expect(await t.textContent()).toBe(HOSTILE[1].title);
    expect(await t.evaluate(el => el.querySelectorAll("*").length)).toBe(0);
    expect(await pwned(page)).toEqual([]);
  });

  test("a hostile url cannot break out of the href attribute", async ({ page }) => {
    await page.locator('#feedRows .row[data-id="hostile-3"]').click();
    await expect(page.locator("#rail .rail-title")).toBeVisible();

    const a = page.locator("#rail .rail-title a");
    if (await a.count()) {
      const href = await a.getAttribute("href");
      expect(href, "href must be a clean http(s) URL").toMatch(/^https?:\/\/[^"'\s<>]*$/);
      // the breakout text must not have become an attribute
      const attrs = await a.evaluate(el => el.getAttributeNames());
      expect(attrs.some(n => /^on/i.test(n))).toBe(false);
      expect(attrs.sort()).toEqual(["href", "rel", "target"]);
    }
    // hostile entity strings land in data-ent — hover and click them too
    const ents = page.locator("#rail [data-ent]");
    for (let i = 0; i < await ents.count(); i++) {
      await ents.nth(i).hover();
      await ents.nth(i).click();
    }
    expect(await pwned(page)).toEqual([]);
  });

  test("a smuggled </script><script> in a summary never becomes a script", async ({ page }) => {
    const s = page.locator('#feedRows .row[data-id="hostile-4"] .s');
    expect(await s.textContent()).toBe(HOSTILE[3].summary);
    const scripts = await page.evaluate(() =>
      [...document.querySelectorAll("script")].map(x => x.textContent || x.src));
    expect(scripts.some(t => /__pwned/.test(t))).toBe(false);
    expect(await pwned(page)).toEqual([]);
  });

  test("hostile category/source cannot break out of a class attribute", async ({ page }) => {
    const row = page.locator('#feedRows .row[data-id="hostile-5"]');
    await expect(row).toBeVisible();
    const attrs = await row.locator(".tag").evaluate(el => el.getAttributeNames());
    expect(attrs.some(n => /^on/i.test(n))).toBe(false);
    expect(await row.locator(".tag").textContent()).toBe(HOSTILE[4].category);
    expect(await pwned(page)).toEqual([]);
  });

  // The feed is not the only attacker-reachable payload: cves.json and
  // health.json are interpolated into markup too, and their numeric fields were
  // going in raw on the assumption that the schema guarantees a number.
  test("hostile numeric fields in cves.json and health.json stay inert", async ({ page }) => {
    await page.route("**/data/cves.json", async route => {
      const real = await (await route.fetch()).json();
      // the table renders 100 rows sorted by risk — poison the row that is
      // guaranteed to be on screen, or the test proves nothing
      const risk = c => (c.kev ? 2 : 0) + (c.epss ?? 0);
      const top = real.cves.reduce((a, b) => (risk(b) > risk(a) ? b : a));
      top.cvss = '"><img src=x onerror=window.__pwned8=1>';
      route.fulfill({ contentType: "application/json", body: JSON.stringify(real) });
    });
    await page.route("**/data/health.json", async route => {
      const real = await (await route.fetch()).json();
      real.sources[0].items = '" onmouseenter="window.__pwned9=1';
      route.fulfill({ contentType: "application/json", body: JSON.stringify(real) });
    });
    await page.reload();
    await page.waitForFunction(() => document.querySelectorAll("#cveRows tr").length > 0);

    await expect(page.locator("#cveRows img, #healthGrid img")).toHaveCount(0);
    const cell = page.locator("#cveRows tr").first();
    await cell.hover();
    await page.locator("#healthGrid .hcell").first().hover();
    await page.waitForTimeout(500);         // give any onerror a chance to fire
    expect(await page.evaluate(() =>
      ["__pwned8", "__pwned9"].filter(n => typeof window[n] !== "undefined"))).toEqual([]);
  });

  test("nothing fires after hovering, selecting and acting on every hostile row", async ({ page }) => {
    const rows = page.locator("#feedRows .row");
    for (let i = 0; i < await rows.count(); i++) {
      const row = rows.nth(i);
      await row.hover();
      await row.click();
      await expect(page.locator("#rail .rail-title")).toBeVisible();
      await page.locator("#rail [data-copy=notable]").click();
      await row.locator("[data-act=review]").click();
    }
    // exports carry the same strings — make sure round-tripping them is inert
    await page.click("#exportBtn").catch(() => {});
    await page.waitForTimeout(300);
    expect(await pwned(page)).toEqual([]);
    await expect(page.locator("#feedRows img, #rail img, body script[src='']")).toHaveCount(0);
  });
});
