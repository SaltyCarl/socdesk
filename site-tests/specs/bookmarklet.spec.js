// bookmarklet.spec.js — the bookmarklet is the only code this project ships
// that executes inside somebody else's page, and it is installed once and then
// never updated. A bug here is permanent for every analyst who already dragged
// it. So these tests execute the real serialised body rather than trusting that
// the source function is correct.
const { test, expect } = require("@playwright/test");
const fs = require("fs");
const path = require("path");
const R = require("../lib/real");

/** The href the install card actually assigns, read off the live page. */
async function href(page) {
  await page.goto("/index.html");
  await page.click("nav [data-view=toolbelt]");
  return page.getAttribute("#bmkLink", "href");
}

/** Decode the href back to the JavaScript a browser would run. */
const body = h => decodeURIComponent(h.replace(/^javascript:/, ""));

/**
 * Run the bookmarklet against a page we control, with window.open stubbed, and
 * return the URL it tried to open. `prepare` runs in the page and sets up the
 * selection before the bookmarklet fires.
 */
async function opens(page, code, html, prepare) {
  await page.setContent(html);
  if (prepare) await page.evaluate(prepare);
  return page.evaluate(src => {
    let opened = null;
    const real = window.open;
    window.open = u => { opened = u; return null; };
    try { eval(src); } finally { window.open = real; }
    return opened;
  }, code);
}

test.describe("lookup bookmarklet", () => {
  test("the '#' in the deep link is percent-encoded", async ({ page }) => {
    // Regression guard, and the single most important assertion in this file.
    // An unencoded '#' makes the browser treat everything after it as the
    // bookmark's fragment: the saved program is silently truncated to a stub
    // that opens the site with no indicator, and it fails only in production.
    const h = await href(page);
    expect(h.startsWith("javascript:")).toBe(true);
    expect(h.slice("javascript:".length)).not.toContain("#");
    expect(body(h)).toContain('"#q="');
  });

  test("the base URL is the origin it was installed from, not a hardcode", async ({ page }) => {
    const src = body(await href(page));
    const base = new URL(page.url());
    expect(src).toContain(base.origin + "/");
    expect(src, "__BASE__ placeholder must be substituted").not.toContain("__BASE__");
  });

  test("the shipped HTML contains no javascript: URL of its own", async () => {
    // The href is assigned at runtime so the static file stays clean and the
    // page never offers a link our own CSP would refuse to follow.
    const html = fs.readFileSync(path.join(R.SITE, "index.html"), "utf8");
    expect(html).not.toMatch(/javascript:/i);
  });

  test("text selected inside an input becomes the lookup", async ({ page }) => {
    // The common case, and the one a naive getSelection() implementation gets
    // wrong: Chrome and Safari report an empty selection for <input> and
    // <textarea> content, and a SIEM query bar is exactly that.
    const code = body(await href(page));
    const url = await opens(page, code,
      `<textarea id="t">src_ip=185.220.101.42 AND action=allow</textarea>`,
      () => {
        const t = document.getElementById("t");
        t.focus();
        t.setSelectionRange(7, 22);
      });
    expect(url).toContain("#q=" + encodeURIComponent("185.220.101.42"));
  });

  test("an ordinary document selection becomes the lookup", async ({ page }) => {
    const code = body(await href(page));
    const url = await opens(page, code, `<p id="p">CVE-2024-3400</p>`, () => {
      const r = document.createRange();
      r.selectNodeContents(document.getElementById("p"));
      getSelection().removeAllRanges();
      getSelection().addRange(r);
    });
    expect(url).toContain("#q=CVE-2024-3400");
  });

  test("a multi-indicator selection survives for a bulk lookup", async ({ page }) => {
    const code = body(await href(page));
    const url = await opens(page, code,
      `<pre id="p">8.8.8.8\nevil.example.com\nCVE-2024-3400</pre>`, () => {
        const r = document.createRange();
        r.selectNodeContents(document.getElementById("p"));
        getSelection().removeAllRanges();
        getSelection().addRange(r);
      });
    const q = decodeURIComponent(new URL(url).hash.replace("#q=", ""));
    expect(q.split(/\s+/)).toEqual(["8.8.8.8", "evil.example.com", "CVE-2024-3400"]);
  });

  test("no selection opens the console rather than a broken lookup", async ({ page }) => {
    const code = body(await href(page));
    const url = await opens(page, code, `<p>nothing selected</p>`);
    expect(url).not.toContain("#q=");
    expect(url).toMatch(/^https?:\/\//);
  });

  test("an oversize selection is truncated instead of building a dead URL", async ({ page }) => {
    const code = body(await href(page));
    const url = await opens(page, code,
      `<p id="p">${"A".repeat(4000)}</p>`, () => {
        const r = document.createRange();
        r.selectNodeContents(document.getElementById("p"));
        getSelection().removeAllRanges();
        getSelection().addRange(r);
      });
    const q = decodeURIComponent(new URL(url).hash.replace("#q=", ""));
    expect(q.length).toBe(1500);
  });

  test("clicking the card's button on our own page does not navigate", async ({ page }) => {
    // Our CSP forbids javascript: navigation. Clicking must be intercepted, or
    // the control fires a policy violation and looks broken to the analyst.
    await page.goto("/index.html");
    await page.click("nav [data-view=toolbelt]");
    const before = page.url();
    await page.click("#bmkLink");
    expect(page.url()).toBe(before);
    await expect(page.locator("#bmkHint")).toContainText("bookmarks bar");
  });

  test("arriving on a deep link lands on the verdict, whatever view was last open", async ({ page }) => {
    // The critical path for this whole feature, and it was broken: the console
    // rendered correctly but stayed off-screen above whichever view and scroll
    // position the previous session left behind, so a bookmarklet click landed
    // the analyst on the toolbelt with no visible answer.
    await page.goto("/index.html");
    await page.click("nav [data-view=toolbelt]");
    await page.locator("#bmkCopy").scrollIntoViewIfNeeded();

    const cve = R.topKevCve().cve;
    await page.goto(`/index.html#q=${encodeURIComponent(cve)}`);
    await expect(page.locator("#vword")).toHaveText("ACTIVELY EXPLOITED", { timeout: 8000 });

    const onScreen = await page.locator("#console").evaluate(el => {
      const r = el.getBoundingClientRect();
      return r.top < innerHeight && r.bottom > 0;
    });
    expect(onScreen, "the verdict console must be in the viewport on arrival").toBe(true);
  });

  test("the service worker caches the bookmarklet module", async () => {
    // The card is inert without it, and the shell is served cache-first.
    const sw = fs.readFileSync(path.join(R.SITE, "sw.js"), "utf8");
    expect(sw).toContain("./js/bookmarklet.js");
  });
});
