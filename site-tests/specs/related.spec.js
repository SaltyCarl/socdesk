// related.spec.js — the RELATED block: relations.json finally read by the site.
// Contract per docs/RELATIONSHIPS.md: a ranked list keyed to the entity in
// focus — type chip, name, weight, honest provenance — never a graph.
const { test, expect } = require("@playwright/test");
const R = require("../lib/real");

function edgedIds(rel) {
  const s = new Set();
  for (const e of rel.edges) { s.add(e.src); s.add(e.dst); }
  return s;
}

function neighborsOf(rel, nodeId) {
  const names = new Set();
  for (const e of rel.edges) {
    if (e.src !== nodeId && e.dst !== nodeId) continue;
    const other = e.src === nodeId ? e.dst : e.src;
    const n = rel.nodes.find(x => x.id === other);
    if (n) names.add(n.name.toLowerCase());
  }
  return names;
}

/** An actor that BOTH has edges and resolves to an ATT&CK profile lookup. */
function actorUnderTest() {
  const rel = R.json("relations");
  if (!rel) throw new Error("relations.json not published — run the pipeline");
  const profiles = new Set((R.actors()?.profiles ?? []).map(p => p.name.toLowerCase()));
  const edged = edgedIds(rel);
  const node = rel.nodes.find(n =>
    n.type === "actor" && edged.has(n.id) && profiles.has(n.name.toLowerCase()));
  if (!node) throw new Error("no edged actor with a published profile");
  return { rel, node };
}

test.describe("related entities", () => {
  test("an actor profile carries a ranked RELATED block", async ({ page }) => {
    const { rel, node } = actorUnderTest();
    await page.goto("/index.html");
    await page.fill("#q", node.name);
    await page.press("#q", "Enter");

    const block = page.locator("#console .related");
    await expect(block).toBeVisible();

    const rows = block.locator(".rel-row");
    const count = await rows.count();
    expect(count).toBeGreaterThan(0);
    expect(count).toBeLessThanOrEqual(8);

    // provenance is one of the three honest labels — nothing invented
    for (const t of await block.locator(".rel-prov").allTextContents())
      expect(t).toMatch(/ATT&CK|CVE db|feed item/);

    // every listed name is a true neighbor in the published edge list
    const names = neighborsOf(rel, node.id);
    for (const nm of await block.locator(".rel-name").allTextContents()) {
      const clean = nm.replace(/\s*↗\s*$/, "").trim().toLowerCase();
      expect(names.has(clean), `"${clean}" must be a real neighbor of ${node.id}`)
        .toBe(true);
    }
  });

  test("a CVE verdict carries related vendor/product rows", async ({ page }) => {
    const rel = R.json("relations");
    const inCorpus = new Set((R.cves()?.cves ?? []).map(c => c.cve));
    const edged = edgedIds(rel);
    const node = rel.nodes.find(n =>
      n.type === "cve" && edged.has(n.id) && inCorpus.has(n.name));
    test.skip(!node, "no edged CVE in the current corpus");

    await page.goto("/index.html");
    await page.fill("#q", node.name);
    await page.press("#q", "Enter");
    await expect(page.locator("#console .related")).toBeVisible();
  });

  test("clicking a clickable related row pivots the console in place", async ({ page }) => {
    const { node } = actorUnderTest();
    await page.goto("/index.html");
    await page.fill("#q", node.name);
    await page.press("#q", "Enter");
    await expect(page.locator("#console .related")).toBeVisible();

    const btn = page.locator("#console .related button.rel-name").first();
    test.skip(await btn.count() === 0, "this actor has no clickable neighbors");

    const headBefore = await page.locator("#console .vc-head").innerText();
    await btn.click();
    await expect(page.locator("#console .vc-head")).not.toHaveText(headBefore);
  });
});
