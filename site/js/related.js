// related.js — the ranked RELATED block, the one sanctioned presentation of
// relations.json (docs/RELATIONSHIPS.md: a list keyed to the entity in focus;
// no node-link graph — that verdict is settled, do not re-litigate it here).
//
// The payload is an evidence-carrying edge list. Rank: live feed evidence
// before encyclopedia structure, then weight, then KEV endpoints, then name —
// deterministic, matching the pipeline's own ordering philosophy.
import { esc } from "./data.js";

let byId = new Map(), byName = new Map(), adj = new Map();

export function setRelations(rel) {
  byId = new Map(); byName = new Map(); adj = new Map();
  if (!rel || !Array.isArray(rel.nodes) || !Array.isArray(rel.edges)) return;
  for (const n of rel.nodes) {
    byId.set(n.id, n);
    byName.set(String(n.name).toLowerCase(), n);
  }
  for (const e of rel.edges) {
    if (!adj.has(e.src)) adj.set(e.src, []);
    if (!adj.has(e.dst)) adj.set(e.dst, []);
    adj.get(e.src).push(e);
    adj.get(e.dst).push(e);
  }
}

const isFeedEvidence = ev => ev[0] !== "attack" && ev[0] !== "cve-db";

const provenance = ev =>
  ev[0] === "attack" ? "ATT&CK" :
  ev[0] === "cve-db" ? "CVE db" :
  `${ev.length} feed item${ev.length === 1 ? "" : "s"}`;

export function relatedFor(names, max = 8) {
  const focus = names.map(n => byName.get(String(n).toLowerCase())).filter(Boolean);
  if (!focus.length) return [];
  const focusIds = new Set(focus.map(n => n.id));
  const seen = new Set();
  const rows = [];
  for (const f of focus) {
    for (const e of adj.get(f.id) ?? []) {
      const otherId = e.src === f.id ? e.dst : e.src;
      if (focusIds.has(otherId) || seen.has(otherId)) continue;
      const other = byId.get(otherId);
      if (!other) continue;
      seen.add(otherId);
      rows.push({ node: other, edge: e });
    }
  }
  rows.sort((a, b) =>
    (isFeedEvidence(b.edge.evidence) - isFeedEvidence(a.edge.evidence)) ||
    (b.edge.weight - a.edge.weight) ||
    ((b.node.kev === true) - (a.node.kev === true)) ||
    a.node.name.localeCompare(b.node.name));
  return rows.slice(0, max);
}

// Only types the verdict engine can resolve pivot in place; techniques deep-
// link to ATT&CK; vendors/products are context, not destinations.
const CLICKABLE = new Set(["actor", "malware", "cve"]);

const techniqueUrl = id =>
  `https://attack.mitre.org/techniques/${encodeURIComponent(id).replace(/\./g, "/")}/`;

/** Append the RELATED block to `el` if the focused names have any neighbors. */
export function attachRelated(el, names, onPick) {
  const rows = relatedFor(names);
  if (!rows.length) return;
  const block = document.createElement("div");
  block.className = "ev related";
  block.innerHTML = `<div class="l">Related</div>` + rows.map(({ node, edge }) => {
    const name = CLICKABLE.has(node.type)
      ? `<button class="rel-name" data-rel="${esc(node.name)}">${esc(node.name)}</button>`
      : node.type === "technique"
        ? `<a class="rel-name" href="${techniqueUrl(node.name)}" target="_blank" rel="noopener noreferrer">${esc(node.name)} ↗</a>`
        : `<span class="rel-name">${esc(node.name)}</span>`;
    return `<div class="rel-row">
      <span class="rel-main"><span class="vtag tone-muted">${esc(node.type)}</span>${name}</span>
      <span class="rel-prov">${esc(provenance(edge.evidence))} · w${esc(edge.weight)}</span>
    </div>`;
  }).join("");
  el.appendChild(block);
  block.querySelectorAll("[data-rel]").forEach(b =>
    b.onclick = () => onPick?.(b.dataset.rel));
}
