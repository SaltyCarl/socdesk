// belt.js — wires the five toolbelt cards in the page DOM to tools.js.
//
// HARD RULES for this module:
//   1. ZERO network requests. Everything here is local text transformation on
//      input the analyst pasted. This is asserted by test, and it is the whole
//      reason the toolbelt is safe to hand a raw phishing sample.
//   2. All output is written with textContent, never innerHTML. Toolbelt output
//      carries no markup, and textContent is the strongest escaping available —
//      hostile indicator text can never become live DOM.
//   3. Every element lookup is null-guarded, so a page that ships only some of
//      the cards still initialises cleanly.
import {
  extractIOCs, defang, refang,
  smartDecodeBase64, psParseCommandLine, lolbinAnalyze
} from "./tools.js";

const $ = (id) => document.getElementById(id);

/** Write lines to an output node as plain text. Never innerHTML. */
function out(node, lines) {
  if (!node) return;
  node.textContent = Array.isArray(lines) ? lines.join("\n") : String(lines);
}

/** Wire a button to a handler, no-op if either the button or inputs are absent. */
function on(btn, fn) {
  if (!btn) return false;
  btn.addEventListener("click", fn);
  return true;
}

const LABELS = { ips: "IPv4", domains: "Domains", urls: "URLs", emails: "Emails",
                 md5s: "MD5", sha1s: "SHA-1", sha256s: "SHA-256", cves: "CVEs" };

/**
 * Initialise the toolbelt.
 * @param {{ onBulkLookup?: (indicators: string[]) => void }} [opts]
 */
export function initToolbelt({ onBulkLookup } = {}) {
  wireDefang();
  wireExtract(onBulkLookup);
  wireBase64();
  wirePowerShell();
  wireLolbin();
}

// ── 1. Defang / refang ───────────────────────────────────────────────────
function wireDefang() {
  const input = $("defangIn"), btn = $("defangBtn"), output = $("defangOut");
  if (!input || !btn || !output) return;
  let mode = "defang";
  const label = () => { btn.textContent = mode === "defang" ? "DEFANG" : "REFANG"; };
  label();
  on(btn, () => {
    const text = input.value || "";
    if (!text.trim()) { out(output, "Paste text to defang."); return; }
    out(output, mode === "defang" ? defang(text) : refang(text));
    mode = mode === "defang" ? "refang" : "defang";
    label();
  });
}

// ── 2. IOC extract ───────────────────────────────────────────────────────
function wireExtract(onBulkLookup) {
  const input = $("extractIn"), btn = $("extractBtn"), output = $("extractOut");
  const lookupBtn = $("extractLookup");
  if (!input || !btn || !output) return;

  let lastIndicators = [];

  if (lookupBtn) {
    lookupBtn.textContent = "Lookup all ↗";
    lookupBtn.disabled = true;
    on(lookupBtn, () => {
      if (typeof onBulkLookup === "function" && lastIndicators.length) {
        onBulkLookup(lastIndicators.slice());
      }
    });
  }

  on(btn, () => {
    const text = input.value || "";
    const found = extractIOCs(text);
    const lines = [];
    lastIndicators = [];

    for (const key of Object.keys(LABELS)) {
      const vals = found[key] || [];
      if (!vals.length) continue;
      lines.push(`${LABELS[key]} (${vals.length})`);
      for (const v of vals) { lines.push(`  ${v}`); lastIndicators.push(v); }
      lines.push("");
    }

    if (!lines.length) { out(output, "No indicators found."); }
    else { lines.unshift(`${lastIndicators.length} indicator(s) found`, ""); out(output, lines); }

    if (lookupBtn) lookupBtn.disabled = lastIndicators.length === 0;
  });
}

// ── 3. Base64 decode ─────────────────────────────────────────────────────
function wireBase64() {
  const input = $("b64In"), btn = $("b64Btn"), output = $("b64Out");
  if (!input || !btn || !output) return;
  on(btn, () => {
    const res = smartDecodeBase64(input.value || "");
    if (!res) { out(output, "Not valid Base64."); return; }
    out(output, [`Encoding: ${res.encoding}`, "", res.text]);
  });
}

// ── 4. PowerShell parser ─────────────────────────────────────────────────
function wirePowerShell() {
  const input = $("psIn"), btn = $("psBtn"), output = $("psOut");
  if (!input || !btn || !output) return;
  on(btn, () => {
    const cmd = (input.value || "").trim();
    if (!cmd) { out(output, "Paste a PowerShell command line."); return; }

    const p = psParseCommandLine(cmd);
    const lines = [`Binary: ${p.binary || "(none)"}`, ""];

    if (p.flags.length) {
      lines.push("Flags");
      for (const f of p.flags) {
        const reason = p.riskReasons.find((r) => r.flag === f.resolved);
        lines.push(`  ${f.resolved}${f.raw !== f.resolved ? `  (as ${f.raw})` : ""}`);
        if (reason) lines.push(`    ${reason.risk} — ${reason.desc}`);
      }
      lines.push("");
    } else {
      lines.push("Flags: none resolved", "");
    }

    if (p.encodedPayload) {
      lines.push("-EncodedCommand payload");
      lines.push(p.decodedPayload ? `  ${p.decodedPayload}` : "  (could not decode)");
      lines.push("");
    } else if (p.rawCommand) {
      lines.push("Command text", `  ${p.rawCommand}`, "");
    }

    if (p.mitre.length) lines.push(`MITRE: ${p.mitre.join(", ")}`);
    lines.push(`Overall risk: ${p.risk}`);
    out(output, lines);
  });
}

// ── 5. LOLBin lookup ─────────────────────────────────────────────────────
function wireLolbin() {
  const input = $("lolbinIn"), btn = $("lolbinBtn"), output = $("lolbinOut");
  if (!input || !btn || !output) return;
  on(btn, () => {
    const cmd = (input.value || "").trim();
    if (!cmd) { out(output, "Paste a command line."); return; }

    const r = lolbinAnalyze(cmd);
    if (!r) {
      const guess = cmd.split(/\s+/)[0] || cmd;
      out(output, `"${guess}" is not in the LOLBin database. That is not a verdict — it only means this binary has no entry here.`);
      return;
    }

    const lines = [
      `Binary: ${r.binary}`,
      `Risk: ${r.entry.risk}`,
      `MITRE: ${r.entry.mitre}`,
      "",
      r.entry.desc,
      ""
    ];

    if (r.flagsFound.length) {
      lines.push(`Suspicious flags matched (${r.flagsFound.length})`);
      for (const f of r.flagsFound) lines.push(`  ${f.flag} — ${f.desc}`);
    } else {
      lines.push("No known suspicious flags matched in this command line.");
    }
    out(output, lines);
  });
}
