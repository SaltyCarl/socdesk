// evidence.js — the escalation artifact.
//
// The observed workflow: an analyst checks an IP or hash, decides to escalate,
// screenshots the AbuseIPDB or VirusTotal page, and pastes that image into an
// email. The screenshot exists because a picture of the source saying it is
// more credible to the recipient than an analyst retyping the number. This
// module produces that image directly — every source on one card, ready for
// the clipboard.
//
// FOUR RULES, each one a decision rather than a detail:
//
//  1. LIGHT BACKGROUND. This lands in an email body next to white, and may be
//     printed or forwarded into a ticket. It deliberately breaks the site's
//     dark design system; a dark card reads as broken in Outlook.
//  2. EVERY FIGURE IS VERIFIABLE. Each block prints the source's own URL. The
//     card is our composite of their data, so it is only credible if the
//     recipient can go and check it.
//  3. SOURCES WE DID NOT CONSULT ARE NAMED. A card that quietly omits a source
//     it could not reach implies a completeness it does not have.
//  4. THEIR WORDING, NOT OURS. Headlines and facts are the source's own
//     numbers and language. We rank them; we do not restate them.

/* ---------- geometry & palette ------------------------------------------ */

const W = 760;            // CSS px — comfortable in an email body, not clipped
const PAD = 30;
const SCALE = 2;          // drawn at 2x so it stays crisp when scaled or printed

import { tallyHeadline } from "./verdict.js";

const INK = "#16202A", MUTED = "#5A6B7A", RULE = "#D8DFE5", BG = "#FFFFFF";
// Tone inks keyed by the consensus-tally tone (red|amber|green|grey). These are
// the print equivalents of the site's severity inks, tuned for a white ground.
const TONE = {
  red:   "#C0392B",
  amber: "#B26A00",
  green: "#1E7A46",
  grey:  "#5A6B7A",
};
const SANS = '"Archivo", "Segoe UI", system-ui, sans-serif';
const MONO = '"IBM Plex Mono", ui-monospace, "Cascadia Mono", monospace';

/* ---------- content model (pure — this is what the tests assert) --------- */

const LABEL = {
  ipv4: "IP ADDRESS", domain: "DOMAIN", url: "URL",
  md5: "MD5 HASH", sha1: "SHA-1 HASH", sha256: "SHA-256 HASH",
};

/**
 * Turn an /api/enrich response into the card's content.
 * No canvas, no DOM — so the thing that decides what the evidence SAYS can be
 * tested without rendering a pixel.
 */
export function evidenceModel(result, now = new Date()) {
  // The card carries the source-consensus tally, not a SOCDesk verdict word.
  const flagged = Number(result?.flagged ?? 0);
  const consulted = Number(result?.consulted ?? 0);
  const tone = String(result?.tone ?? "grey");
  return {
    title: "INDICATOR REVIEW",
    indicator: result?.indicator ?? "",
    typeLabel: LABEL[result?.type] ?? String(result?.type ?? "").toUpperCase(),
    checkedAt: (result?.checked_at ?? now.toISOString()).replace("T", " ").slice(0, 16) + " UTC",
    flagged,
    consulted,
    tone,
    tallyNum: `${flagged} / ${consulted}`,
    headline: tallyHeadline(flagged, consulted),
    // Attributed findings first, context (geolocation) last — the reader wants
    // the reputation data before the background. No per-source verdict chip is
    // printed: the tally above is the only assessment, each line is the source's
    // own words (§3).
    blocks: [...(result?.sources ?? [])]
      .sort((a, b) => (a.kind === "context" ? 1 : 0) - (b.kind === "context" ? 1 : 0))
      .map(s => ({
        name: s.name,
        kind: s.kind === "context" ? "context" : "assessment",
        headline: s.headline ?? "",
        facts: (s.facts ?? []).filter(([, v]) => v && v !== "—"),
        url: s.url ?? "",
      })),
    // Rule 3. Rendered on the card, not swallowed.
    notConsulted: (result?.errors ?? []).map(e => `${e.source} (${e.reason})`),
    footer: "Compiled from the sources listed above, each linked for verification. " +
            "Figures are those sources' own assessments at the time checked.",
    // Provenance, not branding. The recipient is being handed a composite of
    // other people's data by a tool they may never have heard of; they should
    // be able to see what made it and go look at it.
    origin: "SOCDesk · socdesk.io",
  };
}

/* ---------- text helpers ------------------------------------------------- */

let measureCtx = null;
function measurer() {
  if (!measureCtx) measureCtx = document.createElement("canvas").getContext("2d");
  return measureCtx;
}

/** Greedy wrap. Falls back to hard character breaks for unbroken strings —
 *  a 64-character hash or a long URL has no spaces to wrap on. */
function wrap(ctx, text, font, maxWidth) {
  ctx.font = font;
  const out = [];
  for (const paragraph of String(text).split("\n")) {
    let line = "";
    for (const word of paragraph.split(/\s+/)) {
      const next = line ? `${line} ${word}` : word;
      if (ctx.measureText(next).width <= maxWidth) { line = next; continue; }
      if (line) out.push(line);
      if (ctx.measureText(word).width <= maxWidth) { line = word; continue; }
      let chunk = "";
      for (const ch of word) {
        if (ctx.measureText(chunk + ch).width > maxWidth) { out.push(chunk); chunk = ch; }
        else chunk += ch;
      }
      line = chunk;
    }
    out.push(line);
  }
  return out;
}

/* ---------- painter ------------------------------------------------------
 * One pass computes height, the second draws. Same code path both times, so
 * the measured height and the drawn height cannot drift apart.
 * ---------------------------------------------------------------------- */

function paint(ctx, m, draw) {
  const put = (text, font, color, x, y) => {
    if (draw) { ctx.font = font; ctx.fillStyle = color; ctx.fillText(text, x, y); }
  };
  const rule = y => {
    if (draw) { ctx.fillStyle = RULE; ctx.fillRect(PAD, y, W - PAD * 2, 1); }
  };
  const mc = measurer();
  const inner = W - PAD * 2;
  const tone = TONE[m.tone] ?? TONE.grey;
  let y = PAD;

  /* header ------------------------------------------------------------- */
  put(m.title, `700 11px ${SANS}`, MUTED, PAD, y + 11);
  put(m.checkedAt, `400 11px ${MONO}`, MUTED,
      W - PAD - (draw ? ctx.measureText(m.checkedAt).width : 0), y + 11);
  y += 26;

  for (const line of wrap(mc, m.indicator, `600 21px ${MONO}`, inner)) {
    put(line, `600 21px ${MONO}`, INK, PAD, y + 21);
    y += 27;
  }
  put(m.typeLabel, `700 10px ${SANS}`, MUTED, PAD, y + 10);
  y += 22;

  /* consensus tally band ----------------------------------------------- */
  if (draw) {
    ctx.fillStyle = tone;
    ctx.fillRect(PAD, y, 4, 30);                 // a rule of colour, not a blob
  }
  put(m.tallyNum, `800 22px ${MONO}`, tone, PAD + 14, y + 24);
  put("FLAGGED / CONSULTED", `700 9px ${SANS}`, MUTED,
      PAD + 14 + (draw ? (ctx.font = `800 22px ${MONO}`, ctx.measureText(m.tallyNum).width) : 0) + 12,
      y + 24);
  y += 40;
  for (const line of wrap(mc, m.headline, `400 13px ${SANS}`, inner)) {
    put(line, `400 13px ${SANS}`, INK, PAD + 14, y + 13);
    y += 18;
  }
  y += 8;
  rule(y); y += 22;

  /* one block per source ------------------------------------------------ */
  for (const b of m.blocks) {
    put(b.name.toUpperCase(), `700 12px ${SANS}`, INK, PAD, y + 12);
    // Context rows are tagged so; reputation rows carry no verdict chip — the
    // attributed headline beneath is the source's own finding, stated as fact.
    if (b.kind === "context") {
      if (draw) ctx.font = `700 10px ${SANS}`;
      put("CONTEXT — NOT A VERDICT", `700 10px ${SANS}`, MUTED,
          W - PAD - (draw ? ctx.measureText("CONTEXT — NOT A VERDICT").width : 0), y + 12);
    }
    y += 20;

    for (const line of wrap(mc, b.headline, `400 13px ${SANS}`, inner)) {
      put(line, `400 13px ${SANS}`, INK, PAD, y + 13);
      y += 18;
    }
    y += 4;

    // Label column fixed so values align down the card and read as a table.
    const LX = PAD + 168;
    for (const [label, value] of b.facts) {
      put(label, `400 11px ${SANS}`, MUTED, PAD, y + 11);
      const lines = wrap(mc, value, `400 12px ${MONO}`, W - PAD - LX);
      for (const line of lines) { put(line, `400 12px ${MONO}`, INK, LX, y + 11); y += 17; }
      if (!lines.length) y += 17;
    }

    y += 3;
    put(b.url, `400 10px ${MONO}`, MUTED, PAD, y + 10);
    y += 22;
    rule(y); y += 20;
  }

  /* sources we could not consult ---------------------------------------- */
  if (m.notConsulted.length) {
    put("NOT CONSULTED", `700 10px ${SANS}`, MUTED, PAD, y + 10);
    y += 16;
    for (const line of wrap(mc, m.notConsulted.join(" · "), `400 11px ${SANS}`, inner)) {
      put(line, `400 11px ${SANS}`, MUTED, PAD, y + 11);
      y += 15;
    }
    y += 10;
  }

  /* footer --------------------------------------------------------------- */
  for (const line of wrap(mc, m.footer, `400 10px ${SANS}`, inner)) {
    put(line, `400 10px ${SANS}`, MUTED, PAD, y + 10);
    y += 14;
  }
  put(m.origin, `400 10px ${MONO}`, MUTED,
      W - PAD - (draw ? (ctx.font = `400 10px ${MONO}`, ctx.measureText(m.origin).width) : 0),
      y + 10);
  y += 14;
  return y + PAD;
}

/* ---------- public API --------------------------------------------------- */

/**
 * Render the card. Returns a canvas sized to its content.
 * Call after `document.fonts.ready` so the webfaces are available — canvas
 * silently substitutes a fallback face otherwise, and the card looks nothing
 * like the site.
 */
export function renderEvidence(result, now = new Date()) {
  const m = evidenceModel(result, now);
  const height = paint(measurer(), m, false);

  const canvas = document.createElement("canvas");
  canvas.width = W * SCALE;
  canvas.height = Math.ceil(height) * SCALE;
  const ctx = canvas.getContext("2d");
  ctx.scale(SCALE, SCALE);
  ctx.fillStyle = BG;
  ctx.fillRect(0, 0, W, height);
  ctx.textBaseline = "alphabetic";
  paint(ctx, m, true);

  // Hairline border so the card has an edge against a white email body.
  ctx.strokeStyle = RULE;
  ctx.lineWidth = 1;
  ctx.strokeRect(0.5, 0.5, W - 1, height - 1);
  return canvas;
}

export const toBlob = canvas =>
  new Promise(res => canvas.toBlob(res, "image/png"));

/**
 * Put the card on the clipboard as an image.
 * Returns the truth about whether it worked — this project has already shipped
 * a button that reported success while the clipboard rejected it.
 */
export async function copyEvidence(canvas) {
  try {
    if (!navigator.clipboard?.write || typeof ClipboardItem === "undefined") return false;
    const blob = await toBlob(canvas);
    if (!blob) return false;
    await navigator.clipboard.write([new ClipboardItem({ "image/png": blob })]);
    return true;
  } catch {
    return false;                       // denied permission, or insecure origin
  }
}

/** Fallback for browsers that refuse image clipboard writes. */
export async function downloadEvidence(canvas, indicator) {
  const blob = await toBlob(canvas);
  if (!blob) return false;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `socdesk-${String(indicator).replace(/[^\w.-]+/g, "_").slice(0, 60)}.png`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  return true;
}
