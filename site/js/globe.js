// globe.js — the home-hero showpiece: a vendored-cobe dot-matrix globe.
//
// PORTED from design/mockups/hero-globe.js, trimmed to the globe's own
// concerns. Everything the live app already owns is intentionally NOT here:
//   * theme toggle wiring        -> app.js initTheme() sets <html data-theme>;
//                                   we only OBSERVE it to recolor the globe.
//   * count-up / reveals / melt  -> motion.js / views.js.
//   * the answer surface         -> the live verdict console (#console, app.js).
//     The mockup's glass escalation card is deliberately dropped; a fly-to here
//     only springs the globe + drops the located pin. app.js's Enter handler
//     opens the console in parallel — "globe springs AND the console resolves".
//
// Behaviours carried over verbatim in spirit: auto-spin + drag inertia, the
// graded 3-state hover (off-globe = full spin, over-canvas = ~30%, over a pin =
// halt), gesture zoom-grow (flicker-free via a stable oversampled backing store
// + a pure compositor scale), projected verdict-toned pins with analyst-grade
// tooltips, and the critically-damped fly-to.
//
// FLY-TO DATA:
//   * live path  — an /api/enrich result carries the ipinfo "Coordinates"
//                  (lat,lng) fact; enrich-client.js dispatches `socdesk:enrich-
//                  result` and we plot it. Enrichment is dormant (no backend on
//                  the static tier), so this is wired-but-idle today.
//   * demo path  — a small geo table keyed by indicator (the mockup's), so a
//                  recent-chip / typed IP still flies. Absent geo => the globe
//                  stays ambient and only the console answers (graceful degrade).
//
// CSP: strict `script-src 'self'` / `style-src 'self'`. cobe is self-hosted and
// its map texture is a baked data: URI (allowed by `img-src 'self' data:`); WebGL
// shader compilation is not eval. EVERY runtime style write goes through
// element.style.setProperty — never setAttribute('style', …). Nothing here may
// throw at module top-level or log to the console (the QA gate treats a console
// error or a securitypolicyviolation as a failure), so createGlobe is guarded and
// a browser without WebGL simply leaves the hero copy untouched.
import createGlobe from "./vendor/cobe.js";

const root = document.documentElement;

const canvas   = document.getElementById("globe");
const stage    = document.getElementById("globeStage");
const pinsEl    = document.getElementById("globePins");
const landedEl = document.getElementById("landedPin");
const tip      = document.getElementById("pinTip");
const hint     = document.getElementById("globeHint");
const hero     = document.getElementById("hero");
const input    = document.getElementById("q");
const histRow  = document.getElementById("histRow");

// No globe in the DOM (a non-home surface, or the markup was trimmed) -> bail
// quietly. Everything downstream assumes these exist.
if (canvas && stage && hero) {

const rmq = matchMedia("(prefers-reduced-motion: reduce)");
const dpq = matchMedia("(prefers-color-scheme: dark)");

// Detect a SOFTWARE WebGL renderer (headless CI's SwiftShader, or a no-GPU
// device). cobe's per-fragment shader is cheap on a real GPU but expensive in
// software, so there we bound the backing store much tighter — the globe still
// builds and renders (fidelity is unchanged on real hardware), it just costs a
// fraction of the fragments, so several globes rendering in parallel can't
// starve the main thread. One-shot probe on a throwaway context.
const lowPerf = (() => {
  try {
    const c = document.createElement("canvas");
    const gl = c.getContext("webgl") || c.getContext("experimental-webgl");
    if (!gl) return true;
    const ext = gl.getExtension("WEBGL_debug_renderer_info");
    const r = ext ? String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)) : "";
    gl.getExtension("WEBGL_lose_context")?.loseContext();
    return /swiftshader|software|llvmpipe|basic render|microsoft basic/i.test(r);
  } catch (_) { return false; }
})();

/* ---------- theme resolution (mirrors app.js / tokens.css structure) ---------- */
function resolveDark() {
  const t = root.getAttribute("data-theme");
  if (t === "dark")  return true;
  if (t === "light") return false;
  return dpq.matches;
}

/* ---------- globe palette (from tokens.css, [r,g,b] in 0..1) ----------
   Matte periwinkle instrument, halo KILLED by setting glowColor to the
   background ink (no bloom). Lighting pushed for a clear sphere-read (#7). */
function palette(dark) {
  return dark ? {
    // DARK — periwinkle dots on an invisible ocean over warm espresso.
    base:[0.42,0.46,0.78],   // matte periwinkle land dots
    marker:[0.49,0.54,1.0],  // --accent #7C8AFF
    glow:[0.08,0.06,0.04],   // --ink #15100A -> KILLS the halo
    dark:1, mapBrightness:6.4, mapBaseBrightness:0, diffuse:1.25, opacity:0.95
  } : {
    // LIGHT (#6) — cobe renders an OPAQUE sphere, so the dark theme's "dots on
    // an invisible ocean" can't be mirrored on cream. The fix is a WARM GREIGE
    // INSTRUMENT, not a black orb: a low `dark` keeps the sphere body a warm
    // mid-tone; a periwinkle-leaning greige base + brighter periwinkle markers
    // keep the DOTS reading as the signal; reduced `opacity` lets it sit as an
    // elegant element on paper. Halo still killed (glow == paper ink).
    base:[0.51,0.49,0.585],  // warm greige w/ a periwinkle lean (sphere body)
    marker:[0.30,0.33,0.90], // saturated periwinkle markers pop on the greige
    glow:[0.96,0.91,0.83],   // --ink #F2E6D0 (paper) -> KILLS the halo
    dark:0.50, mapBrightness:5.6, mapBaseBrightness:0.30, diffuse:1.30, opacity:0.72
  };
}

const PI = Math.PI, THETA = 0.18;

// unit model-space vector for a lat/lng (matches cobe's marker fn:
// lat->i rad, lng->s=rad-PI; r = [-cos(i)cos(s), sin(i), cos(i)sin(s)])
function unitVec(lat, lng) {
  const i = lat*PI/180, s = lng*PI/180 - PI, cl = Math.cos(i);
  return [-cl*Math.cos(s), Math.sin(i), cl*Math.sin(s)];
}

/* ============================================================
   TI PINS — analyst-grade mock indicators (<=12). Real metro coords.
   Committed to Option B: colour by verdict tier, sized by severity. Pins are a
   projected DOM overlay (cobe's markerColor is one uniform, so per-severity
   colour + hit-testing live in the DOM).
   ============================================================ */
const PINS = [
  { location:[50.11,   8.68], sev:94, tier:"crit", type:"IPv4",    ind:"185.220.101.34",
    what:"Cobalt Strike C2 beacon",        actor:"Infra linked to <b>Akira</b> affiliate",
    consensus:"6 of 6", seen:"3 min ago",  trend:{d:"up",  t:"▲ sharp spike"},
    geo:"Frankfurt, DE · AS24940 Hetzner" },
  { location:[52.37,   4.90], sev:88, tier:"crit", type:"DOMAIN",  ind:"login-verify-ms[.]com",
    what:"Credential-harvesting phishing",  actor:"Attributed to <b>Storm-1101</b> (Tycoon 2FA)",
    consensus:"5 of 6", seen:"18 min ago", trend:{d:"up",  t:"▲ rising"},
    geo:"Amsterdam, NL · AS60781 LeaseWeb" },
  { location:[55.75,  37.61], sev:91, tier:"crit", type:"IPv4",    ind:"45.146.164.110",
    what:"Ransomware staging & exfil node", actor:"Linked to <b>LockBit</b> rebuild infra",
    consensus:"6 of 6", seen:"1 hr ago",   trend:{d:"flat",t:"▶ steady"},
    geo:"Moscow, RU · AS56694 SmartApe" },
  { location:[50.45,  30.52], sev:84, tier:"crit", type:"IPv4",    ind:"176.113.115.84",
    what:"SonicWall SSL-VPN exploit host",  actor:"<b>Akira</b> initial-access broker",
    consensus:"5 of 6", seen:"42 min ago", trend:{d:"up",  t:"▲ rising"},
    geo:"Kyiv, UA · AS44094 IT-Grad" },
  { location:[37.77,-122.42], sev:67, tier:"susp", type:"IPv4",    ind:"20.99.132.44",
    what:"APT29 spearphish sender infra",   actor:"Attributed to <b>APT29</b> (Midnight Blizzard)",
    consensus:"4 of 6", seen:"3 hr ago",   trend:{d:"up",  t:"▲ campaign active"},
    geo:"San Francisco, US · AS8075 Microsoft" },
  { location:[ 1.35, 103.82], sev:71, tier:"susp", type:"IPv4",    ind:"139.180.203.12",
    what:"Tor exit relay",                  actor:"No attributed actor",
    consensus:"3 of 6", seen:"26 min ago", trend:{d:"flat",t:"▶ steady"},
    geo:"Singapore, SG · AS20473 Vultr" },
  { location:[40.71, -74.00], sev:62, tier:"susp", type:"SHA-256", ind:"7f9c34e2…a3e1",
    what:"RedLine infostealer sample",      actor:"Commodity crimeware, no crew",
    consensus:"4 of 6", seen:"2 hr ago",   trend:{d:"up",  t:"▲ new variant"},
    geo:"New York, US · AS14061 DigitalOcean" },
  { location:[51.51,  -0.13], sev:55, tier:"susp", type:"DOMAIN",  ind:"cdn-analytics-cloud[.]net",
    what:"Malware distribution CDN",        actor:"Linked to <b>SocGholish</b> cluster",
    consensus:"4 of 6", seen:"4 hr ago",   trend:{d:"down",t:"▼ cooling"},
    geo:"London, GB · AS16509 Amazon" },
  { location:[-23.55,-46.63], sev:43, tier:"low",  type:"IPv4",    ind:"191.96.150.10",
    what:"Brute-force / scanning source",   actor:"Mirai-class botnet node",
    consensus:"2 of 6", seen:"6 hr ago",   trend:{d:"flat",t:"▶ steady"},
    geo:"São Paulo, BR · AS262287 Latitude" },
  { location:[35.68, 139.69], sev:38, tier:"low",  type:"DOMAIN",  ind:"update-pkg-mirror[.]org",
    what:"Newly-registered suspicious domain", actor:"Unclassified",
    consensus:"2 of 6", seen:"9 hr ago",   trend:{d:"up",  t:"▲ slight uptick"},
    geo:"Tokyo, JP · AS7506 GMO" },
  { location:[19.08,  72.88], sev:29, tier:"low",  type:"MD5",     ind:"3ab5f1c0…9f02",
    what:"Adware / PUP bundle",             actor:"Commodity, no attribution",
    consensus:"1 of 6", seen:"13 hr ago",  trend:{d:"down",t:"▼ declining"},
    geo:"Mumbai, IN · AS4755 TATA" }
];
for (const p of PINS) { p.r = unitVec(p.location[0], p.location[1]); p.el = null; p.sx = -1; p.sy = -1; p.fz = -1; }

/* ============================================================
   GEO demo table — keyed by indicator, drives the fly-to when the live enrich
   geo is absent (dormant backend). Coordinates are the located metro; the
   verdict tone/severity size + colour the dropped pin.
   ============================================================ */
const GEO = {
  "185.220.101.34": { pin: PINS[0] },
  "45.146.164.110": { pin: PINS[2] },
  "176.113.115.84": { pin: PINS[3] },
  "20.99.132.44":   { pin: PINS[4] },
  // benign example — still geolocatable, flies + drops a low-tier pin
  "8.8.8.8": { pin: { location:[37.42,-122.08], sev:2, tier:"low", r:unitVec(37.42,-122.08) } }
};

/* ---------- build the ambient pin DOM once ---------- */
function createPins() {
  if (!pinsEl || pinsEl.childElementCount) return;
  const frag = document.createDocumentFragment();
  for (const p of PINS) {
    const d = 9 + p.sev/100 * 13;          // severity -> 9..22px diameter
    const el = document.createElement("div");
    el.className = "pin " + p.tier;
    el.style.setProperty("--d", d.toFixed(1) + "px");
    p.el = el; p.d = d;
    frag.appendChild(el);
  }
  pinsEl.appendChild(frag);
}

/* ---------- live rotation state (theta is animated during fly-to) ---------- */
let phi = 0, targetPhi = 0, theta = THETA;

/* ---------- projection: model-space r -> screen (cobe's exact transform) ---------- */
let projW = 0, projH = 0;
const _o = { x:0, y:0, z:0 };
function projectOne(r, out) {
  const cp = Math.cos(phi), sp = Math.sin(phi);
  const ct = Math.cos(theta), st = Math.sin(theta);
  const fx =  cp*r[0]            + sp*r[2];
  const fy =  sp*st*r[0] + ct*r[1] - cp*st*r[2];
  const fz = -sp*ct*r[0] + st*r[1] + cp*ct*r[2];
  out.x = (fx*0.8 + 1) / 2 * projW;
  out.y = (1 - fy*0.8) / 2 * projH;
  out.z = fz;
}

function projectPins() {
  if (!canvas) return;
  projW = canvas.clientWidth; projH = canvas.clientHeight;
  if (!projW) return;
  const dim = flying ? 0.10 : 1;           // ambient pins yield during the moment
  for (const p of PINS) {
    projectOne(p.r, _o);
    p.sx = _o.x; p.sy = _o.y; p.fz = _o.z;
    const el = p.el; if (!el) continue;
    if (_o.z > 0.02) {                      // front hemisphere -> visible
      const s = 0.82 + _o.z*0.18;           // subtle spatial pop (closer = bigger)
      el.style.setProperty("transform",
        "translate3d(" + _o.x.toFixed(1) + "px," + _o.y.toFixed(1) + "px,0) scale(" + s.toFixed(3) + ")");
      el.style.setProperty("opacity", ((0.42 + _o.z*0.58) * dim).toFixed(3));
    } else {
      el.style.setProperty("opacity", "0"); // back hemisphere -> culled
    }
  }
}

/* ---------- the fly-to landed pin (front-centre drop + pulse) ---------- */
let landed = null;   // {r, tier, sev}
function projectLanded() {
  if (!landedEl || !landed) return;
  projectOne(landed.r, _o);
  landed.sx = _o.x; landed.sy = _o.y; landed.fz = _o.z;
  if (_o.z > -0.02) {
    const s = 0.9 + Math.max(0,_o.z)*0.1;
    landedEl.style.setProperty("transform",
      "translate3d(" + _o.x.toFixed(1) + "px," + _o.y.toFixed(1) + "px,0) scale(" + s.toFixed(3) + ")");
  }
}

/* ---------- hover hit-test + glass verdict tooltip (Option B: verdict accent) ---------- */
let cursor = null, activeId = -1, hovering = false;
function tierAccent(tier) {
  return tier === "crit" ? "var(--red)" : tier === "susp" ? "var(--gold)" : "var(--steam)";
}
function updateActive() {
  let best = -1, bestD = Infinity;
  if (hovering && !dragging && !flying && cursor) {
    for (let i = 0; i < PINS.length; i++) {
      const p = PINS[i];
      if (p.fz <= 0.04) continue;          // front-facing markers only
      const dx = p.sx - cursor.x, dy = p.sy - cursor.y;
      const dist = Math.hypot(dx, dy);
      const thr = p.d/2 + 9;               // generous, forgiving hit radius
      if (dist < thr && dist < bestD) { bestD = dist; best = i; }
    }
  }
  if (best !== activeId) {
    if (activeId >= 0 && PINS[activeId].el) PINS[activeId].el.classList.remove("active");
    activeId = best;
    if (best >= 0) { PINS[best].el.classList.add("active"); populateTip(PINS[best]); }
    else hideTip();
  }
  if (activeId >= 0) positionTip(PINS[activeId]);
}
function populateTip(p) {
  if (!tip) return;
  tip.style.setProperty("--tip-accent", tierAccent(p.tier));
  tip.style.setProperty("--sev", p.sev + "%");
  tip.innerHTML =
    '<div class="tip-head">' +
      '<span class="tip-type">' + p.type + '</span>' +
      '<span class="tip-ind">' + p.ind + '</span>' +
    '</div>' +
    '<div class="tip-body">' +
      '<div class="tip-what">' + p.what + '</div>' +
      '<div class="tip-actor">' + p.actor + '</div>' +
      '<div class="tip-metrics">' +
        '<div class="tip-score">' + p.sev + '<span>/100</span></div>' +
        '<div class="tip-consensus"><b>' + p.consensus + '</b> sources<small>consensus flag</small></div>' +
        '<div class="tip-meter"><i></i></div>' +
      '</div>' +
      '<div class="tip-rows">' +
        '<div class="tip-row"><span class="k">Last seen</span><span class="v mono">' + p.seen + '</span></div>' +
        '<div class="tip-row"><span class="k">Trend</span><span class="v mono tip-trend ' + p.trend.d + '">' + p.trend.t + '</span></div>' +
        '<div class="tip-row"><span class="k">Geo / ASN</span><span class="v mono">' + p.geo + '</span></div>' +
      '</div>' +
    '</div>' +
    '<div class="tip-hint">Enter to open verdict</div>';
  tip.classList.add("show");
  tip.setAttribute("aria-hidden", "false");
}
function positionTip(p) {
  if (!tip || !canvas) return;
  const rect = canvas.getBoundingClientRect();
  const sx = rect.left + p.sx * (rect.width  / canvas.clientWidth);
  const sy = rect.top  + p.sy * (rect.height / canvas.clientHeight);
  const TW = tip.offsetWidth  || 300;
  const TH = tip.offsetHeight || 260;
  const gap = 18;
  let tx = sx + gap;
  if (tx + TW > window.innerWidth - 12) tx = sx - TW - gap;   // flip near the edge
  if (tx < 12) tx = 12;
  let ty = sy - 44;
  if (ty + TH > window.innerHeight - 12) ty = window.innerHeight - 12 - TH;
  if (ty < 12) ty = 12;
  tip.style.setProperty("--tx", tx.toFixed(1) + "px");
  tip.style.setProperty("--ty", ty.toFixed(1) + "px");
}
function hideTip() {
  if (!tip) return;
  tip.classList.remove("show");
  tip.setAttribute("aria-hidden", "true");
}

/* ============================================================
   ZOOM — gesture-only, flicker-free. Growth is a pure compositor transform on
   --globe-grow; the backing store is stable (see build()), so cobe never
   resize()s / clears mid-swell.
   ============================================================ */
const ZMIN = 1.0, ZMAX = 1.6, FLY_ZOOM = 1.42;
// Oversample the backing store so the compositor scale (--globe-grow) stays
// crisp while zooming. Kept modest (not the full ZMAX) and BOUNDED in build():
// an unbounded backing store makes the per-frame fragment shader expensive on
// hi-dpi panels and pathological under a software renderer (headless CI running
// several globes in parallel), where it would starve the main thread.
const SS   = 1.2;
let gz = 1.0, gzTarget = 1.0, gzApplied = -1;
function applyGrow() {
  stage.style.setProperty("--globe-grow", gz.toFixed(4));
  gzApplied = gz;
}
function stepZoom(dt) {
  if (rmq.matches) { gz = gzTarget; }
  else if (Math.abs(gzTarget - gz) > 4e-4) { gz += (gzTarget - gz) * (1 - Math.exp(-dt*9)); }
  else gz = gzTarget;
  if (Math.abs(gz - gzApplied) > 4e-4) applyGrow();
}
function nudgeZoom(delta) {
  gzTarget = Math.max(ZMIN, Math.min(ZMAX, gzTarget + delta));
  if (rmq.matches) { gz = gzTarget; applyGrow(); }
}
function onWheel(e) {
  e.preventDefault();
  wake();
  if (flying) return;
  if (rmq.matches) { nudgeZoom(e.deltaY < 0 ? 0.2 : -0.2); return; }
  nudgeZoom(-e.deltaY * 0.0016);
}
stage.addEventListener("wheel", onWheel, { passive:false });

// two-pointer PINCH over the globe (gesture-only zoom on touch/trackpad)
const pointers = new Map();
let pinchBase = 0;
function pinchDist() {
  const it = [...pointers.values()];
  return Math.hypot(it[0].x - it[1].x, it[0].y - it[1].y);
}
stage.addEventListener("pointerdown", e => {
  pointers.set(e.pointerId, { x:e.clientX, y:e.clientY });
  if (pointers.size === 2) pinchBase = pinchDist();
});
stage.addEventListener("pointermove", e => {
  if (!pointers.has(e.pointerId)) return;
  pointers.set(e.pointerId, { x:e.clientX, y:e.clientY });
  if (pointers.size === 2 && pinchBase > 0) {
    wake();
    const d = pinchDist();
    nudgeZoom((d - pinchBase) * 0.0022);
    pinchBase = d;
  }
}, { passive:true });
function releasePointer(e) {
  pointers.delete(e.pointerId);
  if (pointers.size < 2) pinchBase = 0;
}
stage.addEventListener("pointerup", releasePointer);
stage.addEventListener("pointercancel", releasePointer);

/* ============================================================
   FLY-TO — hand-rolled critically-damped springs on cobe's own loop.
   ============================================================ */
const OMEGA = 7.2;                        // ~0.8s snappy settle (critical)
function spring() { return { x:0, v:0, t:0 }; }
function stepSpring(s, dt, omega) {
  const x0 = s.x - s.t;
  const c2 = s.v + omega*x0;
  const e  = Math.exp(-omega*dt);
  s.x = s.t + (x0 + c2*dt)*e;
  s.v = (c2 - omega*(x0 + c2*dt))*e;
}
function settled(s, ep, ev) { return Math.abs(s.x - s.t) < (ep||0.004) && Math.abs(s.v) < (ev||0.03); }

const flyPhi = spring(), flyTheta = spring(), flyGz = spring();
let flying = false, flyBackMode = false, spinSuspended = false, landedShown = false;

// one beat: the located pin drops + pulses once
function beat() {
  if (!landedEl) return;
  landedShown = true;
  landedEl.classList.add("show");
  void landedEl.offsetWidth;               // retrigger the one-shot drop + pulse
  landedEl.classList.add("dropping", "pulsing");
}

function flyToPin(pin) {
  if (!pin || !pin.r) return;
  wake();                                   // resume a parked (software) loop so the fly renders
  hideTip();
  // targets that bring pin.r to front-centre (derived from projectOne):
  let phiT = Math.atan2(-pin.r[0], pin.r[2]);
  while (phiT - phi >  PI) phiT -= 2*PI;    // take the short way round
  while (phi - phiT >  PI) phiT += 2*PI;
  const thetaT = Math.max(-1.05, Math.min(1.05, Math.asin(Math.max(-1, Math.min(1, pin.r[1])))));

  // landed pin: verdict-toned, sized (a touch larger than ambient) by severity
  const sev = Number.isFinite(pin.sev) ? pin.sev : 60;
  landed = { r:pin.r, tier:pin.tier, sev, sx:-1, sy:-1, fz:-1 };
  const d = 14 + sev/100 * 12;
  if (landedEl) {
    landedEl.style.setProperty("--d", d.toFixed(1) + "px");
    landedEl.style.setProperty("--pin", tierAccent(pin.tier));
    landedEl.classList.remove("show", "dropping", "pulsing");
  }
  landedShown = false;

  if (rmq.matches) {
    // reduced-motion: snap directly to the located end-state, no animation
    phi = phiT; targetPhi = phiT; theta = thetaT; gz = FLY_ZOOM; gzTarget = FLY_ZOOM;
    applyGrow(); projectPins(); projectLanded();
    flying = false; flyBackMode = false; spinSuspended = true;
    beat();
    return;
  }
  flyPhi.x = phi;     flyPhi.v = 0;   flyPhi.t = phiT;
  flyTheta.x = theta; flyTheta.v = 0; flyTheta.t = thetaT;
  flyGz.x = gz;       flyGz.v = 0;    flyGz.t = FLY_ZOOM;
  flying = true; flyBackMode = false; spinSuspended = true;
}

function flyBack() {
  if (!flying && !landed && !landedShown) return;   // nothing to undo (don't reset stray zoom)
  wake();
  if (landedEl) landedEl.classList.remove("show", "dropping", "pulsing");
  landedShown = false;
  if (rmq.matches) {
    theta = THETA; gz = 1.0; gzTarget = 1.0; applyGrow();
    flying = false; spinSuspended = false; landed = null; return;
  }
  flyPhi.x = phi;     flyPhi.v = 0;   flyPhi.t = phi;    // keep phi (no unwind)
  flyTheta.x = theta; flyTheta.v = 0; flyTheta.t = THETA;
  flyGz.x = gz;       flyGz.v = 0;    flyGz.t = 1.0;
  gzTarget = 1.0;                                        // reset wheel-zoom target too
  flying = true; flyBackMode = true; spinSuspended = true;
}

/* ============================================================
   GLOBE LIFECYCLE — build with a STABLE high-res backing store.
   ============================================================ */
let globe = null, dragging = false, lastX = 0, rafSpin = true, parked = false;
let cobeDpr = 1, spinFactor = 1, lastT = 0, idleT = null;

// SOFTWARE-RENDERER scheduler: on a GPU-less device / in headless CI the globe
// parks its render loop when idle (no continuous cost), and any interaction
// (drag, zoom, hover, fly-to) WAKES it; it re-parks a beat after activity
// stops. On a real GPU (lowPerf === false) both are no-ops and the loop runs
// continuously as normal. This is what keeps parallel headless globes from
// starving the main thread while still letting the fly-to actually animate.
function wake() {
  if (!lowPerf) return;
  if (globe && parked && globe.toggle) { parked = false; globe.toggle(true); }
  armIdle();
}
function armIdle() {
  if (!lowPerf) return;
  clearTimeout(idleT);
  idleT = setTimeout(function check() {
    if (!lowPerf || !globe || !globe.toggle) return;
    if (flying || dragging) { idleT = setTimeout(check, 400); return; }   // still busy
    parked = true; globe.toggle(false);
  }, 1400);
}

function build() {
  if (globe) return;
  if (!canvas.clientWidth) return;                // hidden (mobile) or unlaid-out
  const reduce = rmq.matches;
  const dpr = Math.min(window.devicePixelRatio || 1, 2);   // cap DPR at 2
  const size = canvas.clientWidth;
  // STABLE oversample, but cap the backing store per side so neither a hi-dpi
  // panel nor a software renderer pays an unbounded fragment cost. cobe's
  // per-fragment shader cost scales with backing-store AREA, not with
  // mapSamples — so the denser dots below are effectively free. Software
  // renderers get a much tighter cap (see lowPerf).
  cobeDpr = Math.min(dpr * SS, (lowPerf ? 400 : 1200) / size);
  const p = palette(resolveDark());
  // A software renderer can't afford a continuous loop; render a static frame
  // there (no auto-spin) and park it shortly after paint (below).
  rafSpin = !reduce && !lowPerf;
  parked = false;
  lastT = 0;

  try {
    globe = createGlobe(canvas, {
      devicePixelRatio: cobeDpr,
      width:  size * cobeDpr,
      height: size * cobeDpr,
      phi, theta,
      dark: p.dark, diffuse: p.diffuse,
      mapSamples: 22000,                           // denser dots (#7)
      mapBrightness: p.mapBrightness,
      mapBaseBrightness: p.mapBaseBrightness,
      baseColor:   p.base,
      markerColor: p.marker,
      glowColor:   p.glow,
      opacity: p.opacity,
      markers: [],                                 // pins are the DOM overlay
      onRender(state) {
        const now = performance.now();
        let dt = lastT ? (now - lastT) / 1000 : 0.0167;
        lastT = now;
        if (dt > 0.05) dt = 0.05;                  // clamp (throttle / tab blur)

        if (flying) {
          stepSpring(flyPhi, dt, OMEGA);   phi = flyPhi.x; targetPhi = phi;
          stepSpring(flyTheta, dt, OMEGA); theta = flyTheta.x;
          stepSpring(flyGz, dt, OMEGA);    gz = flyGz.x; applyGrow();
          // fire the beat as the point swings to the front (cohesive, not late)
          if (!flyBackMode && !landedShown) {
            projectLanded();
            if (landed && landed.fz > 0.82) beat();
          }
          if (settled(flyPhi) && settled(flyTheta) && settled(flyGz, 0.004, 0.05)) {
            flying = false;
            if (flyBackMode) { flyBackMode = false; spinSuspended = false; landed = null; }
            else { gzTarget = gz; if (!landedShown) beat(); }
          }
        } else {
          // ambient — graded 3-state spin
          let ts = 1;
          if (dragging || spinSuspended) ts = 0;
          else if (activeId >= 0) ts = 0;          // on a pin -> full halt
          else if (hovering) ts = 0.30;            // over the canvas -> ~30%
          spinFactor += (ts - spinFactor) * (1 - Math.exp(-dt*7));
          if (rafSpin && !dragging) targetPhi += 0.0035 * (dt*60) * spinFactor;
          phi += (targetPhi - phi) * (1 - Math.exp(-dt*6.5));
          if (!landed) theta += (THETA - theta) * (1 - Math.exp(-dt*6.5));
          stepZoom(dt);
        }

        state.phi = phi;
        state.theta = theta;
        const w = canvas.clientWidth * cobeDpr;    // keep resolution uniform in sync
        state.width = w; state.height = w;
        projectPins();
        projectLanded();
        updateActive();
      }
    });
  } catch (_) {
    // No WebGL (or a context refusal): leave the hero copy untouched, no console
    // noise. The omnibox + console still work; the globe is purely atmosphere.
    globe = null;
    return;
  }

  requestAnimationFrame(() => {
    canvas.classList.add("globe-ready");
    hero.classList.add("loaded");
  });

  // Software renderer: arm the idle-park countdown (see wake/armIdle). The loop
  // paints while settling, then parks; interactions wake it on demand.
  if (lowPerf) armIdle();
}

function destroy() {
  if (globe) { try { globe.destroy(); } catch (_) {} globe = null; }
  hideTip();
}

// theme re-init: colours are baked at createGlobe, so destroy->rebuild while
// CARRYING phi/theta/gz (module globals persist). Debounced against toggle thrash.
let reTimer = null;
function rebuild() {
  clearTimeout(reTimer);
  reTimer = setTimeout(() => {
    if (!globe) return;                            // nothing live to recolor
    destroy();
    build();
  }, 120);
}

/* ---------- drag to rotate; drag overrides / interrupts a fly ---------- */
if (!rmq.matches) {
  canvas.addEventListener("pointerdown", e => {
    wake();
    dragging = true; lastX = e.clientX;
    if (flying && !flyBackMode) flying = false;    // hand control to the drag
    stage.classList.add("dragging");
    if (canvas.setPointerCapture && e.pointerId != null) {
      try { canvas.setPointerCapture(e.pointerId); } catch (_) {}
    }
  });
  window.addEventListener("pointermove", e => {
    if (!dragging) return;
    targetPhi += (e.clientX - lastX) * 0.005;      // mutate target; phi lerps in onRender
    lastX = e.clientX;
  }, { passive:true });
  const endDrag = () => { dragging = false; stage.classList.remove("dragging"); };
  window.addEventListener("pointerup", endDrag);
  window.addEventListener("pointercancel", endDrag);
}
// hover state for the graded spin + tooltip (works in reduced-motion too)
stage.addEventListener("pointerenter", () => { wake(); hovering = true; if (hint) hint.classList.add("show"); });
stage.addEventListener("pointerleave", () => { hovering = false; cursor = null; if (hint) hint.classList.remove("show"); });
stage.addEventListener("pointermove", e => {
  if (!canvas.clientWidth) return;
  wake();                                          // keep the (software) loop alive while hovering
  const rect = canvas.getBoundingClientRect();
  cursor = {
    x: (e.clientX - rect.left) / rect.width  * canvas.clientWidth,
    y: (e.clientY - rect.top)  / rect.height * canvas.clientHeight
  };
});

/* ---------- lifecycle: build when hero visible, free when gone ---------- */
createPins();
const gio = new IntersectionObserver(entries => {
  for (const en of entries) {
    if (en.isIntersecting) { if (!globe) build(); }
    else if (globe) destroy();                     // free the GL context; keep phi/theta/gz
  }
}, { threshold: 0 });
gio.observe(hero);

// pause the GL loop when the tab is backgrounded (cobe self-schedules its rAF;
// toggle(false) halts it, toggle(true) resumes) — no cost while hidden
document.addEventListener("visibilitychange", () => {
  if (globe && globe.toggle) globe.toggle(!document.hidden && !parked);
});

// recolor on theme change (explicit toggle sets <html data-theme>; System clears
// it and lets the OS preference govern)
new MutationObserver(rebuild).observe(root, { attributes:true, attributeFilter:["data-theme"] });
dpq.addEventListener("change", () => { if (!root.getAttribute("data-theme")) rebuild(); });

/* ============================================================
   FLY-TO WIRING — omnibox (demo geo table) + live enrich (dormant today).
   ============================================================ */
function flyToIndicator(raw) {
  const v = String(raw || "").trim();
  if (!v) return false;
  const rec = GEO[v];
  if (rec) { flyToPin(rec.pin); return true; }
  return false;
}
// a live /api/enrich result -> plot the real coordinates
function flyToLatLng(lat, lng, opts = {}) {
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return;
  flyToPin({ r: unitVec(lat, lng), tier: opts.tier || "crit", sev: Number.isFinite(opts.sev) ? opts.sev : 70 });
}

if (input) {
  input.addEventListener("keydown", e => { if (e.key === "Enter") flyToIndicator(input.value); });
  input.addEventListener("input", () => { if (input.value.trim() === "") flyBack(); });
}
if (histRow) {
  histRow.addEventListener("click", e => {
    const b = e.target.closest("button");
    if (!b) return;
    flyToIndicator(b.dataset.h || b.textContent.trim().split(/\s+/)[0]);
  });
}
window.addEventListener("keydown", e => { if (e.key === "Escape") flyBack(); });

// live enrich geo (enrich-client.js dispatches this once /api/enrich resolves).
// Dormant on the static tier — degrades to no-fly. The ipinfo context row
// carries a "Coordinates" fact as "lat,lng"; tone -> tier, ratio -> severity.
function geoFromResult(result) {
  if (!result || !Array.isArray(result.sources)) return null;
  const ctx = result.sources.find(s => s && s.kind === "context");
  if (!ctx || !Array.isArray(ctx.facts)) return null;
  const co = ctx.facts.find(f => Array.isArray(f) && /coordinates/i.test(f[0]));
  if (!co) return null;
  const m = String(co[1]).match(/^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*$/);
  if (!m) return null;
  const tier = result.tone === "red" ? "crit" : result.tone === "amber" ? "susp" : "low";
  const ratio = result.consulted ? result.flagged / result.consulted : 0;
  return { lat: parseFloat(m[1]), lng: parseFloat(m[2]), tier, sev: Math.round(ratio * 100) };
}
document.addEventListener("socdesk:enrich-result", e => {
  try {
    const g = geoFromResult(e.detail);
    if (g) flyToLatLng(g.lat, g.lng, { tier: g.tier, sev: g.sev });
  } catch (_) {}
});

// small public surface for future live-geo callers
window.socdeskGlobe = { flyToLatLng, flyToIndicator, flyBack };

// hide the tooltip while the page scrolls (the globe recedes under later content)
window.addEventListener("scroll", () => { if (activeId >= 0) { hovering = false; cursor = null; } }, { passive:true });

}
