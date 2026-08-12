/* ============================================================
   SOCDesk — Home Hero mockup behaviour.
   cobe globe (matte periwinkle, halo killed) + drag inertia,
   theme re-init (destroy->rebuild carrying phi), reduced-motion
   static frame, vanilla rAF count-up, IntersectionObserver
   reveal/melt fallback. No JS animation library.

   THIS PASS:
   · ZOOM (flicker-free) — a STABLE high-resolution backing store
     (cobe's devicePixelRatio bumped once at build) + growth as a PURE
     compositor transform (scale(--globe-grow)). cobe never resize()s /
     clears mid-swell, so the dots stay crisp at every zoom and never flash.
   · GRADED 3-STATE HOVER-SPIN — off-globe = full auto-spin; over the
     canvas (not a pin) = ease down to ~30%; over a PIN = fully halt (phi
     freezes so the tooltip/pin stay put). Eased between states; drag overrides.
   · COMMITTED verdict-toned pins (Option B), no dev HUD, gesture-only zoom
     (wheel + pinch over the canvas, preventDefault only there).
   · FLY-TO — submit a geolocatable IOC and the globe SPRINGS to the location
     (critically-damped, hand-rolled, on cobe's own loop — no lib), zoom-grows
     in, the located pin DROPS + pulses once, and the glass escalation card
     resolves in as one beat. Esc / clearing the box flies back out.

   CSP-safe: every runtime style write goes through element.style.setProperty
   / CSSOM property assignment — never setAttribute('style', ...).
   ============================================================ */
import createGlobe from './vendor/cobe.js';

const root   = document.documentElement;
root.classList.add('js');

const canvas   = document.getElementById('globe');
const stage    = document.getElementById('globeStage');
const pinsEl   = document.getElementById('globePins');
const landedEl = document.getElementById('landedPin');
const tip      = document.getElementById('pinTip');
const hint     = document.getElementById('globeHint');
const card     = document.getElementById('escCard');
const linkEl   = document.getElementById('escLink');
const linkLine = linkEl ? linkEl.querySelector('line') : null;
const hero     = document.getElementById('hero');
const search   = document.getElementById('heroSearch');
const toggle   = document.getElementById('themeToggle');
const input    = document.getElementById('q');
const detect   = document.getElementById('detect');
const histRow  = document.getElementById('histRow');

const rmq = matchMedia('(prefers-reduced-motion: reduce)');
const dpq = matchMedia('(prefers-color-scheme: dark)');

/* ---------- theme resolution ---------- */
function resolveDark(){
  const t = root.getAttribute('data-theme');
  if (t === 'dark')  return true;
  if (t === 'light') return false;
  return dpq.matches;
}

/* ---------- globe palette (from tokens.css, [r,g,b] in 0..1) ---------- */
function palette(dark){
  return dark ? {
    base:[0.42,0.46,0.78],   // matte periwinkle land dots
    marker:[0.49,0.54,1.0],  // --accent #7C8AFF
    glow:[0.08,0.06,0.04],   // --ink #15100A -> KILLS the halo
    dark:1, mapBrightness:6, mapBaseBrightness:0, diffuse:1.1, opacity:0.95
  } : {
    // LIGHT — cobe renders an OPAQUE sphere, so the dark theme's "periwinkle
    // dots on an invisible ocean" can't be mirrored on cream. The fix is a
    // WARM GREIGE INSTRUMENT, not a black orb: a low `dark` keeps the sphere
    // body a warm mid-tone (never black); a periwinkle-leaning greige base +
    // brighter periwinkle markers keep the DOTS reading as the signal; reduced
    // `opacity` lets it sit as an elegant element on paper. Halo still killed
    // (glow == paper ink). Chosen candidate L2 (see return notes).
    base:[0.51,0.49,0.585],  // warm greige w/ a periwinkle lean (sphere body)
    marker:[0.30,0.33,0.90], // saturated periwinkle markers pop on the greige
    glow:[0.96,0.91,0.83],   // --ink #F2E6D0 (paper) -> KILLS the halo
    dark:0.50, mapBrightness:5.6, mapBaseBrightness:0.30, diffuse:1.30, opacity:0.72
  };
}

/* ============================================================
   TI PINS — analyst-grade mock indicators (<=12). Real metro coords.
   Committed to Option B: colour by verdict tier, sized by severity.
   Pins are a projected DOM overlay (cobe's markerColor is one uniform).
   ============================================================ */
const PI = Math.PI, THETA = 0.18;
const PINS = [
  { location:[50.11,   8.68], sev:94, tier:'crit', type:'IPv4',    ind:'185.220.101.34',
    what:'Cobalt Strike C2 beacon',        actor:'Infra linked to <b>Akira</b> affiliate',
    consensus:'6 of 6', seen:'3 min ago',  trend:{d:'up',  t:'▲ sharp spike'},
    geo:'Frankfurt, DE · AS24940 Hetzner' },
  { location:[52.37,   4.90], sev:88, tier:'crit', type:'DOMAIN',  ind:'login-verify-ms[.]com',
    what:'Credential-harvesting phishing',  actor:'Attributed to <b>Storm-1101</b> (Tycoon 2FA)',
    consensus:'5 of 6', seen:'18 min ago', trend:{d:'up',  t:'▲ rising'},
    geo:'Amsterdam, NL · AS60781 LeaseWeb' },
  { location:[55.75,  37.61], sev:91, tier:'crit', type:'IPv4',    ind:'45.146.164.110',
    what:'Ransomware staging & exfil node', actor:'Linked to <b>LockBit</b> rebuild infra',
    consensus:'6 of 6', seen:'1 hr ago',   trend:{d:'flat',t:'▶ steady'},
    geo:'Moscow, RU · AS56694 SmartApe' },
  { location:[50.45,  30.52], sev:84, tier:'crit', type:'IPv4',    ind:'176.113.115.84',
    what:'SonicWall SSL-VPN exploit host',  actor:'<b>Akira</b> initial-access broker',
    consensus:'5 of 6', seen:'42 min ago', trend:{d:'up',  t:'▲ rising'},
    geo:'Kyiv, UA · AS44094 IT-Grad' },
  { location:[37.77,-122.42], sev:67, tier:'susp', type:'IPv4',    ind:'20.99.132.44',
    what:'APT29 spearphish sender infra',   actor:'Attributed to <b>APT29</b> (Midnight Blizzard)',
    consensus:'4 of 6', seen:'3 hr ago',   trend:{d:'up',  t:'▲ campaign active'},
    geo:'San Francisco, US · AS8075 Microsoft' },
  { location:[ 1.35, 103.82], sev:71, tier:'susp', type:'IPv4',    ind:'139.180.203.12',
    what:'Tor exit relay',                  actor:'No attributed actor',
    consensus:'3 of 6', seen:'26 min ago', trend:{d:'flat',t:'▶ steady'},
    geo:'Singapore, SG · AS20473 Vultr' },
  { location:[40.71, -74.00], sev:62, tier:'susp', type:'SHA-256', ind:'7f9c34e2…a3e1',
    what:'RedLine infostealer sample',      actor:'Commodity crimeware, no crew',
    consensus:'4 of 6', seen:'2 hr ago',   trend:{d:'up',  t:'▲ new variant'},
    geo:'New York, US · AS14061 DigitalOcean' },
  { location:[51.51,  -0.13], sev:55, tier:'susp', type:'DOMAIN',  ind:'cdn-analytics-cloud[.]net',
    what:'Malware distribution CDN',        actor:'Linked to <b>SocGholish</b> cluster',
    consensus:'4 of 6', seen:'4 hr ago',   trend:{d:'down',t:'▼ cooling'},
    geo:'London, GB · AS16509 Amazon' },
  { location:[-23.55,-46.63], sev:43, tier:'low',  type:'IPv4',    ind:'191.96.150.10',
    what:'Brute-force / scanning source',   actor:'Mirai-class botnet node',
    consensus:'2 of 6', seen:'6 hr ago',   trend:{d:'flat',t:'▶ steady'},
    geo:'São Paulo, BR · AS262287 Latitude' },
  { location:[35.68, 139.69], sev:38, tier:'low',  type:'DOMAIN',  ind:'update-pkg-mirror[.]org',
    what:'Newly-registered suspicious domain', actor:'Unclassified',
    consensus:'2 of 6', seen:'9 hr ago',   trend:{d:'up',  t:'▲ slight uptick'},
    geo:'Tokyo, JP · AS7506 GMO' },
  { location:[19.08,  72.88], sev:29, tier:'low',  type:'MD5',     ind:'3ab5f1c0…9f02',
    what:'Adware / PUP bundle',             actor:'Commodity, no attribution',
    consensus:'1 of 6', seen:'13 hr ago',  trend:{d:'down',t:'▼ declining'},
    geo:'Mumbai, IN · AS4755 TATA' }
];
// unit model-space vector for each marker (matches cobe's marker fn:
// lat->i rad, lng->s=rad-PI; r = [-cos(i)cos(s), sin(i), cos(i)sin(s)])
function unitVec(lat, lng){
  const i = lat*PI/180, s = lng*PI/180 - PI, cl = Math.cos(i);
  return [-cl*Math.cos(s), Math.sin(i), cl*Math.sin(s)];
}
for (const p of PINS){
  p.r = unitVec(p.location[0], p.location[1]);
  p.el = null; p.sx = -1; p.sy = -1; p.fz = -1;
}

/* ============================================================
   GEO / verdict mock — a small analyst-grade table keyed by indicator.
   Drives the fly-to + the escalation card (consensus tally per
   docs/VERDICT-LANGUAGE.md: N of M sources flagged; benign shown; the tally
   is the answer, never a SOCDesk-voice verdict word).
   ============================================================ */
const GEO = {
  '185.220.101.34': {
    pin: PINS[0], flagged:6, consulted:6, tone:'red', gen:'14:22 UTC',
    headline:'consulted sources flagged this as adverse.',
    what:'Cobalt Strike C2 beacon', attribution:'Akira affiliate infrastructure',
    note:'Strongest signal: MalwareBazaar catalogs 3 samples beaconing here. Tagged Tor exit — elevated reports can reflect dual-use traffic.',
    sources:[
      ['bad','AbuseIPDB','reports 100% abuse confidence, 1,204 reports'],
      ['bad','GreyNoise','classifies malicious; observed C2 callbacks; tagged Tor exit'],
      ['bad','VirusTotal','11 / 94 vendors flag this address'],
      ['bad','MalwareBazaar','catalogs 3 known samples (Cobalt Strike)'],
      ['ctx','ipinfo','AS24940 Hetzner, Frankfurt DE · context, not a verdict']
    ]
  },
  '45.146.164.110': {
    pin: PINS[2], flagged:6, consulted:6, tone:'red', gen:'14:22 UTC',
    headline:'consulted sources flagged this as adverse.',
    what:'Ransomware staging & exfil node', attribution:'LockBit rebuild infrastructure',
    note:'Strongest signal: GreyNoise observed data-exfil patterns; AbuseIPDB reporting sharp over 24h.',
    sources:[
      ['bad','AbuseIPDB','reports 96% abuse confidence, 842 reports'],
      ['bad','GreyNoise','classifies malicious; observed scanning + exfil'],
      ['bad','VirusTotal','9 / 94 vendors flag this address'],
      ['bad','Spamhaus','lists in DROP (do-not-route) advisory'],
      ['ctx','ipinfo','AS56694 SmartApe, Moscow RU · context, not a verdict']
    ]
  },
  '176.113.115.84': {
    pin: PINS[3], flagged:5, consulted:6, tone:'red', gen:'14:22 UTC',
    headline:'consulted sources flagged this as adverse.',
    what:'SonicWall SSL-VPN exploit host', attribution:'Akira initial-access broker',
    note:'Strongest signal: Shadowserver observed exploit attempts against CVE-2024-40766.',
    sources:[
      ['bad','AbuseIPDB','reports 88% abuse confidence, 401 reports'],
      ['bad','GreyNoise','classifies malicious; VPN brute-force + exploit'],
      ['bad','Shadowserver','observed exploitation of CVE-2024-40766'],
      ['ok','VirusTotal','0 / 94 vendors flag — no detection on record'],
      ['bad','AlienVault OTX','2 pulses reference this host (Akira)'],
      ['ctx','ipinfo','AS44094 IT-Grad, Kyiv UA · context, not a verdict']
    ]
  },
  '20.99.132.44': {
    pin: PINS[4], flagged:4, consulted:6, tone:'amber', gen:'14:22 UTC',
    headline:'consulted sources flagged this as adverse.',
    what:'APT29 spearphish sender infra', attribution:'APT29 (Midnight Blizzard)',
    note:'Shared Microsoft Azure space — scope to the observed sender, not the ASN.',
    sources:[
      ['bad','AbuseIPDB','reports 54% abuse confidence, 66 reports'],
      ['bad','GreyNoise','classifies suspicious; malformed SMTP + auth probes'],
      ['bad','AlienVault OTX','1 pulse references this host (APT29)'],
      ['bad','urlscan','prior scan rated malicious (phishing kit)'],
      ['ok','VirusTotal','0 / 94 vendors flag — no detection on record'],
      ['ctx','ipinfo','AS8075 Microsoft, San Francisco US · context, not a verdict']
    ]
  },
  // benign example — the tally must show "0 of M ... not a clearance"
  '8.8.8.8': {
    pin: { location:[37.42,-122.08], sev:2, tier:'low', type:'IPv4', ind:'8.8.8.8',
           geo:'Mountain View, US · AS15169 Google', seen:'—', r:unitVec(37.42,-122.08) },
    flagged:0, consulted:6, tone:'green', gen:'14:22 UTC',
    headline:'consulted sources flagged this — no adverse findings. Not a clearance.',
    what:'Google Public DNS resolver', attribution:'Google LLC — legitimate service',
    note:'A benign result is not a clearance; it reflects only what public sources report.',
    sources:[
      ['ok','GreyNoise','classifies benign (RIOT: common business service)'],
      ['ok','AbuseIPDB','reports 0% abuse confidence, 0 reports'],
      ['ok','VirusTotal','0 / 94 vendors flag this address'],
      ['ctx','ipinfo','AS15169 Google, Mountain View US · context, not a verdict']
    ]
  }
};

/* ---------- build the ambient pin DOM once ---------- */
function createPins(){
  if (!pinsEl || pinsEl.childElementCount) return;
  const frag = document.createDocumentFragment();
  for (const p of PINS){
    const d = 9 + p.sev/100 * 13;          // severity -> 9..22px diameter
    const el = document.createElement('div');
    el.className = 'pin ' + p.tier;
    el.style.setProperty('--d', d.toFixed(1) + 'px');
    p.el = el; p.d = d;
    frag.appendChild(el);
  }
  pinsEl.appendChild(frag);
}

/* ---------- live rotation state (theta is animated during fly-to) ---------- */
let phi = 0, targetPhi = 0, theta = THETA;

/* ---------- projection: model-space r -> screen (cobe's exact transform,
   now with the LIVE theta so pins/landed track a tilt during fly-to). ---------- */
function projectOne(r, out){
  const cp = Math.cos(phi), sp = Math.sin(phi);
  const ct = Math.cos(theta), st = Math.sin(theta);
  const fx =  cp*r[0]            + sp*r[2];
  const fy =  sp*st*r[0] + ct*r[1] - cp*st*r[2];
  const fz = -sp*ct*r[0] + st*r[1] + cp*ct*r[2];
  out.x = (fx*0.8 + 1) / 2 * projW;
  out.y = (1 - fy*0.8) / 2 * projH;
  out.z = fz;
}
let projW = 0, projH = 0;
const _o = { x:0, y:0, z:0 };

function projectPins(){
  if (!canvas) return;
  projW = canvas.clientWidth; projH = canvas.clientHeight;
  if (!projW) return;
  const dim = (flying || cardShown) ? 0.10 : 1;   // ambient pins yield during the moment
  for (const p of PINS){
    projectOne(p.r, _o);
    p.sx = _o.x; p.sy = _o.y; p.fz = _o.z;
    const el = p.el; if (!el) continue;
    if (_o.z > 0.02){                       // front hemisphere -> visible
      const s = 0.82 + _o.z*0.18;           // subtle spatial pop (closer = bigger)
      el.style.setProperty('transform',
        'translate3d(' + _o.x.toFixed(1) + 'px,' + _o.y.toFixed(1) + 'px,0) scale(' + s.toFixed(3) + ')');
      el.style.setProperty('opacity', ((0.42 + _o.z*0.58) * dim).toFixed(3));
    } else {
      el.style.setProperty('opacity', '0'); // back hemisphere -> culled
    }
  }
}

/* ---------- the fly-to landed pin (front-centre drop + pulse) ---------- */
let landed = null;   // {r, tier, sev}
function projectLanded(){
  if (!landedEl || !landed) return;
  projectOne(landed.r, _o);
  landed.sx = _o.x; landed.sy = _o.y; landed.fz = _o.z;
  if (_o.z > -0.02){
    const s = 0.9 + Math.max(0,_o.z)*0.1;
    landedEl.style.setProperty('transform',
      'translate3d(' + _o.x.toFixed(1) + 'px,' + _o.y.toFixed(1) + 'px,0) scale(' + s.toFixed(3) + ')');
  }
}

/* ---------- hover hit-test + glass verdict tooltip (Option B: verdict accent) ---------- */
let cursor = null, activeId = -1, hovering = false;

function tierAccent(tier){
  return tier === 'crit' ? 'var(--red)' : tier === 'susp' ? 'var(--gold)' : 'var(--steam)';
}
function updateActive(){
  let best = -1, bestD = Infinity;
  if (hovering && !dragging && !flying && !cardShown && cursor){
    for (let i = 0; i < PINS.length; i++){
      const p = PINS[i];
      if (p.fz <= 0.04) continue;          // front-facing markers only
      const dx = p.sx - cursor.x, dy = p.sy - cursor.y;
      const dist = Math.hypot(dx, dy);
      const thr = p.d/2 + 9;               // generous, forgiving hit radius
      if (dist < thr && dist < bestD){ bestD = dist; best = i; }
    }
  }
  if (best !== activeId){
    if (activeId >= 0 && PINS[activeId].el) PINS[activeId].el.classList.remove('active');
    activeId = best;
    if (best >= 0){ PINS[best].el.classList.add('active'); populateTip(PINS[best]); }
    else hideTip();
  }
  if (activeId >= 0) positionTip(PINS[activeId]);
}
function populateTip(p){
  if (!tip) return;
  tip.style.setProperty('--tip-accent', tierAccent(p.tier));
  tip.style.setProperty('--sev', p.sev + '%');
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
  tip.classList.add('show');
  tip.setAttribute('aria-hidden', 'false');
}
function positionTip(p){
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
  tip.style.setProperty('--tx', tx.toFixed(1) + 'px');
  tip.style.setProperty('--ty', ty.toFixed(1) + 'px');
}
function hideTip(){
  if (!tip) return;
  tip.classList.remove('show');
  tip.setAttribute('aria-hidden', 'true');
}

/* ============================================================
   ZOOM — gesture-only, flicker-free.
   Growth is a pure compositor transform on --globe-grow; the backing store
   is stable (see build()), so cobe never resize()s / clears mid-swell.
   ============================================================ */
const ZMIN = 1.0, ZMAX = 1.6, FLY_ZOOM = 1.42;
const SS   = Math.max(ZMAX, FLY_ZOOM);   // supersample: crisp up to max display zoom
let gz = 1.0, gzTarget = 1.0, gzApplied = -1;

function applyGrow(){
  hero.style.setProperty('--globe-grow', gz.toFixed(4));
  hero.style.setProperty('--zoom01', Math.max(0, Math.min(1, (gz - ZMIN) / (ZMAX - ZMIN))).toFixed(4));
  gzApplied = gz;
}
function stepZoom(dt){
  if (rmq.matches){ gz = gzTarget; }
  else if (Math.abs(gzTarget - gz) > 4e-4){ gz += (gzTarget - gz) * (1 - Math.exp(-dt*9)); }
  else gz = gzTarget;
  if (Math.abs(gz - gzApplied) > 4e-4) applyGrow();
}
function nudgeZoom(delta){
  gzTarget = Math.max(ZMIN, Math.min(ZMAX, gzTarget + delta));
  if (rmq.matches){ gz = gzTarget; applyGrow(); }
}
// wheel / trackpad-pinch over the globe only — preventDefault here so the page
// never scrolls while the pointer is on the instrument.
function onWheel(e){
  e.preventDefault();
  if (flying) return;
  if (rmq.matches){ nudgeZoom(e.deltaY < 0 ? 0.2 : -0.2); return; }
  nudgeZoom(-e.deltaY * 0.0016);
}
if (stage) stage.addEventListener('wheel', onWheel, { passive:false });

// two-pointer PINCH over the globe (gesture-only zoom on touch/trackpad)
const pointers = new Map();
let pinchBase = 0;
function pinchDist(){
  const it = [...pointers.values()];
  return Math.hypot(it[0].x - it[1].x, it[0].y - it[1].y);
}
function onPointerDownStage(e){
  pointers.set(e.pointerId, { x:e.clientX, y:e.clientY });
  if (pointers.size === 2){ pinchBase = pinchDist(); }
}
function onPointerMoveStage(e){
  if (!pointers.has(e.pointerId)) return;
  pointers.set(e.pointerId, { x:e.clientX, y:e.clientY });
  if (pointers.size === 2 && pinchBase > 0){
    const d = pinchDist();
    nudgeZoom((d - pinchBase) * 0.0022);
    pinchBase = d;
  }
}
function onPointerUpStage(e){
  pointers.delete(e.pointerId);
  if (pointers.size < 2) pinchBase = 0;
}
if (stage){
  stage.addEventListener('pointerdown', onPointerDownStage);
  stage.addEventListener('pointermove', onPointerMoveStage, { passive:true });
  stage.addEventListener('pointerup', onPointerUpStage);
  stage.addEventListener('pointercancel', onPointerUpStage);
}

/* ============================================================
   FLY-TO — hand-rolled critically-damped springs on cobe's own loop.
   ============================================================ */
const OMEGA = 7.2;                        // ~0.8s snappy settle (critical)
function spring(){ return { x:0, v:0, t:0 }; }
function stepSpring(s, dt, omega){
  const x0 = s.x - s.t;
  const c2 = s.v + omega*x0;
  const e  = Math.exp(-omega*dt);
  s.x = s.t + (x0 + c2*dt)*e;
  s.v = (c2 - omega*(x0 + c2*dt))*e;
}
function settled(s, ep, ev){ return Math.abs(s.x - s.t) < (ep||0.004) && Math.abs(s.v) < (ev||0.03); }

const flyPhi = spring(), flyTheta = spring(), flyGz = spring();
let flying = false, flyBackMode = false, spinSuspended = false;
let landedShown = false, cardShown = false;

function flyTo(rec){
  const p = rec.pin;
  hideTip();
  // targets that bring p.r to front-centre (derived from projectOne):
  let phiT = Math.atan2(-p.r[0], p.r[2]);
  while (phiT - phi >  PI) phiT -= 2*PI;   // take the short way round
  while (phi - phiT >  PI) phiT += 2*PI;
  const thetaT = Math.max(-1.05, Math.min(1.05, Math.asin(Math.max(-1, Math.min(1, p.r[1])))));

  // landed pin: verdict-toned, sized (a touch larger than ambient) by severity
  landed = { r:p.r, tier:p.tier, sev:p.sev, sx:-1, sy:-1, fz:-1 };
  const d = 14 + p.sev/100 * 12;
  landedEl.style.setProperty('--d', d.toFixed(1) + 'px');
  landedEl.style.setProperty('--pin', tierAccent(p.tier));
  landedEl.classList.remove('show','dropping','pulsing');
  hero.classList.add('answering');
  pendingCard = rec;
  landedShown = false;

  if (rmq.matches){
    // reduced-motion: snap directly to the located + card end-state
    phi = phiT; targetPhi = phiT; theta = thetaT; gz = FLY_ZOOM; gzTarget = FLY_ZOOM;
    applyGrow(); projectPins(); projectLanded();
    flying = false; flyBackMode = false; spinSuspended = true;
    beat();
    return;
  }
  flyPhi.x = phi;   flyPhi.v = 0;   flyPhi.t = phiT;
  flyTheta.x = theta; flyTheta.v = 0; flyTheta.t = thetaT;
  flyGz.x = gz;     flyGz.v = 0;     flyGz.t = FLY_ZOOM;
  flying = true; flyBackMode = false; spinSuspended = true;
}

function flyBack(){
  hideCard();
  if (linkEl) linkEl.classList.remove('show');
  landedEl.classList.remove('show','dropping','pulsing');
  hero.classList.remove('answering');
  landedShown = false; pendingCard = null;
  if (rmq.matches){
    theta = THETA; gz = 1.0; gzTarget = 1.0; applyGrow();
    flying = false; spinSuspended = false; landed = null; return;
  }
  flyPhi.x = phi;   flyPhi.v = 0;   flyPhi.t = phi;     // keep phi (no unwind)
  flyTheta.x = theta; flyTheta.v = 0; flyTheta.t = THETA;
  flyGz.x = gz;     flyGz.v = 0;     flyGz.t = 1.0;
  gzTarget = 1.0;                                       // reset wheel-zoom target too
  flying = true; flyBackMode = true; spinSuspended = true;
}

// one beat: the located pin drops + pulses AND the card resolves in together
let pendingCard = null;
function beat(){
  landedShown = true;
  landedEl.classList.add('show');
  // retrigger the one-shot drop + pulse
  void landedEl.offsetWidth;
  landedEl.classList.add('dropping','pulsing');
  if (pendingCard) showCard(pendingCard);
}

/* ---------- escalation card (glass answer surface) ---------- */
function toneAccent(tone){
  return tone === 'red' ? 'var(--red)' : tone === 'amber' ? 'var(--gold)'
       : tone === 'green' ? 'var(--green)' : 'var(--steam)';
}
function buildCardHTML(rec){
  const p = rec.pin;
  const M = rec.consulted, N = rec.flagged;
  const srcRows = rec.sources.map(s => {
    const cls = s[0] === 'ok' ? ' ok' : s[0] === 'ctx' ? ' ctx' : '';
    return '<div class="ec-src' + cls + '"><span class="d"></span>' +
           '<span class="t"><b>' + s[1] + '</b> — ' + s[2] + '</span></div>';
  }).join('');
  return '' +
    '<div class="ec-head">' +
      '<span class="ec-type">' + p.type + '</span>' +
      '<span class="ec-ind">' + p.ind + '</span>' +
      '<button type="button" class="ec-close" data-esc-close aria-label="Dismiss">ESC</button>' +
    '</div>' +
    '<div class="ec-body">' +
      '<div class="ec-tally">' +
        '<div class="ec-ratio">' + N + '<span> / ' + M + '</span></div>' +
        '<div class="ec-score">PRIORITY<b>' + p.sev + '</b></div>' +
      '</div>' +
      '<div class="ec-headline"><b>' + N + ' of ' + M + '</b> ' + rec.headline + '</div>' +
      '<div class="ec-note"><b>' + rec.what + '.</b> ' + rec.note + '</div>' +
      '<div class="ec-meter"><i></i></div>' +
      '<div class="ec-sources">' + srcRows + '</div>' +
      '<div class="ec-rows">' +
        '<div class="ec-row"><span class="k">Attribution</span><span class="v">' + rec.attribution + '</span></div>' +
        '<div class="ec-row"><span class="k">Geo / ASN</span><span class="v mono">' + p.geo + '</span></div>' +
        '<div class="ec-row"><span class="k">Last seen</span><span class="v mono">' + p.seen + '</span></div>' +
      '</div>' +
    '</div>' +
    '<div class="ec-foot">Reflects third-party reputation at the time shown — attributed, not independently verified. Generated ' + rec.gen + '.</div>';
}
function positionCard(){
  if (!card || !hero || !search) return;
  const heroRect = hero.getBoundingClientRect();
  const sRect = search.getBoundingClientRect();
  const cy = (sRect.bottom - heroRect.top) + 18;
  card.style.setProperty('--cx', '0px');
  card.style.setProperty('--cy', cy.toFixed(1) + 'px');
}
function showCard(rec){
  if (!card) return;
  card.innerHTML = buildCardHTML(rec);
  const accent = toneAccent(rec.tone);
  card.style.setProperty('--card-accent', accent);
  const fill = Math.round(rec.flagged / Math.max(1,rec.consulted) * 100);
  positionCard();
  cardShown = true;
  requestAnimationFrame(() => {
    const meter = card.querySelector('.ec-meter i');
    if (meter) meter.style.setProperty('width', fill + '%');
    card.classList.add('show');
    card.setAttribute('aria-hidden', 'false');
  });
  if (linkEl) linkEl.style.setProperty('--link-accent', accent);
}
function hideCard(){
  if (!card) return;
  card.classList.remove('show');
  card.setAttribute('aria-hidden', 'true');
  cardShown = false;
}
// close button (delegated; no inline handler)
if (card){
  card.addEventListener('click', (e) => {
    if (e.target.closest('[data-esc-close]')){ input && (input.value = ''); syncDetect(); flyBack(); }
  });
}

/* ---------- whisper-subtle link: located pin -> card ---------- */
function updateLink(){
  if (!linkEl || !linkLine || !cardShown || !landed || !canvas) return;
  if (landed.fz <= 0.02){ linkEl.classList.remove('show'); return; }
  const rect = canvas.getBoundingClientRect();
  const px = rect.left + landed.sx * (rect.width  / canvas.clientWidth);
  const py = rect.top  + landed.sy * (rect.height / canvas.clientHeight);
  const cRect = card.getBoundingClientRect();
  // nearest card corner/edge on the card's right side, toward the pin
  const cx = cRect.right;
  const cy = Math.max(cRect.top + 16, Math.min(cRect.bottom - 16, py));
  linkLine.setAttribute('x1', cx.toFixed(1));
  linkLine.setAttribute('y1', cy.toFixed(1));
  linkLine.setAttribute('x2', px.toFixed(1));
  linkLine.setAttribute('y2', py.toFixed(1));
  linkEl.classList.add('show');
}

/* ============================================================
   GLOBE LIFECYCLE — build with a STABLE high-res backing store.
   ============================================================ */
let globe = null, dragging = false, lastX = 0, rafSpin = true, pressMoved = false;
let cobeDpr = 1, spinFactor = 1, lastT = 0;

function build(){
  if (!canvas || !canvas.clientWidth) return;   // hidden (mobile) or unlaid-out
  const reduce = rmq.matches;
  const dpr = Math.min(window.devicePixelRatio || 1, 2);   // cap DPR at 2
  cobeDpr = dpr * SS;                             // STABLE oversample -> crisp at every zoom
  const size = canvas.clientWidth;
  const p = palette(resolveDark());
  rafSpin = !reduce;
  lastT = 0;

  globe = createGlobe(canvas, {
    devicePixelRatio: cobeDpr,
    width:  size * cobeDpr,
    height: size * cobeDpr,
    phi, theta,
    dark: p.dark, diffuse: p.diffuse,
    mapSamples: 16000,
    mapBrightness: p.mapBrightness,
    mapBaseBrightness: p.mapBaseBrightness,
    baseColor:   p.base,
    markerColor: p.marker,
    glowColor:   p.glow,
    opacity: p.opacity,
    markers: [],                                   // pins are the DOM overlay
    onRender(state){
      const now = performance.now();
      let dt = lastT ? (now - lastT) / 1000 : 0.0167;
      lastT = now;
      if (dt > 0.05) dt = 0.05;                    // clamp (headless throttle / tab blur)

      if (flying){
        stepSpring(flyPhi, dt, OMEGA);   phi = flyPhi.x; targetPhi = phi;
        stepSpring(flyTheta, dt, OMEGA); theta = flyTheta.x;
        stepSpring(flyGz, dt, OMEGA);    gz = flyGz.x; applyGrow();
        // fire the beat as the point swings to the front (cohesive, not late)
        if (!flyBackMode && !landedShown){
          projectLanded();
          if (landed && landed.fz > 0.82) beat();
        }
        if (settled(flyPhi) && settled(flyTheta) && settled(flyGz, 0.004, 0.05)){
          flying = false;
          if (flyBackMode){ flyBackMode = false; spinSuspended = false; landed = null; }
          else { gzTarget = gz; if (!landedShown) beat(); }
        }
      } else {
        // ambient — graded 3-state spin
        let ts = 1;
        if (dragging || spinSuspended) ts = 0;
        else if (activeId >= 0) ts = 0;            // on a pin -> full halt
        else if (hovering) ts = 0.30;              // over the canvas -> ~30%
        spinFactor += (ts - spinFactor) * (1 - Math.exp(-dt*7));
        if (rafSpin && !dragging) targetPhi += 0.0035 * (dt*60) * spinFactor;
        phi += (targetPhi - phi) * (1 - Math.exp(-dt*6.5));
        if (!landed) theta += (THETA - theta) * (1 - Math.exp(-dt*6.5));
        stepZoom(dt);
      }

      state.phi = phi;
      state.theta = theta;
      const w = canvas.clientWidth * cobeDpr;      // keep resolution uniform in sync
      state.width = w; state.height = w;
      projectPins();
      projectLanded();
      updateActive();
      updateLink();
    }
  });

  requestAnimationFrame(() => {
    canvas.classList.add('globe-ready');
    hero.classList.add('loaded');
  });
}

function destroy(){
  if (globe){ globe.destroy(); globe = null; }
}

// theme re-init: colours are baked at createGlobe, so destroy->rebuild while
// CARRYING phi/theta/gz (no snap). Debounced against Light/Dark/System thrash.
let reTimer = null;
function rebuild(){
  clearTimeout(reTimer);
  reTimer = setTimeout(() => {
    if (!globe) return;
    destroy();
    build();
  }, 120);
}

/* ---------- drag to rotate (cobe-native lerp); drag overrides / interrupts fly ---------- */
function onDown(e){
  if (rmq.matches) return;
  dragging = true; lastX = e.clientX; pressMoved = false;
  if (flying && !flyBackMode){ flying = false; }   // hand control to the drag
  if (stage) stage.classList.add('dragging');
  if (canvas.setPointerCapture && e.pointerId != null){
    try { canvas.setPointerCapture(e.pointerId); } catch(_){}
  }
}
function onMove(e){
  if (!dragging) return;
  const dx = e.clientX - lastX;
  if (Math.abs(dx) > 3) pressMoved = true;
  targetPhi += dx * 0.005;                        // mutate target; phi lerps toward it in onRender
  lastX = e.clientX;
}
function onUp(){
  dragging = false;
  if (stage) stage.classList.remove('dragging');
}
if (canvas && !rmq.matches){
  canvas.addEventListener('pointerdown', onDown);
  window.addEventListener('pointermove', onMove, { passive:true });
  window.addEventListener('pointerup',   onUp);
  window.addEventListener('pointercancel', onUp);
}
// hover state for the graded spin + tooltip (works in reduced-motion too — informational)
if (stage){
  stage.addEventListener('pointerenter', () => { hovering = true; if (hint) hint.classList.add('show'); });
  stage.addEventListener('pointerleave', () => { hovering = false; cursor = null; if (hint) hint.classList.remove('show'); });
  stage.addEventListener('pointermove', (e) => {
    if (!canvas.clientWidth) return;
    const rect = canvas.getBoundingClientRect();
    cursor = {
      x: (e.clientX - rect.left) / rect.width  * canvas.clientWidth,
      y: (e.clientY - rect.top)  / rect.height * canvas.clientHeight
    };
  });
}

/* ---------- lifecycle: build when hero visible, free when gone ---------- */
createPins();
if (canvas){
  const gio = new IntersectionObserver((entries) => {
    for (const en of entries){
      if (en.isIntersecting){
        if (!globe) build();
      } else if (globe){
        destroy();                                 // free GL context, keep phi/theta/gz
      }
    }
  }, { threshold: 0 });
  gio.observe(hero);
}

/* ---------- theme toggle (Light / Dark / System) ---------- */
function setTheme(mode){
  if (mode === 'system') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', mode);
  toggle.querySelectorAll('button').forEach(b =>
    b.classList.toggle('on', b.dataset.themeSet === mode));
  rebuild();
}
if (toggle){
  toggle.addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (b && b.dataset.themeSet) setTheme(b.dataset.themeSet);
  });
  const cur = root.getAttribute('data-theme') || 'system';
  toggle.querySelectorAll('button').forEach(b =>
    b.classList.toggle('on', b.dataset.themeSet === cur));
}
dpq.addEventListener('change', () => {
  if (!root.getAttribute('data-theme')) rebuild();
});

/* ---------- count-up: ~20-line vanilla rAF tween (replaces GSAP) ---------- */
function countUp(el){
  const target = parseFloat(el.dataset.count);
  const suffix = el.dataset.suffix || '';
  const fmt = (v) => v.toLocaleString('en-US') + suffix;
  if (rmq.matches){ el.textContent = fmt(target); return; }
  const dur = 1100, start = performance.now();
  (function frame(now){
    const t = Math.min((now - start) / dur, 1);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = fmt(Math.round(target * eased));
    if (t < 1) requestAnimationFrame(frame);
  })(performance.now());
}
document.querySelectorAll('.hero-stats .n[data-count]').forEach(countUp);

/* ---------- omnibox: live indicator-type detector + submit-to-fly ---------- */
const RX = [
  [/^CVE-\d{4}-\d{4,}$/i,                 'CVE'],
  [/^(\d{1,3}\.){3}\d{1,3}$/,             'IPv4'],
  [/^[a-f0-9]{64}$/i,                     'SHA-256'],
  [/^[a-f0-9]{40}$/i,                     'SHA-1'],
  [/^[a-f0-9]{32}$/i,                     'MD5'],
  [/^[^@\s]+@[^@\s]+\.[^@\s]+$/,          'EMAIL'],
  [/^https?:\/\/\S+$/i,                   'URL'],
  [/^([a-z0-9-]+\.)+[a-z]{2,}$/i,         'DOMAIN']
];
function detectType(v){
  for (const [rx, name] of RX){ if (rx.test(v)) return name; }
  return '';
}
function syncDetect(){
  if (!input || !detect) return;
  const label = detectType(input.value.trim());
  if (label){ detect.textContent = label; detect.classList.add('show'); }
  else detect.classList.remove('show');
}
function submit(){
  const v = input ? input.value.trim() : '';
  const rec = GEO[v];
  if (rec) flyTo(rec);                              // geolocatable IOC -> fly + card
  // (non-geo indicators: no fly in this mockup)
}
if (input){
  input.addEventListener('input', () => {
    syncDetect();
    if (cardShown && input.value.trim() === '') flyBack();   // clearing reverses
  });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter'){ e.preventDefault(); submit(); }
    else if (e.key === 'Escape'){
      if (cardShown){ e.preventDefault(); input.value = ''; syncDetect(); flyBack(); }
    }
  });
}
// recent chips — fill the box; geolocatable IPs also fly
if (histRow){
  histRow.addEventListener('click', (e) => {
    const chip = e.target.closest('.chip');
    if (!chip || !input) return;
    input.value = chip.textContent.trim();
    syncDetect();
    submit();
    input.focus();
  });
}
// global Esc + '/' focus
window.addEventListener('keydown', (e) => {
  if (e.key === '/' && document.activeElement !== input){
    e.preventDefault(); input && input.focus();
  } else if (e.key === 'Escape' && cardShown){
    input && (input.value = ''); syncDetect(); flyBack();
  }
});

/* ---------- reveals + melt fallback (no native scroll-driven support) ---------- */
const hasViewTL   = CSS.supports && CSS.supports('animation-timeline: view()');
const hasScrollTL = CSS.supports && CSS.supports('animation-timeline: scroll()');

if (!hasViewTL || rmq.matches){
  const rio = new IntersectionObserver((ents) => {
    ents.forEach(en => {
      if (en.isIntersecting){ en.target.classList.add('in'); rio.unobserve(en.target); }
    });
  }, { threshold: 0, rootMargin: '0px 0px -12% 0px' });
  document.querySelectorAll('.reveal').forEach(el => rio.observe(el));
}

// hide the tooltip while the page scrolls (globe recedes under the melt)
window.addEventListener('scroll', () => { if (activeId >= 0){ hovering = false; cursor = null; } }, { passive:true });

if (hasScrollTL === false && !rmq.matches){
  let ticking = false;
  const apply = () => {
    ticking = false;
    const win = window.innerHeight * 0.84;
    const p = Math.min(Math.max(window.scrollY / win, 0), 1);
    hero.style.setProperty('--melt', p.toFixed(4));
  };
  window.addEventListener('scroll', () => {
    if (!ticking){ ticking = true; requestAnimationFrame(apply); }
  }, { passive: true });
  apply();
}
