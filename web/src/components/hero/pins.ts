/**
 * Globe pin model + projection — the CSP-safe, framework-agnostic core.
 *
 * PORTED from site/js/globe.js (the vanilla showpiece). Everything here is
 * pure data + math so `useGlobe` can stay a thin lifecycle shell:
 *   • PINS       — analyst-grade mock indicators (real metro coords).
 *   • GEO        — indicator → fly-to target table (drives the demo fly-to
 *                  when the live enrich geo is dormant).
 *   • unitVec    — lat/lng → model-space unit vector (cobe's marker fn).
 *   • project    — model-space r → screen px, matching cobe@2's transform for
 *                  a SQUARE canvas at scale 1 / offset 0 (see useGlobe notes).
 *
 * Colour-by-verdict (Option B): tier tones the pin; severity sizes it. Pins
 * are a projected DOM overlay because cobe's markerColor is a single uniform —
 * per-severity colour + hit-testing must live in the DOM.
 */

export type Tier = 'crit' | 'susp' | 'low'
export type TrendDir = 'up' | 'down' | 'flat'

export interface Pin {
  id: string
  location: [number, number]
  sev: number
  tier: Tier
  type: string
  ind: string
  what: string
  actor: string
  consensus: string
  seen: string
  trend: { d: TrendDir; t: string }
  geo: string
  /** model-space unit vector, precomputed from `location`. */
  r: [number, number, number]
}

/** A minimal fly-to target (the landed pin needs only geometry + tone). */
export interface FlyTarget {
  r: [number, number, number]
  tier: Tier
  sev: number
}

const PI = Math.PI

/** lat/lng → unit model-space vector (matches cobe's marker projection:
 *  lat→i rad, lng→s=rad−PI; r = [−cos(i)cos(s), sin(i), cos(i)sin(s)]). */
export function unitVec(lat: number, lng: number): [number, number, number] {
  const i = (lat * PI) / 180
  const s = (lng * PI) / 180 - PI
  const cl = Math.cos(i)
  return [-cl * Math.cos(s), Math.sin(i), cl * Math.sin(s)]
}

export interface Projected {
  x: number
  y: number
  z: number
}

/**
 * model-space r → screen px, for cobe@2 with a SQUARE backing store, scale 1,
 * offset 0. cobe@2 projects a surface point as
 *   c = cos(phi)·x + sin(phi)·z            (→ ndc x, ÷ aspect = 1 here)
 *   s = sin(phi)sin(theta)·x + cos(theta)·y − cos(phi)sin(theta)·z  (→ ndc y)
 * on a sphere of radius ee = 0.8, so the disc edge lands at |ndc| = 0.8 — the
 * same 0.8 factor the vanilla overlay used. Depth `z` culls the back face.
 */
export function project(
  r: readonly [number, number, number],
  phi: number,
  theta: number,
  w: number,
  h: number,
  out: Projected,
): void {
  const cp = Math.cos(phi)
  const sp = Math.sin(phi)
  const ct = Math.cos(theta)
  const st = Math.sin(theta)
  const fx = cp * r[0] + sp * r[2]
  const fy = sp * st * r[0] + ct * r[1] - cp * st * r[2]
  const fz = -sp * ct * r[0] + st * r[1] + cp * ct * r[2]
  out.x = ((fx * 0.8 + 1) / 2) * w
  out.y = ((1 - fy * 0.8) / 2) * h
  out.z = fz
}

/** fly-to targets that bring pin.r to front-centre (from `project`). */
export function flyTargets(r: readonly [number, number, number]): {
  phi: number
  theta: number
} {
  const phi = Math.atan2(-r[0], r[2])
  const theta = Math.max(
    -1.05,
    Math.min(1.05, Math.asin(Math.max(-1, Math.min(1, r[1])))),
  )
  return { phi, theta }
}

/* ============================================================
   TI PINS — <=12 analyst-grade mock indicators. Real metro coords.
   Attribution is plain text (React renders it; no innerHTML).
   ============================================================ */
function makePins(): Pin[] {
  const raw: Array<Omit<Pin, 'r'>> = [
    {
      id: '185.220.101.34', location: [50.11, 8.68], sev: 94, tier: 'crit', type: 'IPv4',
      ind: '185.220.101.34', what: 'Cobalt Strike C2 beacon',
      actor: 'Infra linked to Akira affiliate', consensus: '6 of 6', seen: '3 min ago',
      trend: { d: 'up', t: '▲ sharp spike' }, geo: 'Frankfurt, DE · AS24940 Hetzner',
    },
    {
      id: 'login-verify-ms.com', location: [52.37, 4.9], sev: 88, tier: 'crit', type: 'DOMAIN',
      ind: 'login-verify-ms[.]com', what: 'Credential-harvesting phishing',
      actor: 'Attributed to Storm-1101 (Tycoon 2FA)', consensus: '5 of 6', seen: '18 min ago',
      trend: { d: 'up', t: '▲ rising' }, geo: 'Amsterdam, NL · AS60781 LeaseWeb',
    },
    {
      id: '45.146.164.110', location: [55.75, 37.61], sev: 91, tier: 'crit', type: 'IPv4',
      ind: '45.146.164.110', what: 'Ransomware staging & exfil node',
      actor: 'Linked to LockBit rebuild infra', consensus: '6 of 6', seen: '1 hr ago',
      trend: { d: 'flat', t: '▶ steady' }, geo: 'Moscow, RU · AS56694 SmartApe',
    },
    {
      id: '176.113.115.84', location: [50.45, 30.52], sev: 84, tier: 'crit', type: 'IPv4',
      ind: '176.113.115.84', what: 'SonicWall SSL-VPN exploit host',
      actor: 'Akira initial-access broker', consensus: '5 of 6', seen: '42 min ago',
      trend: { d: 'up', t: '▲ rising' }, geo: 'Kyiv, UA · AS44094 IT-Grad',
    },
    {
      id: '20.99.132.44', location: [37.77, -122.42], sev: 67, tier: 'susp', type: 'IPv4',
      ind: '20.99.132.44', what: 'APT29 spearphish sender infra',
      actor: 'Attributed to APT29 (Midnight Blizzard)', consensus: '4 of 6', seen: '3 hr ago',
      trend: { d: 'up', t: '▲ campaign active' }, geo: 'San Francisco, US · AS8075 Microsoft',
    },
    {
      id: '139.180.203.12', location: [1.35, 103.82], sev: 71, tier: 'susp', type: 'IPv4',
      ind: '139.180.203.12', what: 'Tor exit relay', actor: 'No attributed actor',
      consensus: '3 of 6', seen: '26 min ago', trend: { d: 'flat', t: '▶ steady' },
      geo: 'Singapore, SG · AS20473 Vultr',
    },
    {
      id: '7f9c34e2-a3e1', location: [40.71, -74.0], sev: 62, tier: 'susp', type: 'SHA-256',
      ind: '7f9c34e2…a3e1', what: 'RedLine infostealer sample',
      actor: 'Commodity crimeware, no crew', consensus: '4 of 6', seen: '2 hr ago',
      trend: { d: 'up', t: '▲ new variant' }, geo: 'New York, US · AS14061 DigitalOcean',
    },
    {
      id: 'cdn-analytics-cloud.net', location: [51.51, -0.13], sev: 55, tier: 'susp', type: 'DOMAIN',
      ind: 'cdn-analytics-cloud[.]net', what: 'Malware distribution CDN',
      actor: 'Linked to SocGholish cluster', consensus: '4 of 6', seen: '4 hr ago',
      trend: { d: 'down', t: '▼ cooling' }, geo: 'London, GB · AS16509 Amazon',
    },
    {
      id: '191.96.150.10', location: [-23.55, -46.63], sev: 43, tier: 'low', type: 'IPv4',
      ind: '191.96.150.10', what: 'Brute-force / scanning source',
      actor: 'Mirai-class botnet node', consensus: '2 of 6', seen: '6 hr ago',
      trend: { d: 'flat', t: '▶ steady' }, geo: 'São Paulo, BR · AS262287 Latitude',
    },
    {
      id: 'update-pkg-mirror.org', location: [35.68, 139.69], sev: 38, tier: 'low', type: 'DOMAIN',
      ind: 'update-pkg-mirror[.]org', what: 'Newly-registered suspicious domain',
      actor: 'Unclassified', consensus: '2 of 6', seen: '9 hr ago',
      trend: { d: 'up', t: '▲ slight uptick' }, geo: 'Tokyo, JP · AS7506 GMO',
    },
    {
      id: '3ab5f1c0-9f02', location: [19.08, 72.88], sev: 29, tier: 'low', type: 'MD5',
      ind: '3ab5f1c0…9f02', what: 'Adware / PUP bundle',
      actor: 'Commodity, no attribution', consensus: '1 of 6', seen: '13 hr ago',
      trend: { d: 'down', t: '▼ declining' }, geo: 'Mumbai, IN · AS4755 TATA',
    },
  ]
  return raw.map((p) => ({ ...p, r: unitVec(p.location[0], p.location[1]) }))
}

export const PINS: Pin[] = makePins()

/** ambient pin diameter (px) from severity — 9..22. */
export function ambientDiameter(sev: number): number {
  return 9 + (sev / 100) * 13
}
/** landed fly-to pin diameter (px) — a touch larger, 14..26. */
export function landedDiameter(sev: number): number {
  return 14 + (sev / 100) * 12
}

/* ============================================================
   GEO demo table — indicator → fly-to target. Drives the fly-to when the
   live enrich geo is absent (dormant backend on the static tier).
   ============================================================ */
export const GEO: Record<string, FlyTarget> = {
  '185.220.101.34': { r: PINS[0].r, tier: 'crit', sev: PINS[0].sev },
  '45.146.164.110': { r: PINS[2].r, tier: 'crit', sev: PINS[2].sev },
  '176.113.115.84': { r: PINS[3].r, tier: 'crit', sev: PINS[3].sev },
  '20.99.132.44': { r: PINS[4].r, tier: 'susp', sev: PINS[4].sev },
  // benign example — still geolocatable, flies + drops a muted low-tier pin
  '8.8.8.8': { r: unitVec(37.42, -122.08), tier: 'low', sev: 2 },
}

/** CSS custom-property expression for a tier's ink (verdict tones + neutral).
 *  --steam isn't a web token, so `low` maps to the warm neutral --muted. */
export function tierInk(tier: Tier): string {
  return tier === 'crit'
    ? 'var(--red)'
    : tier === 'susp'
      ? 'var(--gold)'
      : 'var(--muted)'
}

/* ============================================================
   GREAT-CIRCLE ARC MATH — the attack-arc geometry (MOVE 1). Pure vectors so
   useGlobe can slerp source→target on the unit sphere, lift the mid-arc off the
   surface (Bézier-ish altitude via sin(πt)), and project each sample with the
   same project()/unitVec math the pins use — so arcs inherit the exact rotation,
   fly-to and --globe-grow zoom the globe has.
   ============================================================ */
export type Vec3 = [number, number, number]

/** angle (radians) of the great circle between two unit vectors. */
export function arcAngle(a: Vec3, b: Vec3): number {
  const d = a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
  return Math.acos(Math.max(-1, Math.min(1, d)))
}

/** spherical-linear interpolation along the great circle a→b at t∈[0,1].
 *  `omega`/`sinOmega` are precomputed once per arc (from arcAngle). Returns a
 *  unit-ish vector; scale it by an altitude factor to lift it off the sphere. */
export function slerp(
  a: Vec3,
  b: Vec3,
  t: number,
  omega: number,
  sinOmega: number,
  out: Vec3,
): void {
  if (sinOmega < 1e-4) {
    out[0] = a[0]
    out[1] = a[1]
    out[2] = a[2]
    return
  }
  const s0 = Math.sin((1 - t) * omega) / sinOmega
  const s1 = Math.sin(t * omega) / sinOmega
  out[0] = a[0] * s0 + b[0] * s1
  out[1] = a[1] * s0 + b[1] * s1
  out[2] = a[2] * s0 + b[2] * s1
}

/** ambient-arc endpoints — the crit/susp pins' unit vectors (real metro coords).
 *  Ambient arcs route only between these earned nodes, never `low` decoration. */
export const ARC_NODES: readonly Vec3[] = PINS.filter((p) => p.tier !== 'low').map(
  (p) => p.r,
)

/** neutral origin for the scored incoming beam when there's no prior landing —
 *  a mid-Atlantic "home sensor" (kept off any real actor node). */
export const HOME_VEC: Vec3 = unitVec(30, -40)
