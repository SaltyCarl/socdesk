// geo.ts — the geolocation model + the embedded dot-matrix world landmask.
//
// Shared, unchanged, by the on-screen IP hero (SVG, heroes.tsx) and the copy-
// card canvas (drawVerdict.ts) so both place the pin identically. Everything is
// STATIC and embedded: no tile server, no external request — the indicator and
// its coordinates never leave the browser (design spec §3.3 + evidence.js note).
//
// Honesty: geolocation is CONTEXT, never a verdict; and we never print a precise-
// looking coordinate we do not actually hold — with only a country code we place
// the pin at the country centroid and label the readout "country-level".

import type { FactRow } from '../verdict'

export interface FlagDef {
  /** 'h' = bands stacked top→bottom, 'v' = bands left→right. */
  dir: 'h' | 'v'
  bands: string[]
}

export interface GeoModel {
  countryCode: string
  countryName: string
  city: string
  asn: string
  org: string
  lat: number
  lon: number
  /** True only when a real lat/long was on the wire (else country centroid). */
  precise: boolean
  flag: FlagDef | null
}

/** A locatable row (context or scored) — just the parts geo cares about. */
export interface GeoRow {
  name?: string
  kind?: string
  facts?: FactRow[]
}

/* code -> [name, lat, lon]. Rough centroids; the map is a coarse dot-matrix so
 * country-level placement is more than enough. */
const GEO: Record<string, [string, number, number]> = {
  US: ['United States', 39.8, -98.6], CA: ['Canada', 56.1, -106.3], MX: ['Mexico', 23.6, -102.5],
  BR: ['Brazil', -10.3, -53.2], AR: ['Argentina', -38.4, -63.6], CL: ['Chile', -35.7, -71.5],
  CO: ['Colombia', 4.6, -74.3], PE: ['Peru', -9.2, -75.0], VE: ['Venezuela', 6.4, -66.6],
  GB: ['United Kingdom', 54.0, -2.9], IE: ['Ireland', 53.4, -8.2], FR: ['France', 46.6, 2.5],
  DE: ['Germany', 51.2, 10.5], NL: ['Netherlands', 52.1, 5.3], BE: ['Belgium', 50.6, 4.6],
  LU: ['Luxembourg', 49.8, 6.1], CH: ['Switzerland', 46.8, 8.2], AT: ['Austria', 47.6, 14.1],
  IT: ['Italy', 42.8, 12.6], ES: ['Spain', 40.2, -3.7], PT: ['Portugal', 39.6, -8.0],
  SE: ['Sweden', 62.2, 15.3], NO: ['Norway', 64.6, 12.0], FI: ['Finland', 64.5, 26.3],
  DK: ['Denmark', 56.0, 9.5], IS: ['Iceland', 64.9, -18.6], PL: ['Poland', 51.9, 19.1],
  CZ: ['Czechia', 49.8, 15.5], SK: ['Slovakia', 48.7, 19.7], HU: ['Hungary', 47.2, 19.5],
  RO: ['Romania', 45.9, 25.0], BG: ['Bulgaria', 42.7, 25.5], GR: ['Greece', 39.1, 22.9],
  HR: ['Croatia', 45.1, 15.2], RS: ['Serbia', 44.0, 21.0], SI: ['Slovenia', 46.1, 14.8],
  UA: ['Ukraine', 48.4, 31.2], BY: ['Belarus', 53.7, 27.9], MD: ['Moldova', 47.4, 28.4],
  LT: ['Lithuania', 55.2, 23.9], LV: ['Latvia', 56.9, 24.6], EE: ['Estonia', 58.6, 25.0],
  RU: ['Russia', 61.5, 105.3], TR: ['Türkiye', 39.0, 35.2], CY: ['Cyprus', 35.1, 33.4],
  IL: ['Israel', 31.4, 34.9], AE: ['United Arab Emirates', 24.0, 54.0], SA: ['Saudi Arabia', 24.0, 45.1],
  IR: ['Iran', 32.4, 53.7], IQ: ['Iraq', 33.2, 43.7], EG: ['Egypt', 26.8, 30.8],
  ZA: ['South Africa', -30.6, 22.9], NG: ['Nigeria', 9.1, 8.7], KE: ['Kenya', 0.0, 37.9],
  MA: ['Morocco', 31.8, -7.1], DZ: ['Algeria', 28.0, 1.7], IN: ['India', 22.4, 78.7],
  PK: ['Pakistan', 30.4, 69.3], BD: ['Bangladesh', 23.7, 90.4], CN: ['China', 35.9, 104.2],
  HK: ['Hong Kong', 22.3, 114.2], TW: ['Taiwan', 23.7, 121.0], JP: ['Japan', 36.2, 138.3],
  KR: ['South Korea', 36.4, 127.9], KP: ['North Korea', 40.3, 127.5], VN: ['Vietnam', 16.0, 108.0],
  TH: ['Thailand', 15.1, 101.0], MY: ['Malaysia', 4.2, 101.9], SG: ['Singapore', 1.35, 103.8],
  ID: ['Indonesia', -2.5, 118.0], PH: ['Philippines', 12.9, 121.8], AU: ['Australia', -25.7, 134.5],
  NZ: ['New Zealand', -41.8, 172.9],
}

/* Easily-drawn band flags. Non-band flags (crosses/unions/stars) fall back to a
 * neutral chip carrying the ISO code — honest and always renders. */
const FLAGS: Record<string, FlagDef> = {
  DE: { dir: 'h', bands: ['#111111', '#DD0000', '#FFCE00'] },
  FR: { dir: 'v', bands: ['#0055A4', '#FFFFFF', '#EF4135'] },
  NL: { dir: 'h', bands: ['#AE1C28', '#FFFFFF', '#21468B'] },
  IT: { dir: 'v', bands: ['#008C45', '#F4F5F0', '#CD212A'] },
  IE: { dir: 'v', bands: ['#169B62', '#FFFFFF', '#FF883E'] },
  BE: { dir: 'v', bands: ['#111111', '#FDDA24', '#EF3340'] },
  RO: { dir: 'v', bands: ['#002B7F', '#FCD116', '#CE1126'] },
  RU: { dir: 'h', bands: ['#FFFFFF', '#0039A6', '#D52B1E'] },
  ES: { dir: 'h', bands: ['#AA151B', '#F1BF00', '#AA151B'] },
  AT: { dir: 'h', bands: ['#ED2939', '#FFFFFF', '#ED2939'] },
  BG: { dir: 'h', bands: ['#FFFFFF', '#00966E', '#D62612'] },
  LT: { dir: 'h', bands: ['#FDB913', '#006A44', '#C1272D'] },
  PL: { dir: 'h', bands: ['#FFFFFF', '#DC143C'] },
  UA: { dir: 'h', bands: ['#0057B7', '#FFD700'] },
  ID: { dir: 'h', bands: ['#FF0000', '#FFFFFF'] },
}

/** The coarse equirectangular landmask ('#' = land). Fixed bytes every time. */
export const WORLD: string[] = [
  '............................#######.............................................',
  '............................#######.....................#############...........',
  '....#####..........####......#######...............#########################....',
  '...#####################.....######........#####################################',
  '...#######################....####.......#######################################',
  '..........#################............#####################################....',
  '...........################...........#####################################.....',
  '...........################.............##################################......',
  '............##############.............########..########################.......',
  '............############...............##.####...########################.......',
  '.............###########..............#...........######################........',
  '..............#########..................##........###################..........',
  '.................######.................#######....################.............',
  '.................#####.................#########....###############.............',
  '......................................##########.......############.............',
  '..................##.................############.......###..####...............',
  '....................#...............#############.......##...###...#............',
  '.....................#####..........###############......#....#...##............',
  '......................#####...........#############.............................',
  '......................######.............##########..........#..................',
  '......................########............########............###...............',
  '......................##########..........#######..............##########.......',
  '......................##########..........#######...............................',
  '.......................########...........#######...................####........',
  '.......................########............#####..#................#####........',
  '.......................#######.............#####..#..............########.......',
  '........................#####..............####..................########.......',
  '........................####................##....................#######.......',
  '........................###.................##........................###.......',
  '........................###.....................................................',
  '.......................###...................................................##.',
  '.......................##....................................................###',
  '................................................................................',
  '................................................................................',
]

/** Pin position as fractions of the map width/height (equirectangular),
 *  clamped inside the frame. Shared by the SVG hero and the canvas. */
export function project(lat: number, lon: number): { fx: number; fy: number } {
  const fx = Math.min(0.999, Math.max(0.001, (lon + 180) / 360))
  const fy = Math.min(0.999, Math.max(0.001, (90 - lat) / 180))
  return { fx, fy }
}

/** Great-circle arc between two coordinates, sampled and projected to map
 *  fractions (the SAME equirectangular `project` the pins use). Returned as
 *  one-or-more polyline SEGMENTS, split at the antimeridian so a flat-map
 *  polyline never draws a spurious line straight across the frame. Pure geometry:
 *  the honest shortest-path line between two REAL looked-up coordinates. */
export function greatCircleArc(
  aLat: number,
  aLon: number,
  bLat: number,
  bLon: number,
  samples = 48,
): Array<Array<{ fx: number; fy: number }>> {
  const rad = (d: number) => (d * Math.PI) / 180
  const deg = (r: number) => (r * 180) / Math.PI
  const toVec = (lat: number, lon: number): [number, number, number] => {
    const p = rad(lat)
    const l = rad(lon)
    return [Math.cos(p) * Math.cos(l), Math.cos(p) * Math.sin(l), Math.sin(p)]
  }
  const A = toVec(aLat, aLon)
  const B = toVec(bLat, bLon)
  const dot = Math.max(-1, Math.min(1, A[0] * B[0] + A[1] * B[1] + A[2] * B[2]))
  const omega = Math.acos(dot)
  const sinO = Math.sin(omega)

  const segments: Array<Array<{ fx: number; fy: number }>> = []
  let cur: Array<{ fx: number; fy: number }> = []
  let prevFx: number | null = null

  for (let i = 0; i <= samples; i++) {
    const t = i / samples
    let v: [number, number, number]
    if (sinO < 1e-6) {
      v = A // coincident (or antipodal — no unique great circle); degenerate to A
    } else {
      const a = Math.sin((1 - t) * omega) / sinO
      const b = Math.sin(t * omega) / sinO
      v = [a * A[0] + b * B[0], a * A[1] + b * B[1], a * A[2] + b * B[2]]
    }
    const lat = deg(Math.asin(Math.max(-1, Math.min(1, v[2]))))
    const lon = deg(Math.atan2(v[1], v[0]))
    const { fx, fy } = project(lat, lon)
    if (prevFx !== null && Math.abs(fx - prevFx) > 0.5) {
      if (cur.length) segments.push(cur)
      cur = []
    }
    cur.push({ fx, fy })
    prevFx = fx
  }
  if (cur.length) segments.push(cur)
  return segments
}

function factMap(row: GeoRow): Map<string, string> {
  return new Map((row.facts ?? []).map(([k, v]) => [String(k).toLowerCase(), v]))
}

/**
 * Derive the geolocation block from the context (ipinfo) row, falling back to a
 * scored source's country code. Returns null for indicator types that have no
 * location (hashes, most domains) — the hero then omits the map entirely.
 */
export function geoModel(context: GeoRow[], sources: GeoRow[]): GeoModel | null {
  // Prefer a geolocation context row (ipinfo) over a co-present WHOIS/registrar
  // row, so a domain's resolved geo isn't shadowed by its registration facts.
  const hasLoc = (r: GeoRow) => {
    const f = factMap(r)
    return f.has('country') || f.has('location') || f.has('city')
  }
  const ctx =
    context.find((r) => /ipinfo|geo/i.test(r.name ?? '')) ?? context.find(hasLoc) ?? context[0]
  let code = ''
  let city = ''
  let asn = ''
  let org = ''
  let lat: number | null = null
  let lon: number | null = null

  if (ctx) {
    const f = factMap(ctx)
    code = String(f.get('country') ?? '').toUpperCase()
    city = String(f.get('city') ?? '')
    asn = String(f.get('asn') ?? '').replace(/^—$/, '')
    org = String(f.get('organisation') ?? f.get('organization') ?? '').replace(/^—$/, '')

    // "City, Region, CC" style location, if a discrete country wasn't given.
    if (!code || !city) {
      const parts = String(f.get('location') ?? '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
      if (parts.length) {
        const last = parts[parts.length - 1]
        if (!code && /^[A-Za-z]{2}$/.test(last)) code = last.toUpperCase()
        if (!city && parts.length > 1) city = parts[0]
      }
    }

    // A precise coordinate, ONLY if the wire actually carried one.
    for (const [, v] of ctx.facts ?? []) {
      const m = String(v).match(/^\s*(-?\d{1,2}(?:\.\d+)?)\s*,\s*(-?\d{1,3}(?:\.\d+)?)\s*$/)
      if (m) {
        lat = parseFloat(m[1])
        lon = parseFloat(m[2])
        break
      }
    }
  }

  if (!code) {
    for (const s of sources) {
      const cc = factMap(s).get('country')
      if (cc && /^[A-Za-z]{2}$/.test(cc)) {
        code = cc.toUpperCase()
        break
      }
    }
  }

  if (!code && lat == null) return null

  const ref = GEO[code]
  const precise = lat != null && lon != null
  if (!precise && ref) {
    lat = ref[1]
    lon = ref[2]
  }
  if (lat == null || lon == null) {
    lat = 20
    lon = 0
  }

  return {
    countryCode: code,
    countryName: ref ? ref[0] : code || 'Location',
    city,
    asn,
    org,
    lat,
    lon,
    precise,
    flag: FLAGS[code] ?? null,
  }
}

/** The right-hand coordinate readout — honest about precision. */
export function coordLabel(g: GeoModel): string {
  if (!g.precise) return 'country-level'
  const ns = `${Math.abs(g.lat).toFixed(2)}°${g.lat >= 0 ? 'N' : 'S'}`
  const ew = `${Math.abs(g.lon).toFixed(2)}°${g.lon >= 0 ? 'E' : 'W'}`
  return `${ns} ${ew}`
}
