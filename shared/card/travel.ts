// travel.ts — the "impossible travel" helper: great-circle distance between two
// IP geolocations (MILES) and, given the time between sign-ins, the implied
// ground speed (MPH) with an honest plausibility read. Pure + deterministic.
//
// HARD honesty note — this is the feature's whole safety. IP geolocation is
// city-level and routinely distorted by VPNs, proxies, mobile carriers, and
// CGNAT, so a large separation is a TRIAGE LEAD, never proof of compromise.
// Every string this module emits says so, and the caller only ever computes a
// distance from a REAL coordinate (geoModel.precise), never a country centroid.

const EARTH_RADIUS_MI = 3958.8
const toRad = (deg: number) => (deg * Math.PI) / 180
const commas = (n: number) => Math.round(n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',')

/** Great-circle (haversine) distance between two lat/long points, in statute miles. */
export function haversineMiles(aLat: number, aLon: number, bLat: number, bLon: number): number {
  const dLat = toRad(bLat - aLat)
  const dLon = toRad(bLon - aLon)
  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(aLat)) * Math.cos(toRad(bLat)) * Math.sin(dLon / 2) ** 2
  return 2 * EARTH_RADIUS_MI * Math.asin(Math.min(1, Math.sqrt(h)))
}

export type TravelBand = 'plausible' | 'implausible' | 'impossible'

export interface TravelAssessment {
  miles: number
  milesLabel: string // "2,412 mi"
  /** Implied ground speed — only when a positive time gap was supplied. */
  mph: number | null
  mphLabel: string | null // "9,648 mph"
  /** null = distance-only (no time gap given). */
  band: TravelBand | null
  /** Plain-English one-liner for the panel + the client summary. */
  read: string
}

// Commercial jets cruise ~575 mph; 600 gives realistic door-to-door headroom.
// Above the fastest crewed aircraft (~2,200 mph) it is physically impossible.
const COMMERCIAL_MPH = 600
const AIRCRAFT_CEILING_MPH = 2200

/** Miles + (when a positive `minutes` is given) the implied mph and an honest
 *  plausibility band. Never asserts compromise — the reads are investigative. */
export function travelAssessment(miles: number, minutes: number | null): TravelAssessment {
  const milesLabel = `${commas(miles)} mi`
  if (minutes == null || !(minutes > 0)) {
    return {
      miles,
      milesLabel,
      mph: null,
      mphLabel: null,
      band: null,
      read: 'Add the time between the two sign-ins to gauge travel feasibility.',
    }
  }
  const mph = miles / (minutes / 60)
  const mphLabel = `${commas(mph)} mph`
  if (mph <= COMMERCIAL_MPH) {
    return {
      miles,
      milesLabel,
      mph,
      mphLabel,
      band: 'plausible',
      read: `≈${mphLabel} implied — within commercial-flight speed, so the two sign-ins are geographically consistent with travel.`,
    }
  }
  if (mph <= AIRCRAFT_CEILING_MPH) {
    return {
      miles,
      milesLabel,
      mph,
      mphLabel,
      band: 'implausible',
      read: `≈${mphLabel} implied — faster than a commercial flight (~575 mph) and implausible for one traveler. Investigate VPN/proxy use or account compromise.`,
    }
  }
  return {
    miles,
    milesLabel,
    mph,
    mphLabel,
    band: 'impossible',
    read: `≈${mphLabel} implied — beyond any aircraft; not physically possible for one person. Almost certainly VPN/proxy use or account compromise.`,
  }
}

/** The copyable one-liner for a client email: distance, the velocity read, and
 *  the mandatory approximate-geo caveat. `fromLabel`/`toLabel` are "City, CC". */
export function travelSummary(fromLabel: string, toLabel: string, t: TravelAssessment): string {
  const base = `Two sign-ins for this account originated ~${t.milesLabel} apart (${fromLabel} → ${toLabel}).`
  const vel =
    t.mph == null
      ? ''
      : t.band === 'plausible'
        ? ` Over the stated window that implies ≈${t.mphLabel}, within commercial-flight speed — geographically consistent with travel.`
        : t.band === 'implausible'
          ? ` Over the stated window that implies ≈${t.mphLabel}, faster than a commercial flight — implausible for a single traveler.`
          : ` Over the stated window that implies ≈${t.mphLabel}, beyond any aircraft — not physically possible for a single traveler.`
  const caveat =
    ' Note: IP geolocation is approximate (city-level) and is commonly distorted by VPNs, proxies, and mobile carriers — treat this as an investigative lead, not proof.'
  return base + vel + caveat
}
