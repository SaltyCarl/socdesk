// Pure helpers for the PICKET surfaces — no React, no fetch. The copy rules
// live here so the tab, the teaser and the tests agree: a silent sensor is
// "no export", never "no attacks".
import type { PicketSensor, PicketStatus, VolumePoint } from './types'

// Freshness thresholds — mirror pipeline/picket.py LIVE_MINUTES / SILENT_MINUTES.
export const LIVE_MINUTES = 90
export const SILENT_MINUTES = 1440

export function statusLabel(s: PicketStatus): string {
  return s === 'live' ? 'Live' : s === 'stale' ? 'Stale' : 'Silent'
}

export function formatAge(minutes: number): string {
  if (minutes < 60) return `${minutes} min`
  if (minutes < 1440) return `${Math.round(minutes / 60)} h`
  return `${Math.round(minutes / 1440)} d`
}

/**
 * Minutes since the export, from the CLIENT clock when `exported_at` parses.
 * The pipeline-stamped `export_age_minutes` cannot age if the pipeline itself
 * stops — picket.json would freeze at "live · 25 min ago" — so the stamped
 * figure is only the fallback for an unparseable timestamp. Never negative.
 */
export function exportAgeMinutes(sensor: PicketSensor, now = Date.now()): number {
  const t = Date.parse(sensor.exported_at)
  if (!Number.isFinite(t)) return sensor.export_age_minutes
  return Math.max(0, Math.floor((now - t) / 60_000))
}

/** live / stale / silent from the client-side age (same thresholds as the
 *  pipeline); the pipeline's own status is trusted only when the timestamp
 *  cannot be parsed. */
export function sensorStatus(sensor: PicketSensor, now = Date.now()): PicketStatus {
  if (!Number.isFinite(Date.parse(sensor.exported_at))) return sensor.status
  const age = exportAgeMinutes(sensor, now)
  return age < LIVE_MINUTES ? 'live' : age < SILENT_MINUTES ? 'stale' : 'silent'
}

export function statusCopy(sensor: PicketSensor, now = Date.now()): string {
  const status = sensorStatus(sensor, now)
  const age = formatAge(exportAgeMinutes(sensor, now))
  if (status === 'live') return `Sensor reporting · last export ${age} ago`
  if (status === 'stale') return `Sensor stale · no export for ${age} — figures below are the last received`
  return `Sensor silent · no export for ${age} — the sensor or its uplink is down; figures below are the last received`
}

export function histogramPoints(hist: number[], generatedAt?: string): VolumePoint[] {
  if (!Array.isArray(hist) || hist.length === 0) return []
  const end = generatedAt ? new Date(generatedAt) : new Date()
  const days = Math.max(1, Math.floor(hist.length / 24))
  const out: VolumePoint[] = []
  for (let d = 0; d < days; d++) {
    const slice = hist.slice(hist.length - (days - d) * 24, hist.length - (days - d - 1) * 24)
    const day = new Date(end.getTime() - (days - 1 - d) * 86_400_000)
    out.push({ date: day.toISOString().slice(0, 10), count: slice.reduce((a, b) => a + b, 0) })
  }
  return out
}
