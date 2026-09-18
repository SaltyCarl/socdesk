// Pure helpers for the PICKET surfaces — no React, no fetch. The copy rules
// live here so the tab, the teaser and the tests agree: a silent sensor is
// "no export", never "no attacks".
import type { PicketSensor, PicketStatus, VolumePoint } from './types'

export function statusLabel(s: PicketStatus): string {
  return s === 'live' ? 'Live' : s === 'stale' ? 'Stale' : 'Silent'
}

export function formatAge(minutes: number): string {
  if (minutes < 60) return `${minutes} min`
  if (minutes < 1440) return `${Math.round(minutes / 60)} h`
  return `${Math.round(minutes / 1440)} d`
}

export function statusCopy(sensor: PicketSensor): string {
  const age = formatAge(sensor.export_age_minutes)
  if (sensor.status === 'live') return `Sensor reporting · last export ${age} ago`
  if (sensor.status === 'stale') return `Sensor stale · no export for ${age} — figures below are the last received`
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
