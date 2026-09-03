// activity-ui.ts — pure presentation helpers for the leak-site claim heat strip.
// Extracted from ActorProfile so the compact spark in SynthesisBand can reuse the
// exact ladder + labelling (no drift between the full strip and the spark).

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

/** ISO `YYYY-MM-DD` → terse `Mon D`, from the string parts only (deterministic,
 *  no Date/locale — the daily buckets are already UTC date keys). */
export function dayLabel(iso: string): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso)
  if (!m) return iso
  return `${MONTHS[Number(m[2]) - 1] ?? m[2]} ${Number(m[3])}`
}

/** Literal Tailwind opacity classes for the heat ladder (JIT can't see a
 *  computed string — the widths.ts trap). Floor 30%: a fainter periwinkle is
 *  near-invisible on the light theme's panel; lit cells also carry a border
 *  so a single-claim day still reads. Note: this quartile ladder deliberately
 *  supersedes the retired weekly chart's one-accent-tone rule — a heat strip
 *  IS its opacity ramp; the tone is still the single volume accent. */
export function heatClass(count: number, max: number): string {
  if (count <= 0) return 'bg-panel-soft'
  const q = count / Math.max(1, max)
  const o = q > 0.75 ? 'opacity-100' : q > 0.5 ? 'opacity-75' : q > 0.25 ? 'opacity-50' : 'opacity-30'
  return `border border-line bg-accent ${o}`
}
