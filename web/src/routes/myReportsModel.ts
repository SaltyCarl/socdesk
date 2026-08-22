// myReportsModel — pure view logic for the My-reports route (kept out of the
// component so it exports no non-component values — react-refresh discipline,
// and so it is node-testable).

/** A report's moderation status → a NEUTRAL/ACCENT chip variant, NEVER a verdict
 *  hue (a report's lifecycle is not a severity read). In-flight stays neutral;
 *  an actioned/terminal state rides the product accent. */
export function statusChipVariant(status: string): 'neutral' | 'accent' {
  const s = status.toLowerCase()
  if (s === 'published' || s === 'accepted' || s === 'actioned') return 'accent'
  return 'neutral'
}
