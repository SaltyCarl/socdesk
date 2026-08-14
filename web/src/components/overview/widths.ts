// widths.ts — a fixed ladder of LITERAL Tailwind width classes for proportional
// bars. Tailwind's JIT only compiles classes it can see verbatim in source, so a
// dynamic `w-[${n}%]` would never generate — the bar reads a bucketed class from
// this ladder instead. (Same technique the EPSS meter uses.) CSP-safe: a class,
// never an inline style.

export const W_LADDER = [
  'w-[0%]', 'w-[5%]', 'w-[10%]', 'w-[15%]', 'w-[20%]', 'w-[25%]', 'w-[30%]',
  'w-[35%]', 'w-[40%]', 'w-[45%]', 'w-[50%]', 'w-[55%]', 'w-[60%]', 'w-[65%]',
  'w-[70%]', 'w-[75%]', 'w-[80%]', 'w-[85%]', 'w-[90%]', 'w-[95%]', 'w-[100%]',
] as const

/** Bucket a 0–1 fraction to the nearest 5% ladder rung. */
export function barWidthClass(fraction: number): string {
  const clamped = Math.min(1, Math.max(0, fraction))
  return W_LADDER[Math.round(clamped * 20)]
}
