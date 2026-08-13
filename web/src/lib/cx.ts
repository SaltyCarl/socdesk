/**
 * Minimal className joiner (no dependency). Falsy parts are dropped so
 * conditional classes stay readable: cx('base', active && 'is-on').
 */
export function cx(
  ...parts: Array<string | false | null | undefined>
): string {
  return parts.filter(Boolean).join(' ')
}
