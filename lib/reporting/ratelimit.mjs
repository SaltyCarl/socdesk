// L3: per-IP daily cap for /api/report. Defense-in-depth ON TOP of the existing
// auth + Turnstile + per-account cap (policy.mjs) so one IP cannot farm many
// accounts. PURE decision + key; the Function wrapper owns the KV I/O and
// fails open (a KV outage must not block legitimate reporting).
export const IP_DAILY_REPORT_CAP = 40   // above the 25/account cap: only bites cross-account farming
export const REPORT_IP_TTL_S = 93_600   // 26h — self-expiring, ZERO deletes

export const overIpDailyCap = (count) => (Number(count) || 0) >= IP_DAILY_REPORT_CAP

export function reportIpKey(ip, now = new Date()) {
  const d = now instanceof Date ? now : new Date(now)
  const y = d.getUTCFullYear()
  const m = String(d.getUTCMonth() + 1).padStart(2, '0')
  const day = String(d.getUTCDate()).padStart(2, '0')
  return `rl:report:${ip}:${y}${m}${day}`
}
