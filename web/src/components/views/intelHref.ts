/** In-app CVE lookup deep link — the same `#q=` target the omnibox/palette write,
 *  so a group's initial-access CVE pivots into SOCDesk's own KEV/EPSS verdict. */
export function cveLookupHref(cve: string): string {
  return `/lookup#q=${encodeURIComponent(cve)}`
}
