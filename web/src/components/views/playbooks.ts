// playbooks.ts — pure templating + filtering for the enrichment Hunt Playbooks.
// No React, no I/O — unit-tested in the node-env vitest.

import type { Playbook } from './types'

/** IndicatorType (ipv4/ipv6/domain/...) -> step param FAMILY (ip/domain/...).
 *  Both IP families collapse to `ip`; `email`/`cve` have no v1 param (identity
 *  playbooks are IP-triggered in v1). The `param` vocabulary and the
 *  IndicatorType union are DIFFERENT namespaces — this is the bridge. */
export const PARAM_FOR_TYPE: Record<string, string> = {
  ipv4: 'ip',
  ipv6: 'ip',
  domain: 'domain',
  url: 'url',
  md5: 'md5',
  sha1: 'sha1',
  sha256: 'sha256',
}

/** Playbooks offered for an enriched IOC type — those whose ioc_types include it. */
export function playbooksForType(playbooks: Playbook[], iocType: string): Playbook[] {
  return playbooks.filter((p) => p.ioc_types.includes(iocType))
}

/** Escape a value for safe insertion inside a KQL double-quoted string literal:
 *  drop control chars (Unicode Cc — belt-and-suspenders; the IOC is already
 *  detectType-validated), then escape backslash BEFORE quote (order matters —
 *  quote-first would double-escape the backslash). Hyphens/dots are preserved —
 *  domains legitimately contain them. */
function escapeKqlString(v: string): string {
  return v.replace(/\p{Cc}/gu, '').replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

/** Substitute `{{stepParam}}` with the escaped IOC ONLY when the IOC's type maps
 *  to this step's param family; otherwise leave the placeholder visible (a
 *  follow-on entity the analyst fills — never fabricated). Replaces ALL
 *  occurrences via split/join. */
export function injectIoc(kql: string, stepParam: string, iocType: string, iocValue: string): string {
  if (PARAM_FOR_TYPE[iocType] !== stepParam) return kql
  return kql.split(`{{${stepParam}}}`).join(escapeKqlString(iocValue))
}
