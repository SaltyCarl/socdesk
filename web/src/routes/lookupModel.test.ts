import { describe, expect, it } from 'vitest'
import { cveToVerdict, parseQ } from './lookupModel'
import type { Cve } from '../components/views/types'

describe('parseQ', () => {
  it('decodes a plain indicator', () => {
    expect(parseQ('#q=1.1.1.1')).toBe('1.1.1.1')
  })
  it('decodes a percent-encoded command', () => {
    expect(parseQ('#q=powershell%20-enc%20AAA')).toBe('powershell -enc AAA')
  })
  it('returns empty for an empty q value', () => {
    expect(parseQ('#q=')).toBe('')
  })
  it('returns empty for no hash', () => {
    expect(parseQ('')).toBe('')
  })
  it('returns empty for a bare hash', () => {
    expect(parseQ('#')).toBe('')
  })
  it('returns empty when there is no q param', () => {
    expect(parseQ('#foo')).toBe('')
  })
  it('finds q after another param', () => {
    expect(parseQ('#a=1&q=8.8.8.8')).toBe('8.8.8.8')
  })
  it('falls back to the raw token on malformed encoding', () => {
    expect(parseQ('#q=%E0%A4%A')).toBe('%E0%A4%A')
  })
  it('trims surrounding whitespace', () => {
    expect(parseQ('#q=%20%208.8.8.8%20')).toBe('8.8.8.8')
  })
})

const BASE_KEV: Cve = {
  cve: 'CVE-2026-1111',
  kev: true,
  kev_date_added: '2026-07-25',
  kev_ransomware: false,
}

const kevSource = (cve: Cve, snapshotAt?: string) =>
  cveToVerdict(cve, snapshotAt).sources.find((s) => s.kev)

describe('cveToVerdict — KEV remediation deadline', () => {
  it('flags overdue when the due date precedes the snapshot', () => {
    const s = kevSource(
      { ...BASE_KEV, kev_due_date: '2026-08-15', kev_required_action: 'Apply mitigations.' },
      '2026-08-24T00:00:00Z',
    )
    expect(s?.facts).toContainEqual(['Remediation due', '2026-08-15'])
    expect(s?.facts).toContainEqual(['Status', 'Overdue'])
    expect(s?.facts).toContainEqual(['Required action', 'Apply mitigations.'])
    expect(s?.finding).toContain('past the CISA remediation due date of 2026-08-15')
  })

  it('does not flag overdue when the due date is still in the future', () => {
    const s = kevSource({ ...BASE_KEV, kev_due_date: '2026-09-01' }, '2026-08-24T00:00:00Z')
    expect(s?.facts).toContainEqual(['Remediation due', '2026-09-01'])
    expect(s?.facts?.some((f) => f[1] === 'Overdue')).toBe(false)
    expect(s?.finding).not.toContain('past the CISA remediation due date')
  })

  it('omits the due-date fact when CISA published none', () => {
    const s = kevSource(BASE_KEV, '2026-08-24T00:00:00Z')
    expect(s?.facts?.some((f) => f[0] === 'Remediation due')).toBe(false)
    expect(s?.facts?.some((f) => f[1] === 'Overdue')).toBe(false)
  })

  it('never fabricates "overdue" without a snapshot reference date', () => {
    const s = kevSource({ ...BASE_KEV, kev_due_date: '2020-01-01' })
    expect(s?.facts?.some((f) => f[1] === 'Overdue')).toBe(false)
    expect(s?.finding).not.toContain('past the CISA remediation due date')
  })
})
