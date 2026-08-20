// shared/verdict-cards/__tests__/ui.test.ts
// The lead-figure split that drives the evidence-row highlight — the eye should
// land on the number (or the classification phrase), so this parse must be right
// across the source shapes: a percentage, an N/M ratio, and a categorical phrase.
import { describe, expect, it } from 'vitest'
import { splitLead } from '../findingLead'

describe('splitLead (evidence-row lead-figure highlight)', () => {
  it('lifts a leading percentage', () => {
    expect(splitLead('0% abuse confidence · 0 reports in 90 days')).toEqual([
      '0%',
      ' abuse confidence · 0 reports in 90 days',
    ])
  })

  it('lifts a leading N/M ratio', () => {
    expect(splitLead('0/91 engines flagged this')).toEqual(['0/91', ' engines flagged this'])
    expect(splitLead('12/70 engines flagged this')).toEqual(['12/70', ' engines flagged this'])
  })

  it('lifts the leading clause when the finding is categorical (no number)', () => {
    expect(splitLead('Opportunistic internet scanner — mass activity, not targeted')).toEqual([
      'Opportunistic internet scanner',
      ' — mass activity, not targeted',
    ])
  })

  it('bolds the whole finding when it is short with no number or separator', () => {
    expect(splitLead('Known malware sample')).toEqual(['Known malware sample', ''])
  })

  it('does not treat a non-leading number as the lead figure', () => {
    // "Registered 2026-05-14" leads with a word, so the clause (not the date) is lifted.
    const [lead] = splitLead('Registered 2026-05-14 · NameSilo')
    expect(lead).toBe('Registered 2026-05-14')
  })
})
