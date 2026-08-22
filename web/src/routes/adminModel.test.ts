import { describe, expect, it } from 'vitest'
import { removeFromQueue, type QueuedReport } from './adminModel'

function row(id: string): QueuedReport {
  return {
    id,
    github_id: 1,
    login: 'octocat',
    ioc_type: 'ipv4',
    ioc_value: '1.2.3.4',
    category: 'scanner',
    evidence: 'evidence text',
    comment: null,
    status: 'queued',
    created_at: '2026-08-22T00:00:00.000Z',
  }
}

describe('removeFromQueue — optimistic queue update after a moderation POST', () => {
  it('drops the matching row', () => {
    const rows = [row('a'), row('b'), row('c')]
    expect(removeFromQueue(rows, 'b').map((r) => r.id)).toEqual(['a', 'c'])
  })
  it('leaves order and the other rows untouched', () => {
    const rows = [row('a'), row('b')]
    expect(removeFromQueue(rows, 'a')).toEqual([row('b')])
  })
  it('no-ops on an unknown id', () => {
    const rows = [row('a'), row('b')]
    expect(removeFromQueue(rows, 'zzz')).toEqual(rows)
  })
  it('handles an empty array', () => {
    expect(removeFromQueue([], 'a')).toEqual([])
  })
})
