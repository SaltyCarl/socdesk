import { describe, expect, it } from 'vitest'
import { reportOutcome } from './reportOutcome'

describe('reportOutcome — /api/report response → terminal state', () => {
  it('200 fresh insert → queued', () => {
    expect(reportOutcome(200, { id: 'x', status: 'queued' } as never)).toEqual({ kind: 'queued' })
  })
  it('200 deduped:true → deduped', () => {
    expect(reportOutcome(200, { deduped: true })).toEqual({ kind: 'deduped' })
  })
  it('401 → expired (re-gate; draft preserved)', () => {
    expect(reportOutcome(401, { error: 'auth' })).toEqual({ kind: 'expired' })
  })
  it('400 turnstile → turnstile (reset the widget)', () => {
    expect(reportOutcome(400, { error: 'turnstile' })).toEqual({ kind: 'turnstile' })
  })
  it('400 validation → invalid, carrying the field key', () => {
    expect(reportOutcome(400, { error: 'evidence' })).toEqual({ kind: 'invalid', field: 'evidence' })
    expect(reportOutcome(400, { error: 'ioc_value' })).toEqual({ kind: 'invalid', field: 'ioc_value' })
  })
  it('403 → banned (terminal, flat)', () => {
    expect(reportOutcome(403, { error: 'banned' })).toEqual({ kind: 'banned' })
  })
  it('429 → capped (terminal-today)', () => {
    expect(reportOutcome(429, { error: 'rate' })).toEqual({ kind: 'capped' })
  })
  it('network/parse failure (null body, status 0) → error (retryable)', () => {
    expect(reportOutcome(0, null)).toEqual({ kind: 'error' })
  })
  it('an unexpected 5xx → error (retryable, draft intact)', () => {
    expect(reportOutcome(500, null)).toEqual({ kind: 'error' })
  })
})
