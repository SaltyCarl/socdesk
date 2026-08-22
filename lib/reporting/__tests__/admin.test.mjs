import { describe, expect, it } from 'vitest'
import { isOwner, isValidReportId, statusForAction } from '../admin.mjs'

describe('isOwner — fail-closed owner gate on the numeric github_id', () => {
  it('matches on equal numeric id (env vars arrive as numeric strings)', () => {
    expect(isOwner(12345, '12345')).toBe(true)
  })
  it('is false on a mismatched id', () => {
    expect(isOwner(12345, '99999')).toBe(false)
  })
  it('is false when github_id is not a number', () => {
    expect(isOwner('12345', '12345')).toBe(false)
    expect(isOwner(undefined, '12345')).toBe(false)
  })
  it('fails closed when OWNER_GITHUB_ID is unset (undefined)', () => {
    expect(isOwner(12345, undefined)).toBe(false)
  })
  it('fails closed when OWNER_GITHUB_ID is null', () => {
    expect(isOwner(12345, null)).toBe(false)
  })
  it('fails closed when OWNER_GITHUB_ID is an empty string', () => {
    expect(isOwner(12345, '')).toBe(false)
  })
  it('fails closed when OWNER_GITHUB_ID is a non-numeric string', () => {
    expect(isOwner(12345, 'not-a-number')).toBe(false)
  })
  it('fails closed on a whitespace-only OWNER_GITHUB_ID (the Number("   ")===0 trap)', () => {
    expect(isOwner(0, '   ')).toBe(false)
  })
  it('tolerates surrounding whitespace on an otherwise-numeric value', () => {
    expect(isOwner(12345, '  12345  ')).toBe(true)
  })
})

describe('statusForAction — moderation action vocabulary', () => {
  it('approve maps to approved', () => {
    expect(statusForAction('approve')).toBe('approved')
  })
  it('reject maps to rejected', () => {
    expect(statusForAction('reject')).toBe('rejected')
  })
  it('any other action maps to null', () => {
    expect(statusForAction(undefined)).toBe(null)
    expect(statusForAction('')).toBe(null)
    expect(statusForAction('delete')).toBe(null)
  })
})

describe('isValidReportId — UUID-shape guard before the D1 write', () => {
  it('accepts a real crypto.randomUUID() shape', () => {
    expect(isValidReportId('3fa85f64-5717-4562-b3fc-2c963f66afa6')).toBe(true)
  })
  it('rejects a non-UUID string', () => {
    expect(isValidReportId('not-a-uuid')).toBe(false)
    expect(isValidReportId('1; DROP TABLE reports;--')).toBe(false)
  })
  it('rejects the wrong length', () => {
    expect(isValidReportId('3fa85f64-5717-4562-b3fc-2c963f66afa')).toBe(false)
    expect(isValidReportId('3fa85f64-5717-4562-b3fc-2c963f66afa66')).toBe(false)
  })
  it('rejects a non-string', () => {
    expect(isValidReportId(undefined)).toBe(false)
    expect(isValidReportId(null)).toBe(false)
  })
})
