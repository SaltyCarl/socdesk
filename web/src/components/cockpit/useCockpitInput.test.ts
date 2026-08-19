import { describe, expect, it } from 'vitest'
import { resolveCockpitArgs, resolveKind } from './useCockpitInput'

describe('resolveCockpitArgs — the unselected hook gets "" (design spec §3.3)', () => {
  it('routes the committed value to useLookup and "" to usePsAnalysis when kind is indicator', () => {
    expect(resolveCockpitArgs('indicator', '185.220.101.34')).toEqual({
      indicatorArg: '185.220.101.34',
      commandArg: '',
    })
  })
  it('routes the committed value to usePsAnalysis and "" to useLookup when kind is command', () => {
    const raw = 'powershell -enc JABzAGUA'
    expect(resolveCockpitArgs('command', raw)).toEqual({
      indicatorArg: '',
      commandArg: raw,
    })
  })
  it('routes "" to both hooks when kind is unclassified — neither hook does work', () => {
    expect(resolveCockpitArgs('unclassified', 'just some plain words')).toEqual({
      indicatorArg: '',
      commandArg: '',
    })
  })
})

describe('resolveKind — the ModeChip override is monotonic (design spec §2.1)', () => {
  it('never pulls an auto-detected command away from command — the leak-blocking case', () => {
    expect(resolveKind('command', 'indicator')).toBe('command')
  })
  it('allows escalating an auto-detected indicator to command', () => {
    expect(resolveKind('indicator', 'command')).toBe('command')
  })
  it('allows escalating an auto-detected unclassified value to command', () => {
    expect(resolveKind('unclassified', 'command')).toBe('command')
  })
  it('passes through indicator when there is no override', () => {
    expect(resolveKind('indicator', null)).toBe('indicator')
  })
  it('passes through command when there is no override', () => {
    expect(resolveKind('command', null)).toBe('command')
  })
})
