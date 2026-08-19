import { describe, expect, it } from 'vitest'
import { resolveCockpitArgs } from './useCockpitInput'

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
