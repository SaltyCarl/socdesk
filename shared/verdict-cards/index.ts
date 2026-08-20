// Public surface of the escalation-card system.
//
// Two registers over one shared VerdictData: the client escalation card + its
// deterministic copy-card PNG, and the dense analyst console. All wording +
// banding come from web/src/lib/verdict (the doctrine); this layer only renders.

export { useEffectiveTheme } from './useEffectiveTheme'
export type { EffectiveTheme } from './useEffectiveTheme'
export { EscalationCard } from './EscalationCard'
export type { CompareResult } from './CompareIp'
export { AnalystVerdict } from './AnalystVerdict'
export { CardActions, CardCanvasPreview } from './CardActions'
export { Hero, IpHero, DomainHero, UrlHero, HashHero, CveHero } from './heroes'
export {
  Caveat,
  ContextList,
  IndicatorLine,
  SegGauge,
  SourceLedger,
  TallyHeadline,
  VerdictDot,
  ClassChip,
  RecencyTag,
} from './ui'

export { renderVerdictCanvas } from '../card/drawVerdict'
export type { DrawOptions } from '../card/drawVerdict'
export { copyCard, copyText } from './copy'
export type { CopyCardResult } from './copy'
export { detectTheme } from '../card/palette'
export type { CanvasTheme } from '../card/palette'

export { STUBS } from './stubs'
export type { Stub } from './stubs'
