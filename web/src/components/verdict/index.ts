// Public surface of the escalation-card system.
//
// Two registers over one shared VerdictData: the client escalation card + its
// deterministic copy-card PNG, and the dense analyst console. All wording +
// banding come from web/src/lib/verdict (the doctrine); this layer only renders.

export { EscalationCard } from './EscalationCard'
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

export { renderVerdictCanvas } from './drawVerdict'
export type { DrawOptions } from './drawVerdict'
export { copyCard, copyText } from './copy'
export type { CopyCardResult } from './copy'
export { detectTheme } from './palette'
export type { CanvasTheme } from './palette'

export { STUBS } from './stubs'
export type { Stub } from './stubs'
