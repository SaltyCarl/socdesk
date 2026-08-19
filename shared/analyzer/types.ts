import type { IndicatorType } from '../indicators'

export type ConfidenceTier = 'resolved' | 'inferred' | 'opaque'
export type DecodeState = 'fully-decoded' | 'partial' | 'opaque' | 'wall'
export type Specificity = 'weak' | 'strong' | 'near-dispositive'

export interface EvasionFlag { flag: string; raw: string; techniqueIds: string[] }

export interface DecodedLayer {
  index: number
  transform: string
  text: string | null
  state: DecodeState
  residual?: { bytes: number; entropy: number; note: string }
}

export interface ExtractedIoc {
  raw: string
  defanged: string
  type: IndicatorType
  layerIndex: number
}

export interface Signal {
  id: string
  label: string
  techniqueIds: string[]
  specificity: Specificity
  trigger: string
}

export interface Characterization {
  level: 'high-confidence-malicious'
  basis: string[]
  read: string
}

export interface ActionBullet {
  order: number
  verb: string
  text: string
  confidence: ConfidenceTier
  iocs: string[]
  techniqueIds: string[]
}

export interface AnalysisResult {
  input: string
  flags: EvasionFlag[]
  layers: DecodedLayer[]
  iocs: ExtractedIoc[]
  signals: Signal[]
  characterization: Characterization | null
  bullets: ActionBullet[]
  confidence: { fractionAccounted: number; state: DecodeState }
  copyText: string
  checkedAt: string
}
