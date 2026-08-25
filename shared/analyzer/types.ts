import type { IndicatorType } from '../indicators'
import type { Token } from './lex'
import type { Interpreter } from './preprocess'

export type ConfidenceTier = 'resolved' | 'inferred' | 'opaque'
export type DecodeState = 'fully-decoded' | 'partial' | 'opaque' | 'wall'
export type Specificity = 'weak' | 'strong' | 'near-dispositive'

export interface EvasionFlag { flag: string; raw: string; techniqueIds: string[] }

/** The read-only context every signature rule matches against. Built once per
 *  analysis from the decoded corpus (all resolved layer texts) + the outer
 *  command-line evasion flags. `words` are lowercased bareword/string token
 *  values — the lexer has already stripped backtick obfuscation, so matching a
 *  word is literal-safe in a way a raw regex is not. `lower` is a whole-text
 *  fallback for multi-word phrases (e.g. decoy comments). */
export interface RuleContext {
  text: string           // decoded corpus (raw script + every resolved layer.text)
  lower: string          // text.toLowerCase()
  tokens: Token[]        // tokenize(text)
  words: string[]        // lowercased bareword + string token values
  flags: EvasionFlag[]   // outer command-line evasion flags from preprocess
  interpreter: Interpreter // resolved interpreter (post nested-reentry); 'unknown' for existing PS-only call sites
  cmdVarsReassembled: boolean // cmd branch only: reassembleCmdVars actually substituted a %var%/!var! reference (ground truth, independent of whether literal evidence survives in `text`)
}

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
  level: 'high-confidence-malicious' | 'suspicious'
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
