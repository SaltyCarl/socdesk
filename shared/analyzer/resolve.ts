import { tokenize, type Token } from './lex'

const isPlus = (t: Token | undefined): boolean => t?.type === 'bareword' && t?.value === '+'
const isVar = (t: Token | undefined): boolean => !!t && t.type === 'bareword' && /^\$[A-Za-z_][\w]*$/.test(t.value)
const isEq = (t: Token | undefined): boolean => !!t && t.type === 'punct' && t.value === '='

/** Serialize one token back to source-ish text: strings become single-quoted
 *  (their resolved value re-quoted), everything else keeps its original `raw`.
 *  Bare words starting with '+' followed by other chars are split (e.g. '+$x' → '+ $x').
 *  Embedded single quotes in strings are escaped by doubling. */
function emit(t: Token): string {
  if (t.type === 'string') {
    return `'${t.value.replace(/'/g, "''")}'`
  }
  // Bareword starting with '+' followed by other chars: split into operator + operand
  if (t.type === 'bareword' && t.value.startsWith('+') && t.value.length > 1) {
    return '+ ' + t.value.slice(1)
  }
  return t.raw
}

/** Collapse `'a'+'b'+…` runs of string literals into one string token. Only
 *  folds when BOTH sides of every `+` are string literals — a non-literal
 *  operand (a variable, a call) stops the run and is left untouched. */
export function foldConcat(text: string): string {
  const toks = tokenize(text)
  const out: string[] = []
  let i = 0
  while (i < toks.length) {
    if (toks[i].type === 'string' && isPlus(toks[i + 1]) && toks[i + 2]?.type === 'string') {
      let value = toks[i].value
      let j = i + 1
      while (isPlus(toks[j]) && toks[j + 1]?.type === 'string') {
        value += toks[j + 1].value
        j += 2
      }
      out.push(`'${value.replace(/'/g, "''")}'`)
      i = j
    } else {
      out.push(emit(toks[i]))
      i++
    }
  }
  return out.join(' ')
}

/** Substitute single-assignment `$var = '<literal>'` bindings. A variable bound
 *  exactly once to a string literal is replaced at its use sites; a variable
 *  assigned more than once, or to a non-literal, is marked ambiguous and left
 *  untouched (never guessed). Straight-line only — no control-flow reasoning. */
export function resolveVars(text: string): string {
  const toks = tokenize(text)
  // Pass 1: collect single-assignment bindings + the token index of the assignment.
  const bound = new Map<string, { value: string; at: number }>()
  const poisoned = new Set<string>()
  for (let i = 0; i < toks.length; i++) {
    if (isVar(toks[i]) && isEq(toks[i + 1])) {
      const name = toks[i].value
      if (toks[i + 2]?.type === 'string' && !isPlus(toks[i + 3])) {
        if (bound.has(name) || poisoned.has(name)) { bound.delete(name); poisoned.add(name) }
        else bound.set(name, { value: toks[i + 2].value, at: i })
      } else {
        bound.delete(name); poisoned.add(name) // assigned to a non-literal → ambiguous
      }
    }
  }
  // Pass 2: substitute a bound var ONLY at a use site AFTER its assignment (never
  // the LHS, never a use-before-def), escaping quotes so it round-trips.
  const out: string[] = []
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]
    const isAssignLhs = isVar(t) && isEq(toks[i + 1])
    const b = isVar(t) && !isAssignLhs ? bound.get(t.value) : undefined
    if (b && i > b.at) out.push(`'${b.value.replace(/'/g, "''")}'`)
    else out.push(emit(t))
  }
  return out.join(' ')
}

const isOpenParen = (t: Token | undefined): boolean => !!t && t.type === 'punct' && t.value === '('
const isCloseParen = (t: Token | undefined): boolean => !!t && t.type === 'punct' && t.value === ')'
const isOpenBracket = (t: Token | undefined): boolean => !!t && t.type === 'punct' && t.value === '['
const isCloseBracket = (t: Token | undefined): boolean => !!t && t.type === 'punct' && t.value === ']'
const isComma = (t: Token | undefined): boolean => !!t && t.type === 'punct' && t.value === ','
const isCharKeyword = (t: Token | undefined): boolean => !!t && t.type === 'bareword' && /^char$/i.test(t.value)
const isJoinKeyword = (t: Token | undefined): boolean => !!t && t.type === 'bareword' && /^-join$/i.test(t.value)
const isDigits = (t: Token | undefined): boolean => !!t && t.type === 'bareword' && /^\d+$/.test(t.value)
const isEmptyStringTok = (t: Token | undefined): boolean => !!t && t.type === 'string' && t.value === ''

/** Match a `[char]NN` run at token index i (numeric literal only — a
 *  `[char]$x` cast with a variable operand fails this match and is left
 *  untouched, never guessed). Returns the code point and the index just
 *  past the match, or undefined. */
function matchCharLiteral(toks: Token[], i: number): { code: number; next: number } | undefined {
  if (!isOpenBracket(toks[i]) || !isCharKeyword(toks[i + 1]) || !isCloseBracket(toks[i + 2]) || !isDigits(toks[i + 3])) return undefined
  return { code: Number(toks[i + 3].value), next: i + 4 }
}

/** Fold `[char]NN` → its character and `([char]A,[char]B,…) -join ''` → the
 *  assembled literal. Operates on the TOKEN stream (like foldConcat), never
 *  on raw text — a `[char]73`-shaped run of characters inside a string
 *  literal's payload is a single 'string' token and is passed through via
 *  emit() unchanged; it can never be reinterpreted as code. Numeric literals
 *  only — a `[char]$x` with a variable, or a `-join` whose array contains a
 *  non-literal element, is left untouched (a bare `[char]NN` elsewhere in
 *  that same unresolvable expression may still fold on its own — that is
 *  real, independently-decodable code, not a guess). */
export function foldCharArray(text: string): string {
  const toks = tokenize(text)
  const out: string[] = []
  let i = 0
  while (i < toks.length) {
    // ( [char]A , [char]B , ... [char]N ) -join '' | "" → 'assembled'
    if (isOpenParen(toks[i])) {
      const codes: number[] = []
      let j = i + 1
      let ok = true
      for (;;) {
        const m = matchCharLiteral(toks, j)
        if (!m) { ok = false; break }
        codes.push(m.code)
        j = m.next
        if (isComma(toks[j])) { j++; continue }
        break
      }
      if (ok && codes.length > 0 && isCloseParen(toks[j]) && isJoinKeyword(toks[j + 1]) && isEmptyStringTok(toks[j + 2])) {
        const s = String.fromCharCode(...codes).replace(/'/g, "''")
        out.push(`'${s}'`)
        i = j + 3
        continue
      }
    }
    // bare [char]73 → 'I'
    const m = matchCharLiteral(toks, i)
    if (m) {
      out.push(`'${String.fromCharCode(m.code).replace(/'/g, "''")}'`)
      i = m.next
      continue
    }
    out.push(emit(toks[i]))
    i++
  }
  return out.join(' ')
}

const isFormatOp = (t: Token | undefined): boolean => !!t && t.type === 'bareword' && /^-f$/i.test(t.value)

/** Fold `'{0}{1}' -f 'a','b'` → `'ab'`. Operates on the TOKEN stream (like
 *  foldConcat/foldCharArray), never on raw text — a format string or arg is
 *  only recognized when it is its OWN 'string' token, separated from the
 *  `-f` bareword and from every other arg by real token boundaries. Content
 *  such as `-f` or `{0}` sitting inside the payload of a single string
 *  literal is part of that one token's value and can never be mistaken for
 *  the operator or a placeholder. Every arg must itself be a literal string
 *  token — a variable arg (or any non-string token in the arg list) leaves
 *  the whole expression untouched. Plain `{N}` placeholders only: a
 *  format-spec/alignment component (`{0:X2}`, `{0,10}`) or an out-of-range
 *  index also leaves it untouched, never guessed. */
export function foldFormat(text: string): string {
  const toks = tokenize(text)
  const out: string[] = []
  let i = 0
  while (i < toks.length) {
    if (toks[i].type === 'string' && isFormatOp(toks[i + 1]) && toks[i + 2]?.type === 'string') {
      const args: string[] = [toks[i + 2].value]
      let j = i + 3
      let literalArgs = true
      while (isComma(toks[j])) {
        if (toks[j + 1]?.type === 'string') { args.push(toks[j + 1].value); j += 2 }
        else { literalArgs = false; break }
      }
      if (literalArgs) {
        const fmt = toks[i].value
        let ok = !/\{\s*\d+\s*[:,]/.test(fmt) // format-spec/alignment present — do not fold
        const folded = ok
          ? fmt.replace(/\{(\d+)\}/g, (whole: string, idx: string) => {
              const v = args[Number(idx)]
              if (v === undefined) { ok = false; return whole } // index out of range — do not fold
              return v
            })
          : fmt
        if (ok) {
          out.push(`'${folded.replace(/'/g, "''")}'`)
          i = j
          continue
        }
      }
    }
    out.push(emit(toks[i]))
    i++
  }
  return out.join(' ')
}

const REGEX_METACHAR = /[.\\^$*+?()[\]{}|]/

const isReplaceOp = (t: Token | undefined): boolean => !!t && t.type === 'bareword' && /^-replace$/i.test(t.value)
const isReplaceMethod = (t: Token | undefined): boolean => !!t && t.type === 'bareword' && /^\.replace$/i.test(t.value)

/** Fold `'subject' -replace 'pat','rep'` and `'subject'.Replace('pat','rep')` to
 *  the substituted literal — plain-substring substitution ONLY, via split/join,
 *  NEVER by constructing `new RegExp(pat)` from attacker-controlled text.
 *  `-replace` is PowerShell's REGEX replace operator, so a pattern containing
 *  any regex metacharacter is left unfolded (ReDoS guard, spec §5): a hostile
 *  paste must never hand our own analyzer a catastrophic regex to execute.
 *  The SAME metacharacter guard is applied to the `.Replace()` method form
 *  too — even though .NET's String.Replace is never regex, one shared guard
 *  is simpler to reason about and is strictly more conservative, never less
 *  safe (it only ever means falling through to the residue detector instead
 *  of folding, not a wrong or unsafe fold). An empty pattern is also left
 *  unfolded on both forms: `split('')` does not reproduce -replace's regex
 *  empty-match semantics, and .NET's String.Replace throws on an empty
 *  oldValue — folding either would misrepresent what the real call does.
 *
 *  Operates on the TOKEN stream (like foldConcat/foldCharArray/foldFormat),
 *  never on raw text: the subject, pattern and replacement must each be
 *  their OWN 'string' token, separated by real token boundaries from the
 *  `-replace`/`.Replace` operator and from each other — a string literal
 *  whose PAYLOAD merely contains the text `-replace` or `.Replace(` can
 *  never be mistaken for the operator, because there is no token boundary
 *  there for the match to fire against (this is the same safety argument as
 *  foldFormat's fix in Task 9 / foldCharArray's fix in Task 8). A variable
 *  subject, pattern or replacement operand leaves the whole expression
 *  untouched — never guessed.
 *
 *  Whenever a full structural match is found (subject + operator + pattern +
 *  `,` + replacement, in either form), the ENTIRE span is consumed as one
 *  atomic unit — folded if the guard accepts it, or re-emitted verbatim
 *  token-by-token if the guard rejects it (metachar or empty pattern) — and
 *  `i` always advances past the whole span. It never falls through to the
 *  generic single-token `i++` mid-span: doing so would let a rejected
 *  clause's replacement-arg token (itself a 'string' token) be re-examined
 *  on its own iteration as a fresh candidate SUBJECT, which could then fold
 *  against an immediately-following real `-replace`/`.Replace` clause and
 *  silently consume + delete it. Concretely: `'evil' -replace '(x)','XX'
 *  -replace 'qq','EE'` — the first clause's pattern `'(x)'` has a
 *  metachar, so it is unresolvable; treating the whole clause as one atomic
 *  span (verbatim, on rejection) keeps `'XX'` from ever being reconsidered
 *  as the subject of the trailing ` -replace 'qq','EE'`, which is otherwise
 *  silently deleted. A partial fold is never produced either way — a span
 *  either folds completely or is reproduced completely, and no token is
 *  ever dropped or reinterpreted across a clause boundary. */
export function foldReplace(text: string): string {
  const toks = tokenize(text)
  const out: string[] = []
  let i = 0
  while (i < toks.length) {
    if (toks[i].type === 'string') {
      // 'subj' -replace 'pat' , 'rep'
      if (
        isReplaceOp(toks[i + 1]) &&
        toks[i + 2]?.type === 'string' &&
        isComma(toks[i + 3]) &&
        toks[i + 4]?.type === 'string'
      ) {
        const pat = toks[i + 2].value
        if (pat !== '' && !REGEX_METACHAR.test(pat)) {
          const folded = toks[i].value.split(pat).join(toks[i + 4].value)
          out.push(`'${folded.replace(/'/g, "''")}'`)
        } else {
          for (let k = i; k <= i + 4; k++) out.push(emit(toks[k]))
        }
        i += 5
        continue
      }
      // 'subj' . Replace ( 'pat' , 'rep' )
      if (
        isReplaceMethod(toks[i + 1]) &&
        isOpenParen(toks[i + 2]) &&
        toks[i + 3]?.type === 'string' &&
        isComma(toks[i + 4]) &&
        toks[i + 5]?.type === 'string' &&
        isCloseParen(toks[i + 6])
      ) {
        const pat = toks[i + 3].value
        if (pat !== '' && !REGEX_METACHAR.test(pat)) {
          const folded = toks[i].value.split(pat).join(toks[i + 5].value)
          out.push(`'${folded.replace(/'/g, "''")}'`)
        } else {
          for (let k = i; k <= i + 6; k++) out.push(emit(toks[k]))
        }
        i += 7
        continue
      }
    }
    out.push(emit(toks[i]))
    i++
  }
  return out.join(' ')
}

/** Re-emit the token stream with no folding or substitution — the whitespace/
 *  quote baseline that separates real deobfuscation from mere reformatting.
 *  resolve(x) === normalize(x) exactly when nothing was folded or substituted. */
export function normalize(text: string): string {
  return tokenize(text).map(emit).join(' ')
}

/** Fold concatenations and substitute single-assignment vars to a fixpoint.
 *  Capped so hostile input can never spin. Note: a var built FROM a concat
 *  (`$c = $a + $b`) resolves over successive passes — substitute the vars, then
 *  the next foldConcat collapses the now-literal `'x' + 'y'`. */
export function resolve(text: string): string {
  const MAX_OUTPUT = 1 << 20 // 1 MiB — bail past this; return the last bounded form
  let cur = text
  for (let i = 0; i < 12; i++) {
    const next = foldConcat(foldReplace(foldFormat(foldCharArray(resolveVars(cur)))))
    if (next.length > MAX_OUTPUT) return cur
    if (next === cur) return next
    cur = next
  }
  return cur
}
