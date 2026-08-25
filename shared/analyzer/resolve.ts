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

/** Fold `[char]NN` → its character and `([char]A,[char]B,…) -join ''` → the
 *  assembled literal. Numeric literals only — a `[char]$x` with a variable is
 *  left untouched (never guessed). Whitespace is tolerated inside `[ char ]`
 *  because this runs on `resolveVars()`'s output, which re-emits every
 *  punctuation token (`[`, `]`, `,`, `(`, `)`) space-separated. */
export function foldCharArray(text: string): string {
  // ([char]73,[char]69,...) -join '' | "" → 'IEX'
  const joined = text.replace(
    /\(\s*((?:\[\s*char\s*\]\s*\d+\s*,\s*)+\[\s*char\s*\]\s*\d+)\s*\)\s*-join\s*(?:''|"")/gi,
    (_m, body: string) => {
      const codes = [...body.matchAll(/\[\s*char\s*\]\s*(\d+)/gi)].map((x) => Number(x[1]))
      const s = String.fromCharCode(...codes).replace(/'/g, "''")
      return `'${s}'`
    },
  )
  // bare [char]73 → 'I'
  return joined.replace(/\[\s*char\s*\]\s*(\d+)/gi, (_m, n: string) => `'${String.fromCharCode(Number(n)).replace(/'/g, "''")}'`)
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
    const next = foldConcat(foldCharArray(resolveVars(cur)))
    if (next.length > MAX_OUTPUT) return cur
    if (next === cur) return next
    cur = next
  }
  return cur
}
