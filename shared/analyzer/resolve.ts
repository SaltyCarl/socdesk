import { tokenize, type Token } from './lex'

const isPlus = (t: Token | undefined): boolean => t?.type === 'bareword' && t?.value === '+'

/** Serialize one token back to source-ish text: strings become single-quoted
 *  (their resolved value re-quoted), everything else keeps its original `raw`.
 *  Bare words starting with '+' followed by other chars are split (e.g. '+$x' → '+ $x'). */
function emit(t: Token): string {
  if (t.type === 'string') {
    return `'${t.value}'`
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
      out.push(`'${value}'`)
      i = j
    } else {
      out.push(emit(toks[i]))
      i++
    }
  }
  return out.join(' ')
}
