import { describe, it, expect } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { PartialDecodeNotice } from '../PartialDecodeNotice'

describe('PartialDecodeNotice', () => {
  it('renders an escalation band when state is partial', () => {
    const html = renderToStaticMarkup(<PartialDecodeNotice state="partial" />)
    expect(html).toMatch(/partially decoded/i)
    expect(html).toMatch(/escalate/i)
  })
  it('renders nothing when fully decoded', () => {
    expect(renderToStaticMarkup(<PartialDecodeNotice state="fully-decoded" />)).toBe('')
  })
})
