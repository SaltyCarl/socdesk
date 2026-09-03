import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { BoardPanel } from '../board-ui'

describe('BoardPanel — collapsible mode', () => {
  it('renders a plain <section> with its content when not collapsible (unchanged)', () => {
    const html = renderToStaticMarkup(
      <BoardPanel eyebrow="Reporting">
        <p>report body</p>
      </BoardPanel>,
    )
    expect(html).toContain('<section')
    expect(html).not.toContain('<details')
    expect(html).toContain('report body')
  })

  it('renders a native <details> with data-collapsible + id when collapsible', () => {
    const html = renderToStaticMarkup(
      <BoardPanel eyebrow="Hunt pack" id="huntpack" collapsible aside={<span>· 42</span>}>
        <p>hunt rows</p>
      </BoardPanel>,
    )
    expect(html).toContain('<details')
    expect(html).toContain('data-collapsible')
    expect(html).toContain('id="huntpack"')
    expect(html).toContain('<summary')
    expect(html).toContain('· 42') // count rides the aside slot
  })

  it('is COLLAPSED by default (no open attribute) yet keeps content in the DOM (SEO guard)', () => {
    const html = renderToStaticMarkup(
      <BoardPanel eyebrow="ATT&CK fingerprint" id="fingerprint" collapsible>
        <p data-testid="matrix">the full 87-cell matrix</p>
      </BoardPanel>,
    )
    // React renders open={false} as an absent attribute → collapsed
    expect(html).not.toMatch(/<details[^>]*\sopen/)
    // …but the body is still present in static markup (crawlable/printable)
    expect(html).toContain('the full 87-cell matrix')
  })

  it('honors defaultOpen', () => {
    const html = renderToStaticMarkup(
      <BoardPanel eyebrow="Activity" collapsible defaultOpen>
        <p>open body</p>
      </BoardPanel>,
    )
    expect(html).toMatch(/<details[^>]*\sopen/)
  })
})
