import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { About } from '../About'

describe('About', () => {
  it('renders the /about#picket transparency section', () => {
    const html = renderToStaticMarkup(<About />)

    expect(html).toContain('id="picket"')
    expect(html).toContain('owner-moderated')
    expect(html).toContain('never as pairs')
    expect(html).toContain('MaxMind')
    expect(html).toContain('knock-knock')
    expect(html).toContain('abuse@socdesk.io')
  })
})
