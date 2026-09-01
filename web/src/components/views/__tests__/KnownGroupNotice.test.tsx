import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { KnownGroupNotice } from '../KnownGroupNotice'

describe('KnownGroupNotice — name-only coverage-layer profile stub', () => {
  const html = renderToStaticMarkup(<KnownGroupNotice slug="black x" name="Black X" />)

  it('states the tracked-but-nothing-on-file position with the display name', () => {
    expect(html).toContain('Black X is tracked')
    expect(html).toContain('no claims in the current window')
  })

  it('links OUT to the encoded ransomware.live group page (never editorial inline)', () => {
    expect(html).toContain('href="https://www.ransomware.live/group/black%20x"')
  })

  it('falls back to the slug when no display name is available', () => {
    const bare = renderToStaticMarkup(<KnownGroupNotice slug="nitrogen" />)
    expect(bare).toContain('nitrogen is tracked')
  })
})
