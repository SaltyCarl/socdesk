import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { ProfileNav } from '../ProfileNav'
import type { NavSection } from '../useProfileNav'

const sections: NavSection[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'activity', label: 'Activity' },
  { id: 'huntpack', label: 'Hunt pack' },
]

describe('ProfileNav', () => {
  it('renders an anchor per section, href to its #id', () => {
    const html = renderToStaticMarkup(<ProfileNav sections={sections} activeId="" />)
    expect(html).toContain('href="#overview"')
    expect(html).toContain('href="#activity"')
    expect(html).toContain('href="#huntpack"')
  })

  it('marks the active section with aria-current', () => {
    const html = renderToStaticMarkup(<ProfileNav sections={sections} activeId="activity" />)
    // the active anchor carries aria-current="true"; render it near its href
    expect(html).toMatch(/href="#activity"[^>]*aria-current="true"|aria-current="true"[^>]*href="#activity"/)
    expect(html).not.toMatch(/href="#overview"[^>]*aria-current="true"/)
  })

  it('renders nothing when there is only the Overview landmark (nothing to orient)', () => {
    const html = renderToStaticMarkup(<ProfileNav sections={[{ id: 'overview', label: 'Overview' }]} activeId="" />)
    expect(html).toBe('')
  })

  it('includes a mobile "Jump to" disclosure', () => {
    const html = renderToStaticMarkup(<ProfileNav sections={sections} activeId="" />)
    expect(html).toContain('Jump to')
    expect(html).toContain('<details')
  })
})
