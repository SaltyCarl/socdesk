import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { HuntPlaybookPanelView } from '../HuntPlaybookPanel'
import type { Playbook } from '../types'

const playbooks: Playbook[] = [
  {
    id: 'unfamiliar-signin-properties', title: 'Unfamiliar sign-in properties',
    ioc_types: ['ipv4', 'ipv6'], techniques: ['T1078.004'], tested: '2026-09-04',
    source: { kind: 'socdesk', url: 'https://x/y.yaml', license: 'MIT', author: 'SOCDesk' },
    steps: [
      { id: 'signins-from-ip', title: 'Every sign-in from this IP', kind: 'pivot', param: 'ip',
        dialect: 'log_analytics', tables: ['SigninLogs'], kql: 'SigninLogs | where IPAddress == "{{ip}}"' },
      { id: 'novelty', title: 'Novelty for an account', kind: 'scenario', param: 'upn',
        dialect: 'log_analytics', tables: ['SigninLogs'], kql: 'where UserPrincipalName == "{{upn}}"' },
    ],
  },
  {
    id: 'password-spray', title: 'Password spray', ioc_types: ['ipv4'], techniques: ['T1110.003'],
    source: { kind: 'socdesk', url: 'https://x/z.yaml', license: 'MIT' }, steps: [],
  },
]

describe('HuntPlaybookPanelView', () => {
  const html = renderToStaticMarkup(
    <HuntPlaybookPanelView playbooks={playbooks} iocType="ipv4" iocValue="203.0.113.7" />,
  )

  it('renders a chip per matching playbook', () => {
    expect(html).toContain('Unfamiliar sign-in properties')
    expect(html).toContain('Password spray')
  })

  it('injects the IP into the default (first) playbook pivot step', () => {
    expect(html).toContain('203.0.113.7')
    expect(html).not.toContain('{{ip}}')
  })

  it('leaves a follow-on {{upn}} placeholder visible with a replace note', () => {
    expect(html).toContain('{{upn}}')
    expect(html).toContain('never')
  })

  it('renders the honesty line + provenance', () => {
    expect(html).toContain('starting point')
    expect(html).toContain('tested 2026-09-04')
  })

  it('renders an honest empty state for an enrichable type with no playbook', () => {
    const empty = renderToStaticMarkup(
      <HuntPlaybookPanelView playbooks={playbooks} iocType="sha256" iocValue="abc" />,
    )
    expect(empty).toContain('No SIEM playbook for sha256 yet')
    expect(empty).toContain('IP indicators supported today')
  })

  it('does not render a chip row when only one playbook matches', () => {
    const one = renderToStaticMarkup(
      <HuntPlaybookPanelView playbooks={playbooks} iocType="ipv6" iocValue="::1" />,
    )
    // ipv6 matches only the first playbook; still renders its steps
    expect(one).toContain('Unfamiliar sign-in properties')
    expect(one).not.toContain('Password spray')
  })
})
