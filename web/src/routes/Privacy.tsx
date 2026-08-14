import type { ReactNode } from 'react'
import { MicroLabel, Panel } from '../components/ui'
import { ViewHeader } from '../components/views/ViewFrame'

/**
 * /privacy — the disclosure page, ported from the legacy vanilla site's
 * privacy.html into the slate design language and rewritten to be ACCURATE to
 * how this React app actually handles data (verified against lib/enrich.mjs,
 * functions/api/enrich.js, shared/lib/theme.ts, the palette recents store, and
 * web/public/_headers). No accounts, no tracking, no server-side query storage;
 * the only thing sent anywhere is the indicator the user chooses to look up.
 *
 * Static "last updated" string by design — never Date.now() (a compliance date
 * should change only when the policy changes).
 */

const UPDATED = '2026-08-14'
const CONTACT = 'carlos@sanchezonsecurity.com'

/** A public service the enrichment endpoint queries on the user's behalf. */
interface Provider {
  name: string
  role: string
  href: string
}

const PROVIDERS: Provider[] = [
  {
    name: 'AbuseIPDB',
    role: 'Abuse reports and confidence score for IP addresses.',
    href: 'https://www.abuseipdb.com/privacy',
  },
  {
    name: 'VirusTotal',
    role: 'Multi-engine reputation for IPs, domains, URLs and file hashes.',
    href: 'https://docs.virustotal.com/docs/privacy-policy',
  },
  {
    name: 'GreyNoise',
    role: 'Internet-scanner and background-noise classification for IP addresses.',
    href: 'https://www.greynoise.io/privacy',
  },
  {
    name: 'MalwareBazaar (abuse.ch)',
    role: 'Known-malware sample lookup by file hash.',
    href: 'https://abuse.ch/privacy-policy/',
  },
  {
    name: 'IPinfo',
    role: 'Geolocation and network (ASN) context for IP addresses.',
    href: 'https://ipinfo.io/privacy-policy',
  },
  {
    name: 'urlscan.io',
    role: 'Reads existing public scans for URLs and domains.',
    href: 'https://urlscan.io/privacy/',
  },
]

/** External link — new tab, hardened rel, accent underline-on-hover. */
function Ext({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="text-accent underline-offset-2 outline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-accent"
    >
      {children}
    </a>
  )
}

/** Inline code-like token (endpoints, storage keys, CSP directives). */
function Code({ children }: { children: ReactNode }) {
  return (
    <code className="rounded-sm border border-line bg-panel-soft px-1.5 py-0.5 font-mono text-xs text-paper">
      {children}
    </code>
  )
}

function P({ children }: { children: ReactNode }) {
  return <p className="text-base text-muted">{children}</p>
}

/** A titled disclosure section — mono eyebrow, display heading, prose body. */
function Section({
  eyebrow,
  title,
  children,
}: {
  eyebrow: string
  title: string
  children: ReactNode
}) {
  return (
    <section className="flex flex-col gap-4">
      <div className="flex flex-col gap-2">
        <MicroLabel tone="accent" tick>
          {eyebrow}
        </MicroLabel>
        <h2 className="font-display text-md font-bold tracking-tight text-paper">
          {title}
        </h2>
      </div>
      <div className="flex flex-col gap-4">{children}</div>
    </section>
  )
}

export function Privacy() {
  return (
    <div className="flex flex-col gap-10">
      <ViewHeader
        eyebrow="Disclosure"
        title="Privacy"
        intro="What happens to the indicators you look up, and the data SOCDesk does and does not handle. No accounts, no tracking, no profiles."
        aside={<MicroLabel tone="faint">Last updated {UPDATED}</MicroLabel>}
      />

      <div className="flex max-w-3xl flex-col gap-10">
        <Panel className="border-[var(--edge-accent)] bg-[var(--tint-accent)]">
          <MicroLabel tone="accent" tick>
            In short
          </MicroLabel>
          <p className="mt-2 text-base text-paper">
            The only thing SOCDesk sends anywhere is the indicator{' '}
            <em className="not-italic text-accent">you</em> choose to look up.
            There are no accounts, no profiles, nothing sold, and no
            third-party tracking.
          </p>
        </Panel>

        <Section eyebrow="Lookups" title="What you look up, and where it goes">
          <P>
            When you look up an indicator — an IP address, domain, URL or file
            hash — SOCDesk sends that single indicator to its own same-origin
            endpoint at <Code>/api/enrich</Code>. That endpoint (a Cloudflare
            Pages Function running on SOCDesk&rsquo;s own domain) queries public
            reputation and context services on your behalf and returns their
            assessments. Each of these services receives the indicator you
            looked up and handles it under its own privacy policy:
          </P>

          <Panel padding="none">
            <ul>
              {PROVIDERS.map((p) => (
                <li
                  key={p.name}
                  className="flex flex-col gap-1 border-t border-line p-4 first:border-t-0 sm:flex-row sm:items-baseline sm:justify-between sm:gap-4"
                >
                  <div className="flex flex-col gap-0.5">
                    <span className="text-base font-semibold text-paper">
                      {p.name}
                    </span>
                    <span className="text-xs text-muted">{p.role}</span>
                  </div>
                  <span className="shrink-0">
                    <Ext href={p.href}>Privacy policy</Ext>
                  </span>
                </li>
              ))}
            </ul>
          </Panel>

          <P>
            SOCDesk passes the indicator to these services as a query parameter;
            it never fetches the indicator itself. An attacker-supplied URL is
            never turned into an outbound request on your behalf, and for
            urlscan.io only existing public scans are read — nothing new is ever
            submitted. Private and reserved IP addresses are refused rather than
            forwarded. The API keys used to query these services live only on the
            server and are never sent to your browser.
          </P>

          <P>
            The lookup endpoint keeps no per-user state and stores none of your
            queries. Results are cached briefly at Cloudflare&rsquo;s edge (up to
            15 minutes), keyed only by the indicator and its type — never by
            anything about you — to reduce load on the upstream services. A
            partial result, where a source was temporarily unavailable, is never
            cached.
          </P>
        </Section>

        <Section eyebrow="On your device" title="What stays in your browser">
          <P>
            A small amount of state is kept in your browser&rsquo;s local storage
            and is never transmitted to SOCDesk:
          </P>
          <ul className="flex flex-col gap-3">
            <li className="text-base text-muted">
              <Code>socdesk-theme</Code> — your light / dark / system theme
              choice.
            </li>
            <li className="text-base text-muted">
              <Code>socdesk-recent-indicators</Code> — the last few indicators
              you looked up (up to eight), shown in the command palette&rsquo;s
              recent list.
            </li>
          </ul>
          <P>
            Both live only in your own browser and are removed when you clear
            your browser storage. You can also clear the recent-indicator list at
            any time from the command palette (&ldquo;Clear recent
            indicators&rdquo;).
          </P>
        </Section>

        <Section
          eyebrow="What we don't do"
          title="No accounts, no tracking, no cookies"
        >
          <ul className="flex flex-col gap-3">
            <li className="text-base text-muted">
              No user accounts, logins, passwords or personal profiles — and no
              personal data collected.
            </li>
            <li className="text-base text-muted">
              No advertising, no ad networks, and no cross-site tracking.
            </li>
            <li className="text-base text-muted">
              No analytics or telemetry: the app loads no analytics script, and
              its strict Content-Security-Policy (<Code>{"connect-src 'self'"}</Code>)
              structurally prevents the page from sending anything to a
              third-party host from your browser. Every third-party query happens
              on the server, for the one indicator you chose.
            </li>
            <li className="text-base text-muted">
              No cookies are set by SOCDesk.
            </li>
          </ul>
        </Section>

        <Section eyebrow="Hosting" title="Where SOCDesk runs">
          <P>
            SOCDesk is hosted on Cloudflare Pages. As the network host and CDN,
            Cloudflare processes ordinary request metadata — such as your IP
            address, timestamp and user-agent — to deliver and protect the site,
            under Cloudflare&rsquo;s own terms. SOCDesk does not add its own
            request logging or profiling on top of that.
          </P>
        </Section>

        <Section eyebrow="Scope" title="What this is">
          <P>
            SOCDesk is a free, non-commercial personal portfolio project for
            security analysts. It sells nothing, carries no advertising, and is
            not directed to children.
          </P>
        </Section>

        <Section eyebrow="Housekeeping" title="Changes and contact">
          <P>
            If this policy changes in a material way, the date above will be
            updated.
          </P>
          <P>
            Questions about this policy:{' '}
            <a
              href={`mailto:${CONTACT}`}
              className="text-accent underline-offset-2 outline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-accent"
            >
              {CONTACT}
            </a>
            .
          </P>
        </Section>
      </div>
    </div>
  )
}
