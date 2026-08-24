import type { ReactNode } from 'react'
import { MicroLabel, Panel } from '../components/ui'
import { ViewHeader } from '../components/views/ViewFrame'

/**
 * /about — what SOCDesk is, plus the transparency page for the community-reports
 * layer. The `#community-reports` section is the "verify" link target for every
 * SOCDesk Community context row on the escalation card (lib/enrich.mjs
 * SOCDESK_COMMUNITY.link) — so the id="community-reports" anchor must stay.
 * Written to be ACCURATE to how the community dataset actually works (verified
 * against pipeline/community.py, schemas/community_reports.schema.json, and
 * lib/enrich.mjs): human-moderated, count-not-verdict, no reporter PII.
 *
 * Static "last updated" by design — never Date.now(); it changes only when the
 * policy does.
 */

const UPDATED = '2026-08-24'
const ABUSE = 'abuse@socdesk.io'

function P({ children }: { children: ReactNode }) {
  return <p className="text-base text-muted">{children}</p>
}

/** Accent inline link — same styling as the privacy page's contact/link form. */
function Link({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a
      href={href}
      className="text-accent underline-offset-2 outline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-accent"
    >
      {children}
    </a>
  )
}

/** A titled section — mono eyebrow, display heading, prose body. `id` anchors
 *  a deep-link target (e.g. #community-reports); scroll-mt keeps the heading
 *  clear of the sticky header when jumped to. */
function Section({
  id,
  eyebrow,
  title,
  children,
}: {
  id?: string
  eyebrow: string
  title: string
  children: ReactNode
}) {
  return (
    <section id={id} className="flex scroll-mt-24 flex-col gap-4">
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

export function About() {
  return (
    <div className="flex flex-col gap-10">
      <ViewHeader
        eyebrow="About"
        title="About SOCDesk"
        intro="A free, non-commercial CTI console for security analysts — paste an indicator, read the reputation, escalate. This page also explains the community-reports layer and how to dispute an entry."
        aside={<MicroLabel tone="faint">Last updated {UPDATED}</MicroLabel>}
      />

      <div className="flex max-w-3xl flex-col gap-10">
        <Section eyebrow="What it is" title="A lookup console, not a verdict machine">
          <P>
            SOCDesk queries public reputation and context services for the one
            indicator you look up and lays their assessments out as an escalation
            card you can read, screenshot, and paste into a ticket. It sells
            nothing, carries no advertising, and keeps no accounts on the lookup
            path. See the <Link href="/privacy">privacy page</Link> for exactly
            what is and isn&rsquo;t handled.
          </P>
        </Section>

        <Section
          id="community-reports"
          eyebrow="Community reports"
          title="The SOCDesk Community layer"
        >
          <Panel className="border-[var(--edge-accent)] bg-[var(--tint-accent)]">
            <MicroLabel tone="accent" tick>
              In short
            </MicroLabel>
            <p className="mt-2 text-base text-paper">
              &ldquo;Reported by N contributor(s)&rdquo; is an attributed{' '}
              <em className="not-italic text-accent">count</em> of the distinct
              people who reported an indicator, reviewed by a human before it
              appears. It is context — never a SOCDesk verdict.
            </p>
          </Panel>

          <P>
            Analysts can report an indicator — an IP address, domain, URL or file
            hash — they have seen behaving abusively. Once a report has been
            approved, it shows on the escalation card as a{' '}
            <strong className="text-paper">SOCDesk Community</strong> row, for
            example &ldquo;Reported by 2 contributors &middot; phishing.&rdquo;
          </P>

          <P>
            <strong className="text-paper">Every entry is owner-moderated.</strong>{' '}
            A report is an allegation, not a fact. Nothing a contributor submits
            appears automatically: the site owner reviews each report, and only
            approved ones are ever published.
          </P>

          <P>
            <strong className="text-paper">It is a count, not a verdict.</strong>{' '}
            The row states how many <em className="not-italic">distinct</em>{' '}
            contributors reported the indicator and the categories they chose —
            nothing more. It sits in the card&rsquo;s context section and is
            deliberately excluded from SOCDesk&rsquo;s independent-source tally
            and its verdict. SOCDesk does not conclude that a reported indicator is
            malicious; it reports that people said so, and leaves the judgement to
            you.
          </P>

          <P>
            <strong className="text-paper">Contributor privacy.</strong> The
            published dataset contains only the indicator, its type, the reported
            categories, a distinct-contributor count, and the first and latest
            report dates. It never contains reporter identities, account handles,
            or the free-text evidence a contributor submitted.
          </P>

          <P>
            <strong className="text-paper">Disputes and removal.</strong> If your
            indicator is listed and you believe it is wrong or should be removed,
            email <Link href={`mailto:${ABUSE}`}>{ABUSE}</Link> with the
            indicator. The owner can un-approve the entry, which removes it from
            the published dataset at the next update.
          </P>
        </Section>
      </div>
    </div>
  )
}
