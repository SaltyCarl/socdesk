/**
 * TipCard — the hero globe's hover / landing card, redesigned in the shipped
 * SLATE briefing language. ONE renderer, three honest cards (IP · ransomware-
 * country · enriched-lookup), shared by GlobeStage3 + GlobeHero3.
 *
 * Design contract (design-system.md + tokens.css):
 *   • Archivo for LABELS (the micro-label voice); IBM Plex Mono for DATA VALUES
 *     only (IPs, counts, ports, dates, coordinates).
 *   • Periwinkle (--accent) is the product tone for the reported layers; verdict
 *     red/amber/green is RESERVED for real severity — only the enrich card's live
 *     source-consensus tally wears it (driven by the result's own `tone`).
 *   • No terminal/bracket/ascii chrome, no fabricated "Enter to open verdict".
 *     Every card ends in a REAL action + an honest framing/attribution line.
 *
 * Position + show-state + the --tip-accent colour are owned by useGlobe3 (CSSOM
 * setProperty); this file only renders content. No `style=` props (CSP + the
 * react/forbid-dom-props lint) — dynamic values ride className + the mono value
 * cells the engine never touches.
 */

import type { ReactNode } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { safeUrl } from '@socdesk/shared/indicators'
import type { EnrichCard, HeroPin, IpPin, RansomCountryPin } from './heroLayers'

export type HeroCard = HeroPin | EnrichCard

/** SPA navigation — mirrors palette/commands.ts::navigate (pushState + a
 *  synthetic popstate the App router listens for). Local so the lazy hero chunk
 *  stays self-contained. */
function spaNavigate(href: string): void {
  window.history.pushState({}, '', href)
  window.dispatchEvent(new PopStateEvent('popstate'))
}

function Row({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="sdh-card-row">
      <span className="sdh-k">{k}</span>
      <span className="sdh-v">{children}</span>
    </div>
  )
}

/* ---------------- layer 1 — reported IP ---------------- */

function IpBody({ pin }: { pin: IpPin }) {
  const href = safeUrl(pin.lookupHref)
  return (
    <>
      <div className="sdh-card-head">
        <span className="sdh-card-badge">Reported IP</span>
        <span className="sdh-card-id">{pin.ip}</span>
      </div>
      <div className="sdh-card-rows">
        <Row k="Malware">
          <span className="sdh-v-text">{pin.malware}</span>
        </Row>
        <Row k="Source">
          <span className="sdh-v-text">{pin.sourceLabel}</span>
        </Row>
        {pin.port && <Row k="Port">{pin.port}</Row>}
        {pin.country && <Row k="Country">{pin.country}</Row>}
        <Row k="First seen">{pin.firstSeen}</Row>
        <Row k="Last seen">{pin.lastSeen}</Row>
      </div>
      <p className="sdh-card-note">
        Reported malicious infrastructure (abuse.ch). Geolocation approximate —
        hosting/registrar, not operator.
      </p>
      <div className="sdh-card-foot">
        <span className="sdh-card-src">abuse.ch · {pin.sourceLabel}</span>
        {href && (
          <a
            className="sdh-card-action"
            href={href}
            target="_blank"
            rel="noopener noreferrer"
          >
            AbuseIPDB<span aria-hidden="true"> →</span>
          </a>
        )}
      </div>
    </>
  )
}

/* ---------------- layer 2 — ransomware by victim country ---------------- */

function RansomBody({ pin }: { pin: RansomCountryPin }) {
  return (
    <>
      <div className="sdh-card-head">
        <span className="sdh-card-badge">Ransomware claims</span>
        <span className="sdh-card-place">{pin.countryName || pin.country}</span>
      </div>
      <div className="sdh-card-rows">
        <Row k="Claimed victims">
          {pin.claims}
          <span className="sdh-v-unit"> located</span>
        </Row>
      </div>
      {pin.groups.length > 0 && (
        <div className="sdh-card-groups">
          <span className="sdh-k">Top groups</span>
          <div className="sdh-card-grouplist">
            {pin.groups.map((g) => {
              const href = `/actor#g=${encodeURIComponent(g.slug)}`
              return (
                <a
                  key={g.slug}
                  className="sdh-card-group"
                  href={href}
                  onClick={(e) => {
                    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
                    e.preventDefault()
                    spaNavigate(href)
                  }}
                >
                  <span className="sdh-card-group-name">{g.name}</span>
                  <span className="sdh-v">{g.claims}</span>
                </a>
              )
            })}
          </div>
        </div>
      )}
      <p className="sdh-card-note">
        Claimed-victim country (where victims are being hit) — not attacker
        origin. Located single claims only; digests are not placed.
      </p>
      <div className="sdh-card-foot">
        <span className="sdh-card-src">ransomware.live</span>
      </div>
    </>
  )
}

/* ---------------- layer 3 — live enrich landing ---------------- */

function EnrichBody({ card }: { card: EnrichCard }) {
  const href = safeUrl(card.primaryUrl)
  const tallyLabel =
    card.consulted === 0 ? 'no sources returned' : 'of sources flagged this'
  return (
    <>
      <div className="sdh-card-head">
        <span className="sdh-card-badge sdh-card-badge-verdict">{card.type || 'Indicator'}</span>
        <span className="sdh-card-id">{card.indicator}</span>
      </div>
      <div className="sdh-card-tally">
        <span className="sdh-card-tally-num">
          {card.flagged}
          <span className="sdh-v-unit">/{card.consulted}</span>
        </span>
        <span className="sdh-card-tally-label">{tallyLabel}</span>
      </div>
      {card.findings.length > 0 && (
        <div className="sdh-card-findings">
          {card.findings.map((f) => (
            <div className="sdh-card-finding" key={f.name}>
              <span className="sdh-k">{f.name}</span>
              <span className="sdh-card-finding-text">{f.text}</span>
            </div>
          ))}
        </div>
      )}
      {(card.geoText || card.asnText) && (
        <div className="sdh-card-rows">
          {card.geoText && (
            <Row k="Location">
              <span className="sdh-v-text">{card.geoText}</span>
            </Row>
          )}
          {card.asnText && (
            <Row k="ASN">
              <span className="sdh-v-text">{card.asnText}</span>
            </Row>
          )}
        </div>
      )}
      <p className="sdh-card-note">
        SOCDesk counts independent public sources — it does not issue a verdict.
        Geolocation is context, never attribution.
        {card.partial && ' Some sources were unavailable.'}
      </p>
      <div className="sdh-card-foot">
        <span className="sdh-card-src">Queried {card.checkedAt}</span>
        {href && card.primaryLabel && (
          <a
            className="sdh-card-action"
            href={href}
            target="_blank"
            rel="noopener noreferrer"
          >
            {card.primaryLabel}<span aria-hidden="true"> →</span>
          </a>
        )}
      </div>
    </>
  )
}

export function TipCard({ card }: { card: HeroCard }) {
  return (
    <div className={cx('sdh-card', card.kind === 'enrich' && 'sdh-card-enrich')}>
      {card.kind === 'ip' && <IpBody pin={card} />}
      {card.kind === 'ransom' && <RansomBody pin={card} />}
      {card.kind === 'enrich' && <EnrichBody card={card} />}
    </div>
  )
}
