// adminModel — pure view logic for the /admin moderation console (kept out
// of the component so it exports no non-component values — react-refresh
// discipline — and so it is node-testable, mirroring myReportsModel.ts).

export type QueuedReport = {
  id: string
  github_id: number
  login: string | null
  ioc_type: string
  ioc_value: string
  category: string
  evidence: string
  comment: string | null
  status: string
  created_at: string
}

/** Optimistic queue update after a successful moderation POST — drops the
 *  actioned row so the list always reflects "still needs a decision." */
export function removeFromQueue(rows: QueuedReport[], id: string): QueuedReport[] {
  return rows.filter((r) => r.id !== id)
}
