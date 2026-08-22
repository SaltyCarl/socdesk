// draft — preserve a typed report across the GitHub OAuth round trip. Before
// navigating to GitHub, the dialog stashes the draft (with pendingOpen:true) in
// sessionStorage keyed to the exact resolved indicator; on return, ReportButton
// auto-opens the dialog and restores it, then clears the flag. SSR-safe.

export interface ReportDraft {
  category: string
  evidence: string
  comment: string
  pendingOpen: boolean
}

export function draftKey(iocType: string, iocValue: string): string {
  return `sd-report-draft:${iocType}:${iocValue}`
}

export function saveDraft(iocType: string, iocValue: string, draft: ReportDraft): void {
  try {
    sessionStorage.setItem(draftKey(iocType, iocValue), JSON.stringify(draft))
  } catch {
    /* storage blocked — the round trip just won't restore; non-fatal */
  }
}

export function loadDraft(iocType: string, iocValue: string): ReportDraft | null {
  try {
    const raw = sessionStorage.getItem(draftKey(iocType, iocValue))
    if (!raw) return null
    const p = JSON.parse(raw) as Partial<ReportDraft>
    return {
      category: typeof p.category === 'string' ? p.category : '',
      evidence: typeof p.evidence === 'string' ? p.evidence : '',
      comment: typeof p.comment === 'string' ? p.comment : '',
      pendingOpen: p.pendingOpen === true,
    }
  } catch {
    return null
  }
}

export function clearDraft(iocType: string, iocValue: string): void {
  try {
    sessionStorage.removeItem(draftKey(iocType, iocValue))
  } catch {
    /* no-op */
  }
}
