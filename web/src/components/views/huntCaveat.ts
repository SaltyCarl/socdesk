// huntCaveat.ts — the per-dialect portability caveat, shared by the Adversaries
// hunt-pack and the enrichment playbook panel (one honest source, no drift). A
// plain constant, so it lives in a .ts (component files export components only).

/** A starting point written for one engine; swap the time column + re-validate
 *  for the other. */
export const DIALECT_CAVEAT: Record<string, string> = {
  log_analytics:
    'Written for a Sentinel workspace (TimeGenerated); in Defender advanced hunting swap TimeGenerated → Timestamp and re-validate.',
  advanced_hunting:
    'Written for Defender advanced hunting (Timestamp); in a Sentinel workspace swap Timestamp → TimeGenerated and re-validate.',
}
