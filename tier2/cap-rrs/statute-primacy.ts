import { CapRrsError, type AuthoritySource, type CatalogVersion, type CatalogVersionConflictEvent } from "./types.js";

/**
 * §10.1 Statute-Primacy Rule — the normative consequence sequence when an
 * amendment posterior to endorsed_at is detected. This function models the
 * detection check only; §10.2's event and HEM escalation are built by the
 * caller from its return value (kept as pure data, no side effects here).
 */
export function checkStatutePrimacy(
  source: AuthoritySource,
  amendmentPromulgationOrEnforcementDates: Iso8601Array,
): { conflictDetected: boolean; conflictingDate: string | null } {
  const endorsedAtMs = Date.parse(source.endorsement.endorsed_at);
  const posterior = amendmentPromulgationOrEnforcementDates.filter((d) => Date.parse(d) > endorsedAtMs);
  if (posterior.length === 0) return { conflictDetected: false, conflictingDate: null };
  // earliest posterior amendment is the one that first breaks primacy
  const earliest = posterior.reduce((a, b) => (Date.parse(a) < Date.parse(b) ? a : b));
  return { conflictDetected: true, conflictingDate: earliest };
}

type Iso8601Array = string[];

export function buildCatalogVersionConflictEvent(f: {
  catalogEntryId: string;
  source: AuthoritySource;
  conflictingAmendmentDate: string;
  hemEscalationId: string;
  nowMs: number;
}): CatalogVersionConflictEvent {
  const endorsedAtMs = Date.parse(f.source.endorsement.endorsed_at);
  const deltaDays = Math.round((Date.parse(f.conflictingAmendmentDate) - endorsedAtMs) / (1000 * 60 * 60 * 24));
  return {
    event_type: "CATALOG_VERSION_CONFLICT",
    catalog_entry_id: f.catalogEntryId,
    authority_source_profile: f.source.profile,
    authority_source_law_id: f.source.law_id,
    authority_source_article_ref: f.source.article_ref,
    endorsed_at: f.source.endorsement.endorsed_at,
    conflicting_amendment_promulgation_date: f.conflictingAmendmentDate,
    conflict_delta_days: deltaDays,
    suspension_effective_at: new Date(f.nowMs).toISOString(),
    hem_escalation_id: f.hemEscalationId,
    resolution: null,
  };
}

/** §10.1(1): provisional suspension — ongoing SACR-authorized actions may complete; no NEW SACR may cite the suspended entry. */
export function assertNoNewSacrOnSuspendedEntry(catalogEntryId: string, suspendedEntryIds: ReadonlySet<string>): void {
  if (suspendedEntryIds.has(catalogEntryId)) {
    throw new CapRrsError("CATALOG_VERSION_REJECTED", `§10.1(1): catalog entry ${catalogEntryId} is under provisional suspension — no new SACR may be issued citing it`);
  }
}

// ---------------------------------------------------------------------------
// §10.5 — catalog_version rejection rules (a)-(d)
// ---------------------------------------------------------------------------

export function assertCatalogVersionValid(
  newVersion: CatalogVersion | undefined,
  currentActiveVersionId: string,
  currentActiveEffectiveDate: string,
  updatedEntryEndorsementAuthorityId: string,
): void {
  if (!newVersion) {
    throw new CapRrsError("CATALOG_VERSION_REJECTED", "§10.5(a): catalog_version is absent — GEC MUST reject");
  }
  if (newVersion.supersedes !== currentActiveVersionId) {
    throw new CapRrsError("CATALOG_VERSION_REJECTED", `§10.5(b): supersedes "${newVersion.supersedes}" does not match currently active version_id "${currentActiveVersionId}"`);
  }
  if (Date.parse(newVersion.effective_date) < Date.parse(currentActiveEffectiveDate)) {
    throw new CapRrsError("CATALOG_VERSION_REJECTED", "§10.5(c): effective_date is earlier than the currently active effective_date — rollback attack defense triggered");
  }
  if (newVersion.published_by !== updatedEntryEndorsementAuthorityId) {
    throw new CapRrsError("CATALOG_VERSION_REJECTED", "§10.5(d): published_by does not match endorsement.authority_id in the updated entry");
  }
}

// ---------------------------------------------------------------------------
// §10.4 — Safe Harbor Clause
// ---------------------------------------------------------------------------

export interface SafeHarborEvidence {
  endorsed_at: Iso8601Only;
  prior_interpretation_id?: string;
  suspension_effective_at: Iso8601Only;
}

type Iso8601Only = string;

/** §10.4: endorsed_at anterior to suspension_effective_at establishes the action was taken under a valid, non-superseded endorsement. */
export function isSafeHarborProtected(evidence: SafeHarborEvidence): boolean {
  return Date.parse(evidence.endorsed_at) < Date.parse(evidence.suspension_effective_at);
}
