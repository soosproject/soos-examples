import { CapError, type CatalogVersion } from "./types.js";
import { evaluateCedarPolicySet, type CedarPolicyResult } from "./cedar-semantics.js";

// ---------------------------------------------------------------------------
// §8.7 — Cedar Policy Conflict Resolution Rule
// ---------------------------------------------------------------------------

export { evaluateCedarPolicySet }; // CONF-CAP-CONFLICT-01: forbid wins across tiers, re-exported for convenience

/** CONF-CAP-CONFLICT-02: a Tier 2 policy MUST NOT explicitly permit an action a Tier 1 policy forbids. */
export function assertTier2DoesNotOverrideTier1(tier1Decision: "PERMIT" | "FORBID", tier2Decision: "PERMIT" | "FORBID"): void {
  if (tier1Decision === "FORBID" && tier2Decision === "PERMIT") {
    throw new CapError("CATALOG_CONFLICT_REJECTED", "CONF-CAP-CONFLICT-02: Tier 2 policy explicitly permits an action Tier 1 forbids — compliance violation, entry MUST be rejected at load time");
  }
}

/** CONF-CAP-CONFLICT-03: a lower tier MUST NOT narrow the scope of a higher tier prohibition (only PCM may narrow Tier 1). */
export function assertLowerTierDoesNotNarrowHigherScope(higherTierPattern: string, lowerTierNarrowedPattern: string): void {
  if (lowerTierNarrowedPattern !== higherTierPattern && lowerTierNarrowedPattern.startsWith(higherTierPattern)) {
    throw new CapError("CATALOG_CONFLICT_REJECTED", `CONF-CAP-CONFLICT-03: lower-tier pattern "${lowerTierNarrowedPattern}" narrows higher-tier pattern "${higherTierPattern}" — only PCM may narrow Tier 1 scope`);
  }
}

// ---------------------------------------------------------------------------
// §8.8 — Catalog Load Validation, ALE-NEW-02
// ---------------------------------------------------------------------------

export interface CatalogConflictDetected {
  conflicting_catalog_id: string;
  conflicting_cedar_policy_id: string;
  superior_catalog_id: string;
  superior_cedar_policy_id: string;
  conflict_type: "EXPLICIT_PERMIT_OVERRIDE" | "SCOPE_AMBIGUITY";
  resolution: "ENTRY_REJECTED" | "HEM_ESCALATION_TRIGGERED";
  timestamp: string;
  kernel_id: string;
}

export type CatalogLoadTrigger = "KERNEL_STARTUP" | "TIER1_UPDATE" | "TIER2_UPDATE";

/** §8.8(i): Tier 2 entry explicitly permits what a loaded Tier 1 entry forbids -> reject + ALE-NEW-02. */
export function detectTier2VsTier1Conflict(tier1: CedarPolicyResult, tier2: CedarPolicyResult, kernelId: string): CatalogConflictDetected | null {
  if (tier1.decision === "FORBID" && tier2.decision === "PERMIT") {
    return {
      conflicting_catalog_id: tier2.policy_id,
      conflicting_cedar_policy_id: tier2.policy_id,
      superior_catalog_id: tier1.policy_id,
      superior_cedar_policy_id: tier1.policy_id,
      conflict_type: "EXPLICIT_PERMIT_OVERRIDE",
      resolution: "ENTRY_REJECTED",
      timestamp: new Date().toISOString(),
      kernel_id: kernelId,
    };
  }
  return null;
}

/** §8.8(iii): two Tier 1 entries for the same jurisdiction with contradictory positions on the same action. */
export function detectTier1InternalConflict(a: CedarPolicyResult, b: CedarPolicyResult, kernelId: string): CatalogConflictDetected | null {
  if (a.decision !== b.decision) {
    return {
      conflicting_catalog_id: b.policy_id,
      conflicting_cedar_policy_id: b.policy_id,
      superior_catalog_id: a.policy_id,
      superior_cedar_policy_id: a.policy_id,
      conflict_type: "SCOPE_AMBIGUITY",
      resolution: "HEM_ESCALATION_TRIGGERED",
      timestamp: new Date().toISOString(),
      kernel_id: kernelId,
    };
  }
  return null;
}

// ---------------------------------------------------------------------------
// §8.9 — Four-phase catalog update propagation
// ---------------------------------------------------------------------------

/** §8.9.1 Phase 1: detection cadence MUST NOT exceed 24 hours (normative MUST, resolves the Step 10 SVL question in advance). */
export const AMENDMENT_DETECTION_MAX_INTERVAL_HOURS = 24;

export type InFlightSessionState = "NOT_YET_STARTED" | "IN_PROGRESS_NOT_EVALUATED" | "IN_PROGRESS_ALREADY_PERMIT" | "IN_PROGRESS_ALREADY_DENY";

/** §8.9.2 Table 3 — suspension behavior by session state at detection. */
export function suspensionBehaviorForSession(state: InFlightSessionState): { action: string; blocksNewSacr: boolean; ceeReturnsSuspended: boolean } {
  switch (state) {
    case "NOT_YET_STARTED":
      return { action: "New SACR citing affected catalog entry MUST NOT be issued", blocksNewSacr: true, ceeReturnsSuspended: false };
    case "IN_PROGRESS_NOT_EVALUATED":
      return { action: "Cedar evaluation returns SUSPENDED, agent receives GOVERNANCE_SUSPENDED, session remains open", blocksNewSacr: false, ceeReturnsSuspended: true };
    case "IN_PROGRESS_ALREADY_PERMIT":
      return { action: "Action may complete, no rollback — prior PERMIT protected by safe harbor", blocksNewSacr: false, ceeReturnsSuspended: false };
    case "IN_PROGRESS_ALREADY_DENY":
      return { action: "Unaffected — denial stands", blocksNewSacr: false, ceeReturnsSuspended: false };
  }
}

export type ResolutionBasis = "statute_clear" | "interpretive_ruling" | "internal_conflict_resolution" | "cross_statute_coordination";

/** §8.9.3 Table 4 — required re-endorsement authority by resolution_basis. */
export function requiredReendorsementAuthority(basis: ResolutionBasis): string {
  switch (basis) {
    case "statute_clear":
      return "Designated authority per LRI profile endorser table";
    case "interpretive_ruling":
      return "Same authority + updated resolution_instrument_id";
    case "internal_conflict_resolution":
      return "Elevated legal authority or equivalent";
    case "cross_statute_coordination":
      return "All co-endorsers must re-endorse";
  }
}

/** §8.9.4 Phase 4 — re-activation validation, steps (1)-(3). */
export function assertReactivationValid(
  updatedPublishedBy: string,
  endorsementAuthorityId: string,
  catalogVersion: CatalogVersion,
  suspendedEntryVersionId: string,
  newEndorsedAtMs: number,
  amendmentEnforcementDateMs: number,
): void {
  if (updatedPublishedBy !== endorsementAuthorityId) {
    throw new CapError("CATALOG_CONFLICT_REJECTED", "§8.9.4(1): published_by does not match endorsement.authority_id");
  }
  if (catalogVersion.supersedes !== suspendedEntryVersionId) {
    throw new CapError("CATALOG_CONFLICT_REJECTED", "§8.9.4(2): catalog_version.supersedes does not match the suspended entry's version_id");
  }
  if (newEndorsedAtMs <= amendmentEnforcementDateMs) {
    throw new CapError("CATALOG_CONFLICT_REJECTED", "§8.9.4(3): new endorsed_at is not posterior to the amendment's EnforcementDate");
  }
}

/** §8.9.4 — 30-day maximum suspension window; CONF-CAP-SUSPEND-01 forbids silent drop. */
export const MAX_SUSPENSION_WINDOW_DAYS = 30;

export function assertNoSilentSuspensionDrop(suspendedSinceMs: number, nowMs: number, operatorNotified: boolean, criticalAlertGenerated: boolean): { mustConvertToDeny: boolean } {
  const daysSuspended = (nowMs - suspendedSinceMs) / (1000 * 60 * 60 * 24);
  if (daysSuspended > MAX_SUSPENSION_WINDOW_DAYS) {
    if (!operatorNotified || !criticalAlertGenerated) {
      throw new CapError("CATALOG_CONFLICT_REJECTED", "CONF-CAP-SUSPEND-01: GEC MUST NOT silently drop GOVERNANCE_SUSPENDED sessions after 30 days — notify operator + CRITICAL Audit Alert required before converting to DENY");
    }
    return { mustConvertToDeny: true };
  }
  return { mustConvertToDeny: false };
}
