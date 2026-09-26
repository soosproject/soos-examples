import {
  type CeeOutput,
  type Tier0ProhibitionRecord,
  type Tier1ProhibitionRecord,
  type Tier2ProhibitionRecord,
  type ProhibitionClearanceRecord,
} from "./types.js";

export interface CeeEvaluationInput {
  actionPattern: string;
  jurisdictions: string[];
  tier0Records: Tier0ProhibitionRecord[];
  tier1Records: Tier1ProhibitionRecord[];
  tier2Records: Tier2ProhibitionRecord[];
  activePcrs: ProhibitionClearanceRecord[];
  conflictResolution: "MOST_PROTECTIVE" | "PRIMARY_JURISDICTION" | "HEM";
  primaryJurisdiction?: string;
  nowMs: number;
}

export interface CeeResult {
  output: CeeOutput;
  matchedRecordId?: string;
  matchedTier?: "0A" | "0B" | "1" | "2";
  activePcrId?: string;
  suspensionReason?: "CATALOG_VERSION_CONFLICT" | "INTERPRETATION_SUPERSEDED";
}

function findActivePcr(pcrs: ProhibitionClearanceRecord[], prohibitionClass: string, nowMs: number): ProhibitionClearanceRecord | undefined {
  return pcrs.find((p) => p.prohibition_class === prohibitionClass && Date.parse(p.expiry_date) > nowMs);
}

function actionMatches(pattern: string, action: string): boolean {
  return pattern === action || pattern === "*";
}

/** §6.2 — the CEE MUST execute this exact six-step sequence, in order, for every evaluation. */
export function evaluateCee(input: CeeEvaluationInput): CeeResult {
  // Step 1: Tier 0-A — unconditional, no PCR, no authority can override.
  const tier0a = input.tier0Records.find((r) => r.tier_0_subclass === "TIER_0A" && actionMatches(r.action_pattern, input.actionPattern));
  if (tier0a) {
    return { output: "CONSTITUTIONAL_VIOLATION", matchedRecordId: tier0a.prohibition_id, matchedTier: "0A" };
  }

  // Step 2: Tier 0-B — clearable via active PCR.
  const tier0b = input.tier0Records.find((r) => r.tier_0_subclass === "TIER_0B" && actionMatches(r.action_pattern, input.actionPattern));
  if (tier0b) {
    const pcr = findActivePcr(input.activePcrs, tier0b.prohibition_class, input.nowMs);
    if (!pcr) return { output: "CONSTITUTIONAL_VIOLATION", matchedRecordId: tier0b.prohibition_id, matchedTier: "0B" };
    return { output: "TIER_0B_PCR_ACTIVE", matchedRecordId: tier0b.prohibition_id, matchedTier: "0B", activePcrId: pcr.pcr_id };
  }

  // Step 3: SUSPENDED check — applicable Tier 1/2 records in SUSPENDED state block evaluation entirely.
  const suspendedTier1 = input.tier1Records.find((r) => r.state === "SUSPENDED" && actionMatches(r.action_pattern, input.actionPattern) && input.jurisdictions.includes(r.jurisdiction));
  const suspendedTier2 = input.tier2Records.find((r) => r.state === "SUSPENDED" && actionMatches(r.action_pattern, input.actionPattern));
  if (suspendedTier1 || suspendedTier2) {
    return { output: "SUSPENDED", matchedRecordId: (suspendedTier1 ?? suspendedTier2)!.prohibition_id, matchedTier: suspendedTier1 ? "1" : "2", suspensionReason: "CATALOG_VERSION_CONFLICT" };
  }

  // Step 4: Tier 1 — jurisdictional.
  const matchingTier1 = input.tier1Records.filter((r) => r.state === "ACTIVE" && actionMatches(r.action_pattern, input.actionPattern) && input.jurisdictions.includes(r.jurisdiction));
  if (matchingTier1.length > 0) {
    const ambiguous = matchingTier1.find((r) => r.ambiguity_flag === "AMBIGUOUS" || r.ambiguity_flag === "DISPUTED");
    if (ambiguous) return { output: "LEGAL_AMBIGUITY_DETECTED", matchedRecordId: ambiguous.prohibition_id, matchedTier: "1" };

    // Check PCR coverage first (any matching record with active PCR clears).
    for (const r of matchingTier1) {
      const pcr = findActivePcr(input.activePcrs, r.prohibition_class, input.nowMs);
      if (pcr) return { output: "TIER_1_PCR_ACTIVE", matchedRecordId: r.prohibition_id, matchedTier: "1", activePcrId: pcr.pcr_id };
    }

    if (matchingTier1.length > 1 || input.jurisdictions.length > 1) {
      // multi-jurisdiction conflict path
      if (input.conflictResolution === "HEM") {
        return { output: "JURISDICTIONAL_CONFLICT", matchedRecordId: matchingTier1[0]!.prohibition_id, matchedTier: "1" };
      }
      if (input.conflictResolution === "PRIMARY_JURISDICTION") {
        const primaryMatch = matchingTier1.find((r) => r.jurisdiction === input.primaryJurisdiction);
        if (!primaryMatch) return { output: "PERMIT" }; // primary jurisdiction doesn't prohibit; secondary conflict logged elsewhere
        return { output: "TIER_1_DENY", matchedRecordId: primaryMatch.prohibition_id, matchedTier: "1" };
      }
      // MOST_PROTECTIVE — any prohibiting jurisdiction denies
      return { output: "TIER_1_DENY", matchedRecordId: matchingTier1[0]!.prohibition_id, matchedTier: "1" };
    }

    return { output: "TIER_1_DENY", matchedRecordId: matchingTier1[0]!.prohibition_id, matchedTier: "1" };
  }

  // Step 5: Tier 2 — operator ethics.
  const matchingTier2 = input.tier2Records.filter((r) => r.state === "ACTIVE" && actionMatches(r.action_pattern, input.actionPattern));
  if (matchingTier2.length > 0) {
    const ambiguous = matchingTier2.find((r) => r.ambiguity_flag === "AMBIGUOUS" || r.ambiguity_flag === "DISPUTED");
    if (ambiguous) return { output: "LEGAL_AMBIGUITY_DETECTED", matchedRecordId: ambiguous.prohibition_id, matchedTier: "2" };
    const nonOverridden = matchingTier2.find((r) => !r.operator_override);
    if (nonOverridden) return { output: "TIER_2_DENY", matchedRecordId: nonOverridden.prohibition_id, matchedTier: "2" };
  }

  // Step 6: no match at any tier.
  return { output: "PERMIT" };
}
