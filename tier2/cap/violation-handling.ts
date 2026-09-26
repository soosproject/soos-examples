import { CapError, type CapViolationRecord } from "./types.js";

/** §12.1 — AI-initiated violation handling. */
export function handleAiInitiatedViolation(record: Omit<CapViolationRecord, "violation_type" | "outcome">): CapViolationRecord {
  return { ...record, violation_type: "AI_INITIATED", outcome: "REFUSED" };
}

/** §12.2 — human-directed violation. Principal's decision slot is NOT consumed; they may resubmit. */
export function handleHumanDirectedViolation(record: Omit<CapViolationRecord, "violation_type" | "outcome">): { record: CapViolationRecord; decisionSlotConsumed: false } {
  return { record: { ...record, violation_type: "HUMAN_DIRECTED", outcome: "REFUSED" }, decisionSlotConsumed: false };
}

/** §12.1(4): the error returned to the caller MUST NOT include the full action_pattern (prevents pattern probing). */
export function buildCallerFacingError(violationType: "AI_INITIATED" | "HUMAN_DIRECTED", prohibitionClass: string): { violation_type: string; prohibition_class: string } {
  return { violation_type: violationType, prohibition_class: prohibitionClass }; // deliberately excludes action_pattern
}

// ---------------------------------------------------------------------------
// §12.3 — APPROVE_WITH_LEGAL_BASIS
// ---------------------------------------------------------------------------

export interface LegalBasisBlock {
  authority_type: "COURT_ORDER" | "STATUTORY" | "REGULATORY" | "TREATY" | "PCR";
  authority_ref: string;
  pcr_id?: string; // REQUIRED when authority_type is "PCR"
  jurisdiction: string;
  expiry: string;
  document_hash: string | null;
}

/** §12.3(1): APPROVE_WITH_LEGAL_BASIS MUST NOT be accepted for Tier 0-A violations under any circumstances. */
export function assertApproveWithLegalBasisValid(matchedTier: "0A" | "0B" | "1" | "2", legalBasis: LegalBasisBlock): void {
  if (matchedTier === "0A") {
    throw new CapError("APPROVE_WITH_LEGAL_BASIS_INVALID", "§12.3(1): APPROVE_WITH_LEGAL_BASIS MUST NOT be accepted for Tier 0-A violations under any circumstances");
  }
  if (legalBasis.authority_type === "PCR" && !legalBasis.pcr_id) {
    throw new CapError("APPROVE_WITH_LEGAL_BASIS_INVALID", "§12.3: pcr_id is REQUIRED when authority_type is PCR");
  }
}

// ---------------------------------------------------------------------------
// §12.5 — Session Suspension
// ---------------------------------------------------------------------------

export const DEFAULT_SESSION_SUSPENSION_THRESHOLD = 3; // Tier 0 violations within a single session

export function checkSessionSuspension(tier0ViolationCountThisSession: number, threshold: number = DEFAULT_SESSION_SUSPENSION_THRESHOLD): { suspend: boolean } {
  return { suspend: tier0ViolationCountThisSession >= threshold };
}
