// SOOS Step 7 — Human Escalation Mechanism (HEM)
// Built against draft-sato-soos-hem-05. -05's NEW material (interaction
// classes §7, HRS §8, Tier 0-A interface §9, INV-HEM-01 §10, security
// defenses §18.10-18.14) is implemented in full. Base HEM mechanics carried
// forward from -04 without modification (session states §4, decision types
// §12.1-12.6, timeout model §14, base Escalation Request §11) are
// implemented at the level of detail visible in -05's carry-forward
// references and Appendix C.2 — -04's full text was not supplied, so those
// areas are lighter-weight than the -05-native material.

export type Iso8601 = string;
export type Sha256Hex = string;

// ---------------------------------------------------------------------------
// §4 — HEM Session States
// ---------------------------------------------------------------------------

export type HemSessionState =
  | "HEM_INACTIVE"
  | "HEM_PENDING"
  | "HEM_RESOLVED"
  | "HEM_TIMEOUT"
  | "HEM_CHAIN_EXHAUSTED";

/** §4.2 — normative state transitions. */
export const HEM_STATE_TRANSITIONS: Record<HemSessionState, HemSessionState[]> = {
  HEM_INACTIVE: ["HEM_PENDING"],
  HEM_PENDING: ["HEM_RESOLVED", "HEM_TIMEOUT", "HEM_CHAIN_EXHAUSTED"],
  HEM_RESOLVED: ["HEM_INACTIVE"],
  HEM_TIMEOUT: ["HEM_CHAIN_EXHAUSTED", "HEM_INACTIVE"],
  HEM_CHAIN_EXHAUSTED: [], // terminal
};

// ---------------------------------------------------------------------------
// §12 — Human Decision Types
//
// SDB-HEM-02: the canonical decision-type list (TOC §12.1-12.6, and
// Appendix C.2's "Decision types" summary) enumerates six: APPROVE,
// APPROVE_WITH_CONSTRAINTS, REDIRECT, TERMINATE, DEFER,
// APPROVE_WITH_PAYMENT. But §7.2.1 (HEM-PRE-1) and §7.2.2 (HEM-PRE-2) both
// normatively list "DENY" as an available decision type for those specific
// interaction classes, and CONF-HEM-HIGH1-02 references DENY-adjacent
// rejection semantics. DENY is never defined in §12 and never added to the
// Appendix C.2 summary. This build treats DENY as a real seventh decision
// type, scoped to the interaction classes that name it (HEM-PRE-1,
// HEM-PRE-2), rather than silently mapping it onto TERMINATE or REDIRECT —
// neither of which matches DENY's stated semantics ("action MUST NOT
// execute", no session termination, no redirect target). PENDING Tom's
// confirmation this is the right call.
// ---------------------------------------------------------------------------

export type HumanDecisionType =
  | "APPROVE"
  | "APPROVE_WITH_CONSTRAINTS"
  | "REDIRECT"
  | "TERMINATE"
  | "DEFER"
  | "APPROVE_WITH_PAYMENT"
  | "DENY"; // SDB-HEM-02 — see note above

/** Which interaction classes DENY is valid for, per §7.2.1 / §7.2.2 text. */
export const DENY_VALID_FOR: ReadonlySet<string> = new Set(["HEM-PRE-1", "HEM-PRE-2"]);

// ---------------------------------------------------------------------------
// §7 — Interaction classes
// ---------------------------------------------------------------------------

export type HemInteractionClass =
  | "HEM-PRE-1"
  | "HEM-PRE-2"
  | "HEM-DS-1"
  | "HEM-DS-2"
  | "HEM-LIM-1"
  | "HEM-DIV-1"
  | "HEM-HIGH-1"
  | "HEM-FAT-1"
  | "HEM-EMO-1"
  | "HEM-CONSENT";

export type HemTriggerClass =
  | "HEM_CEDAR_ROUTED"
  | "HEM_AGENT_ESCALATED"
  | "HEM_PROXIMITY_TRIGGERED"
  | "HEM_MISSION_VALIDITY_FAILED"
  | "HEM_JURISDICTIONAL_CONFLICT"
  | "HEM_TIER0_OBSERVED"
  | "HEM_TIER1_OBSERVED"
  | "HEM_TIER3_ANTICIPATORY"
  | "HEM_TIER3_OBSERVED"
  | "HEM_BUDGET_EXHAUSTED"
  | "HEM_HIGH_STAKES_MANDATORY_REVIEW"; // §7.5.1 — emitted under standard HEM_TRIGGERED, not a Section-5 class

// ---------------------------------------------------------------------------
// §7.4.1 HEM-LIM-1 — limitation_declaration
// ---------------------------------------------------------------------------

export type LimitationType =
  | "CONFIDENCE_BELOW_FLOOR"
  | "OUT_OF_DISTRIBUTION"
  | "EXPLICIT_AGENT_DECLARATION"
  | "COMPETENCE_BOUNDARY";

export interface LimitationDeclaration {
  limitation_type: LimitationType;
  limitation_description: string;
  idp_confidence_level: number;
  competence_floor: number;
  recommended_action?: string;
}

// ---------------------------------------------------------------------------
// §7.4.2 HEM-DIV-1 — deliberation_record
// ---------------------------------------------------------------------------

export type DivergenceType =
  | "ACTION_MISMATCH"
  | "PLAN_B_ACTIVE"
  | "OUT_OF_SCOPE_ACTION"
  | "IDP_COMMITMENT_GAP";

export interface OptionConsidered {
  action_id: string;
  considered: boolean;
  selected: boolean;
  rejection_reason?: string;
}

export interface DeliberationRecord {
  declared_action: string;
  attempted_action: string;
  divergence_type: DivergenceType;
  divergence_reason?: string;
  option_set_considered: OptionConsidered[];
  prior_idp_chain: string[];
}

// ---------------------------------------------------------------------------
// §7.3.1 HEM-DS-1 — options_presentation
// ---------------------------------------------------------------------------

export interface HemOption {
  option_id: string;
  option_label: string;
  option_description: string;
  decision_type: HumanDecisionType;
  consequence_summary: string;
  reversible: boolean;
  gec_recommended: boolean;
}

export interface OptionsPresentation {
  options: HemOption[]; // 2-5 per §7.3.1
  neutrality_certificate: string;
}

// ---------------------------------------------------------------------------
// §7.6.2 HEM-CONSENT — consent_escalation
// ---------------------------------------------------------------------------

export interface ConsentEscalation {
  consent_requirement: string; // e.g. "APPI_ART17", "GDPR_ART6"
  purpose_codes_required: string[];
  purpose_codes_present: string[];
  consent_expiry?: Iso8601;
  data_categories: string[];
}

// ---------------------------------------------------------------------------
// §11 — HEM Escalation Request (base fields per -04, plus -05 additions)
// ---------------------------------------------------------------------------

export interface HemEscalationRequest {
  hem_id: string;
  session_id: string;
  so_id?: string;
  mandate_id?: string;
  trigger_class?: HemTriggerClass;
  urgency?: "CRITICAL" | "HIGH" | "NORMAL";
  trigger_detail?: Record<string, unknown>;
  initiated_at: Iso8601;

  // -05 additions (§11)
  interaction_class?: HemInteractionClass;
  limitation_declaration?: LimitationDeclaration;
  deliberation_record?: DeliberationRecord;
  consent_escalation?: ConsentEscalation;
  options_presentation?: OptionsPresentation;
  hrs_at_escalation?: number;

  // §9.2(c) — concurrent Tier 0-A surfacing (INV-HEM-01(b))
  manipulation_detected?: boolean;
}

export type HemDenyCode =
  | "HEM_DECISION_INVALID"
  | "HEM_DRR_REQUIRED"
  | "HEM_TIMEOUT_DENY"
  | "HEM_SUPPRESSION_DETECTED"
  | "HEM_FATIGUE_BLOCKED"
  | "HEM_DELIBERATION_CHAIN_MISMATCH"
  | "HEM_WEIGHT_CONFIG_ERROR";

export class HemError extends Error {
  constructor(
    public code: HemDenyCode,
    message: string,
  ) {
    super(message);
    this.name = "HemError";
  }
}
