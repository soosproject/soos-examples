// SOOS Step 9 — Constitutional AI Protocol (CAP)
// Built against draft-sato-soos-cap-04.
//
// Build note (not a gap): the plan flagged OQ-SC-02 (cedar-wasm vs native
// Rust Cedar via N-API) as unresolved. Rather than pull in the real
// @cedar-policy/cedar-wasm package while that choice is still open, this
// module implements Cedar's decision semantics directly (§8.7 "forbid
// wins") as a typed merge function, sufficient to demonstrate
// CONF-CAP-CONFLICT-01/02/03. Swapping in a real Cedar engine later is a
// drop-in replacement for evaluateCedarPolicySet() in cedar-semantics.ts.
//
// Also worth noting: the plan's Step 9 block said "CEE has four outputs."
// -04 §6.3 actually specifies ten CEE outputs plus a separate agent-facing
// error code (GOVERNANCE_SUSPENDED). All ten are implemented below.

export type Iso8601 = string;
export type Sha256Hex = string;

// ---------------------------------------------------------------------------
// §6.3 — CEE Outputs (all ten, not four as the plan's block abbreviated)
// ---------------------------------------------------------------------------

export type CeeOutput =
  | "PERMIT"
  | "CONSTITUTIONAL_VIOLATION"
  | "SUSPENDED"
  | "TIER_0B_PCR_ACTIVE"
  | "JURISDICTIONAL_CONFLICT"
  | "TIER_1_DENY"
  | "TIER_1_PCR_ACTIVE"
  | "LEGAL_AMBIGUITY_DETECTED"
  | "TIER_2_DENY"
  | "SESSION_SUSPEND";

/** Agent-facing error code returned when CEE output is SUSPENDED. */
export const GOVERNANCE_SUSPENDED_ERROR_CODE = "GOVERNANCE_SUSPENDED";

// ---------------------------------------------------------------------------
// §7 — Tier 0 prohibition classes
// ---------------------------------------------------------------------------

export type Tier0AClass = "CSAM" | "GENOCIDE_FACILITATION" | "MANIPULATION" | "PERFORMED_EMOTION" | "BIOMETRIC_SIGNAL_INFERENCE";
export type Tier0BClass = "HUMAN_TRAFFICKING" | "WMD_ASSISTANCE" | "TORTURE_FACILITATION" | "TERRORIST_FINANCING";

/** §11.2 — MUST NOT be cleared by any PCR under any circumstances. */
export const UNCLEARABLE_CLASSES: ReadonlySet<string> = new Set<Tier0AClass>([
  "CSAM",
  "GENOCIDE_FACILITATION",
  "MANIPULATION",
  "PERFORMED_EMOTION",
  "BIOMETRIC_SIGNAL_INFERENCE",
]);

export interface Tier0ProhibitionRecord {
  prohibition_id: string;
  tier_0_subclass: "TIER_0A" | "TIER_0B";
  prohibition_class: Tier0AClass | Tier0BClass;
  /** MUST be "EFFECT_BASED_TEST" + section ref for MANIPULATION/PERFORMED_EMOTION/BIOMETRIC_SIGNAL_INFERENCE. */
  treaty_basis: string;
  action_pattern: string;
  jurisdiction: "GLOBAL";
  effective_date: Iso8601;
  modifiable_by: "RFC_ONLY";
}

export interface Tier1ProhibitionRecord {
  prohibition_id: string;
  prohibition_class: string;
  jurisdiction: string; // ISO 3166-1 alpha-2
  action_pattern: string;
  ambiguity_flag: "CLEAR" | "AMBIGUOUS" | "DISPUTED";
  authority_ref: string;
  state: "ACTIVE" | "SUSPENDED";
  catalog_entry_id?: string;
}

export interface Tier2ProhibitionRecord {
  prohibition_id: string;
  prohibition_class: string;
  action_pattern: string;
  ambiguity_flag: "CLEAR" | "AMBIGUOUS" | "DISPUTED";
  operator_override: boolean;
  state: "ACTIVE" | "SUSPENDED";
}

// ---------------------------------------------------------------------------
// §11.6 — Prohibition Clearance Record
// ---------------------------------------------------------------------------

export interface ProhibitionClearanceRecord {
  pcr_id: string;
  prohibition_class: Tier0BClass | string; // Tier 0-B or Tier 1 class; MUST NOT be Tier 0-A
  tier: "TIER_0B" | "TIER_1";
  deployment_context: string;
  pcr_authority_type: "STATUTORY" | "REGULATORY" | "TREATY" | "COURT_ORDER" | "INSTITUTIONAL" | "PROFESSIONAL_REGULATORY";
  pcr_authority_ref: string;
  purpose_scope: string;
  so_type_scope: string[] | "ALL";
  effective_date: Iso8601;
  expiry_date: Iso8601; // REQUIRED — permanent clearances not permitted
  operator_signature: string;
  audit_principal_signature: string;
  regulatory_signature?: string; // REQUIRED for Mode 2, optional for Mode 1
  pcr_hash: Sha256Hex;
}

// ---------------------------------------------------------------------------
// §5.4 — MJWT consent_scope → Cedar context
// ---------------------------------------------------------------------------

export interface ConsentScope {
  purpose_codes: string[];
  data_categories: string[];
  jurisdiction: string;
  governing_law: string;
  expiry: Iso8601;
}

export interface CedarConsentContext {
  data_subject_consent?: true; // MUST be absent, not false, per §5.4 fail-closed rule
  consent_purpose_codes?: string[];
  consent_data_categories?: string[];
  consent_jurisdiction?: string;
  consent_governing_law?: string;
  consent_expiry?: Iso8601;
  consent_source?: "MJWT" | "HEM_RUNTIME" | "INHERITED_FROM_PARENT";
}

// ---------------------------------------------------------------------------
// §12.4, §13.4 — Violation / conflict records
// ---------------------------------------------------------------------------

export interface CapViolationRecord {
  violation_id: string;
  session_id: string;
  hem_id?: string;
  tier: "0A" | "0B" | "1" | "2";
  prohibition_id: string;
  violation_type: "AI_INITIATED" | "HUMAN_DIRECTED";
  action_attempted: string; // internal only — MUST NOT be returned to agent
  context_hash: Sha256Hex;
  outcome: "REFUSED" | "SESSION_SUSPENDED" | "HEM_FIRED";
  timestamp: Iso8601;
  kernel_signature: string;
}

export interface JurisdictionalConflictRecord {
  conflict_id: string;
  session_id: string;
  action: string;
  conflicting_jurisdictions: Array<{ jurisdiction: string; prohibition_id: string; outcome: "PERMIT" | "DENY" }>;
  resolution_method: "MOST_PROTECTIVE" | "PRIMARY_JURISDICTION" | "HEM";
  hem_id?: string;
  timestamp: Iso8601;
}

// ---------------------------------------------------------------------------
// §12a.2 — Policy Transparency Disclosure
// ---------------------------------------------------------------------------

export interface PtdActiveProhibitionEntry {
  record_id: string;
  prohibition_class: string;
  tier: "TIER_0A" | "TIER_0B" | "TIER_1" | "TIER_2" | "TIER_3";
  jurisdiction: string;
  authority_ref: string;
  effective_date: Iso8601;
  review_date: Iso8601;
  disclosure_level: "FULL" | "REDACTED" | "COUNT_ONLY";
}

export interface Ptd {
  ptd_version: string;
  gec_instance_id: string;
  cedar_policy_hash: Sha256Hex;
  generated_at: Iso8601;
  active_prohibitions: PtdActiveProhibitionEntry[];
  deployment_context: string;
  jurisdiction_config: Record<string, unknown>;
  ptd_signature: string;
}

// ---------------------------------------------------------------------------
// §8.9.3 — catalog_version
// ---------------------------------------------------------------------------

export interface CatalogVersion {
  version_id: string;
  effective_date: Iso8601;
  supersedes: string | null;
  amendment_basis: string;
  published_by: string;
  published_at: Iso8601;
}

// ---------------------------------------------------------------------------
// Error / deny codes
// ---------------------------------------------------------------------------

export type CapErrorCode =
  | "CONSTITUTIONAL_VIOLATION"
  | "GOVERNANCE_SUSPENDED"
  | "TIER_1_DENY"
  | "TIER_2_DENY"
  | "LEGAL_AMBIGUITY_DETECTED"
  | "PCR_REJECTED_UNCLEARABLE_CLASS"
  | "PCR_EXPIRED"
  | "CATALOG_CONFLICT_REJECTED"
  | "CONSENT_CONTEXT_OVERRIDE_REJECTED"
  | "APPROVE_WITH_LEGAL_BASIS_INVALID"
  | "TRANSPARENCY_VIOLATION"
  | "SESSION_CAP_SUSPENDED";

export class CapError extends Error {
  constructor(
    public code: CapErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "CapError";
  }
}
