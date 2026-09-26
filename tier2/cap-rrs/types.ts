// SOOS Step 10 — CAP Regulation Record Specification (CAP-RRS)
// Built against draft-sato-soos-cap-rrs-02.
//
// SDB-CAPRRS-01: this -02 draft does NOT reproduce its own base schema.
// Sections 4 (Regulation Record Schema), 5 (Cedar Compilation Profile),
// 6 (Conflict Declaration Model), 7 (Certification Model), and 8 (CMR
// Protocol) are explicitly "carried forward from draft-sato-soos-cap-rrs-01
// without... change... not reproduced here to conserve space." -01 was not
// supplied. Section 12 (HEM Integration) is likewise carried forward from
// -01 §9 unchanged, titles only. This means the exact Regulation Record
// field list (agent_check object, resource_policy object, conflict_
// declarations array, certification object), the exact Cedar Compilation
// Profile mapping rules, the Conflict Declaration Model's conflict types,
// the Certification Model's publisher tiers, the CMR versioning/update
// protocol, and HEM Class 8/9 (Execution Options Package, Natural
// Breakpoint Declaration) are ALL UNVERIFIED against source text below.
//
// What IS fully specified in -02 and built here without caveat: the Law
// Reference Interface (§9), the Statute-Primacy Rule incl. catalog_version
// and both GAR event schemas (§10), and the Operational Requirements
// (§11) — this is the actual "NEW in -02" content the abstract describes.
//
// The RegulationRecord type below is a best-effort reconstruction from
// context clues only (the cmr:// URI pattern in §3.2's pseudocode, field
// names mentioned in passing, the -02 addenda to §4.1/§8.4) — NOT sourced
// from the authoritative -01 schema text. Treat it as a data-shape
// placeholder pending -01, not a conformance target.

export type Iso8601 = string;

// ---------------------------------------------------------------------------
// §9.2 — LRI Generic Schema (fully specified, built with confidence)
// ---------------------------------------------------------------------------

export type ResolutionBasis = "statute_clear" | "interpretive_ruling" | "internal_conflict_resolution" | "cross_statute_coordination";
export type CoEndorsementQuorum = "all" | "primary_only";

export interface Endorsement {
  authority_id: string; // URI
  endorsed_at: Iso8601;
  endorsement_scope: string;
  resolution_basis: ResolutionBasis;
  resolution_instrument_id?: string; // CONDITIONAL: required when resolution_basis is interpretive_ruling
  co_endorsement_required: boolean;
  co_endorsement_quorum?: CoEndorsementQuorum; // CONDITIONAL: required when co_endorsement_required
  co_endorsers?: string[]; // CONDITIONAL: required when co_endorsement_required
  endorsement_claim: string; // signed JWT
}

export interface AuthoritySource {
  lri_version: "1.0";
  profile: string; // LRI profile URI
  law_id: string;
  article_ref: string;
  version_identifier: string;
  retrieved_at: Iso8601;
  amendment_detection_endpoint: string;
  interpretation_endpoint: string | null; // REQUIRED (even if null) when resolution_basis MAY be interpretive_ruling
  endorsement: Endorsement;
}

// ---------------------------------------------------------------------------
// §9.7 — LRI Profile Registry (initial values)
// ---------------------------------------------------------------------------

export const LRI_PROFILE_REGISTRY: Record<string, { uri: string; system: string }> = {
  JP: { uri: "https://laws.e-gov.go.jp/lri/v1", system: "e-LAWS XML v3" },
  EU: { uri: "http://data.europa.eu/eli/lri/v1", system: "ELI" },
  US: { uri: "https://uscode.house.gov/lri/v1", system: "USLM" },
};

// ---------------------------------------------------------------------------
// §10.2 / §10.3 — GAR event schemas (fully specified)
// ---------------------------------------------------------------------------

export interface ResolutionBlock {
  type: "re_endorsement" | "human_override";
  resolved_at: Iso8601;
  resolved_by: string; // operator KIA or authority_id URI
  new_endorsed_at: Iso8601;
  rationale?: string; // REQUIRED for human_override
}

export interface CatalogVersionConflictEvent {
  event_type: "CATALOG_VERSION_CONFLICT";
  catalog_entry_id: string;
  authority_source_profile: string;
  authority_source_law_id: string;
  authority_source_article_ref: string;
  endorsed_at: Iso8601;
  conflicting_amendment_promulgation_date: Iso8601;
  conflict_delta_days: number;
  suspension_effective_at: Iso8601;
  hem_escalation_id: string;
  resolution: ResolutionBlock | null;
}

export interface SupersedingInterpretation {
  issuing_authority: string;
  instrument_type: "cabinet_order" | "ministerial_guidance" | "court_judgment" | "ietf_interpretation";
  instrument_id: string;
  effective_date: Iso8601;
  prior_interpretation_id: string;
}

export interface InterpretationSupersededEvent {
  event_type: "INTERPRETATION_SUPERSEDED";
  authority_source_law_id: string;
  authority_source_article_ref: string;
  endorsed_at: Iso8601;
  superseding_interpretation: SupersedingInterpretation;
  suspension_effective_at: Iso8601;
  hem_escalation_id: string;
  resolution: ResolutionBlock | null;
}

// ---------------------------------------------------------------------------
// §10.5 — catalog_version (fully specified)
// ---------------------------------------------------------------------------

export interface CatalogVersion {
  version_id: string;
  effective_date: Iso8601;
  supersedes: string | null;
  amendment_basis: string;
  published_by: string; // MUST match endorsement.authority_id
  published_at: Iso8601;
}

// ---------------------------------------------------------------------------
// Best-effort reconstruction — NOT sourced from -01. See SDB-CAPRRS-01.
// ---------------------------------------------------------------------------

export interface RegulationRecordStub {
  record_id: string; // inferred from cmr:// URI pattern in §3.2 pseudocode
  tier: "0A" | "0B" | "1" | "2" | "3";
  authority_source_uri: string; // REQUIRED per §11.4 (was OPTIONAL in -01)
  authority_source?: AuthoritySource; // REQUIRED for Tier 0/1/2 per §9.2; Tier 3 MAY omit
  catalog_version: CatalogVersion; // REQUIRED top-level per -02 addendum to §4.1
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

export type CapRrsErrorCode =
  | "LRI_REQUIREMENT_VIOLATION"
  | "INTERPRETATION_ENDPOINT_REQUIRED"
  | "CO_ENDORSEMENT_QUORUM_NOT_MET"
  | "CATALOG_VERSION_REJECTED"
  | "AUTHORITY_SOURCE_URI_MISMATCH"
  | "SUSPENSION_WINDOW_EXCEEDED_SILENT_DROP";

export class CapRrsError extends Error {
  constructor(
    public code: CapRrsErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "CapRrsError";
  }
}
