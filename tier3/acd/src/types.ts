// SOOS — Agent Compliance Disclosure (ACD) Protocol
// Built against draft-sato-soos-acd-01.
//
// Scoped to what PEER (draft-sato-soos-peer-00) actually needs from ACD:
// the ACD Record schema (§6), the Presentation Protocol handshake (§7)
// including the four-check sequence (§7.4), and enough of the GAR
// integration (§10) to produce a real acd_session_id PEER's Gate 2 can
// carry into the PTR. NOT built: full ACD Trust Hierarchy (§8) operator
// credential chains, ACD-to-MJWT sub-agent binding depth-tracing (§9.3)
// beyond the single mjwt_jti field PEER needs. Flagged as scope.

export type Iso8601 = string;
export type Sha256Hex = string;

// ---------------------------------------------------------------------
// §6.1 — Layer 1: Legal Identity
// ---------------------------------------------------------------------

export interface JurisdictionEntry {
  jurisdiction_code: string; // ISO 3166-1 alpha-2
  regulatory_regime: string[];
  ptd_endpoint: string;
}

export interface AcdLayer1 {
  acd_session_id: string; // UUID v4, GEC-generated
  agent_xpid: string;
  governing_law: string;
  primary_jurisdiction: string;
  jurisdictions: JurisdictionEntry[];
  terms_of_use_uri: string;
  liability_scope: 'OPERATOR' | 'DEPLOYER' | 'PRINCIPAL_HIERARCHY';
  acd_validity_not_before: Iso8601;
  acd_validity_not_after: Iso8601; // max 30 days from not_before; default 24h
}

// ---------------------------------------------------------------------
// §6.2 — Layer 2: Constitutional Compliance
// ---------------------------------------------------------------------

export interface ProhibitionTierSummary {
  tier_0a: number;
  tier_0b: number;
  tier_1: number;
  tier_2: number;
}

export interface AcdLayer2 {
  cap_profile_id: string;
  cap_profile_hash: Sha256Hex;
  prohibition_tier_summary: ProhibitionTierSummary;
  gec_manifest_ref: string;
  cedar_policy_hash: Sha256Hex;
  cap_enforcement_attestation: string;
  hem_status: 'ACTIVE' | 'SUSPENDED' | 'ESCALATION_IN_PROGRESS';
  ptd_endpoint: string;
}

// ---------------------------------------------------------------------
// §6.3 — Layer 3: Principal and Redress (+ §9.1 mjwt_jti binding addition)
// ---------------------------------------------------------------------

export interface AcdLayer3 {
  operator_id: string;
  deployer_id?: string; // CONDITIONAL — required when deployer != operator
  principal_hierarchy_summary: string;
  redress_uri: string;
  human_escalation_path: 'AVAILABLE' | 'NOT_AVAILABLE';
  gar_audit_endpoint: string;
  gar_sar_ref?: string;
  acd_timestamp: Iso8601;
  delegation_chain_depth: number;
  parent_kernel_id: string | null; // REQUIRED (non-null) when delegation_chain_depth >= 1
  mandate_scope_type: 'FULL' | 'SLICE';
  mjwt_jti: string; // §9.1 binding requirement
}

export interface AcdRecordBody extends AcdLayer1, AcdLayer2, AcdLayer3 {}

export interface AcdRecord extends AcdRecordBody {
  gec_signature: string; // JWS detached signature over canonical body
}

// ---------------------------------------------------------------------
// §7.4 — Four-Check Sequence inputs (KEE-1 integration, reproduced here
// as the caller-supplied facts the sequence checks — the real manifest/
// revocation-registry lookups are KEE-1/KIA territory this session's
// dependency set for ACD alone doesn't carry).
// ---------------------------------------------------------------------

export interface FourCheckInputs {
  manifestCurrentAndUnrevoked: boolean; // Check 1
  cedarPolicyHashIsFresh: boolean; // Check 2 — computed at generation time, not precomputed/stale
  kiaSigningKeyRevoked: boolean; // Check 3 — true = FAIL
  agentXpidRevokedOrCaepSignaled: boolean; // Check 4 — true = FAIL
}

export type AcdFailedCheck = 1 | 2 | 3 | 4;

export class AcdError extends Error {
  constructor(
    public code: string,
    public failed_check: AcdFailedCheck | undefined,
    message: string,
  ) {
    super(message);
    this.name = 'AcdError';
  }
}

// ---------------------------------------------------------------------
// §8 — ACD Trust Hierarchy
// ---------------------------------------------------------------------

export type AcdTrustLevel = 'STANDARD' | 'ELEVATED' | 'GOVERNMENT';

export type ConformanceLevel = 'L1' | 'L2' | 'L3';

/**
 * The fields ACD-01 §8.1 reads off "the GEC Manifest" to derive a trust
 * level. KEE-1 (draft-sato-soos-kee-00) owns the actual Manifest schema
 * and wasn't in this session's dependency set — this is the subset of
 * fields §8.1's own text names, not a full KEE-1 Manifest reproduction.
 */
export interface GecManifestTrustFields {
  conformance_level: ConformanceLevel;
  frost_threshold?: string; // e.g. "frost:t-of-n:2-3"
  cap_enforcement_attestation_is_tee_backed: boolean;
  hardware_attestation_chain_to_deployment_authority: boolean;
  publisher_key_scheme?: string; // e.g. "2-of-3: Digital Agency + IPA + operator"
  national_deployment_profile?: string; // e.g. "Japan Deployment Profile"
}

/** §8.2 — Audit Principal credential. Issuance mechanism is explicitly operator-defined (out of scope); this models the authentication check the gar_audit_endpoint performs. */
export interface AuditPrincipalCredential {
  principal_id: string;
  principal_kind: 'RESOURCE_PROVIDER' | 'INTERNAL_AUDIT_TEAM' | 'REGULATOR';
  credential_token: string; // operator-defined format, opaque here
}

/** §8.3 — Verified External Auditor credential; full Audit Package scope. */
export interface VeaCredential {
  auditor_id: string;
  accrediting_authority: string; // operator or regulatory authority
  credential_token: string;
}

export type AuditAccessScope = 'SESSION_LEVEL' | 'FULL_AUDIT_PACKAGE';

export interface AuditAccessGrant {
  scope: AuditAccessScope;
  granted_at: Iso8601;
  includes_ptd_access: boolean;
  includes_cap_profile_hash_verification: boolean;
  includes_merkle_proof_access: boolean;
}
