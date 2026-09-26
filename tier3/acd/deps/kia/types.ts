// SOOS Step 6 — Kernel Identity and Attestation (KIA)
// Built against draft-sato-soos-kia-03 (normative) plus the proposed
// -04 GEC Manifest field additions (kernel_version_date, kernel_implementer_id),
// per Tom's July 8 decision to build ahead of -04 finalization.
//
// -04 IS NOT YET MERGED. The three open items in KIA-04-proposed-changes.md
// are unresolved:
//   1. kernel_implementer_id format (keypair fingerprint vs URI) — built here
//      supporting BOTH, per the proposal's stated dual-path design.
//   2. Whether kernel_implementer_id needs its own §15.x caveat — not decided;
//      this implementation does NOT add one, matching the proposal's default.
//   3. Section numbering (15.12) — irrelevant to implementation, doc-only.
// These are logged as SDB-KIA-04-01/02/03 below and in the demo output.
// If -04 lands differently, this module's manifest fields are the blast radius.

/** SHA-256 hex digest. */
export type Sha256Hex = string;

/** Ed25519 signature, base64. */
export type Ed25519SigB64 = string;

/** ISO-8601 UTC timestamp. */
export type Iso8601 = string;

/** ISO-8601 date only (YYYY-MM-DD), per -04 kernel_version_date. */
export type Iso8601Date = string;

// ---------------------------------------------------------------------------
// §4.1 — Trust chain / keypair model
// ---------------------------------------------------------------------------

export interface Ed25519KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** §4.1 FROST deployment_constraints[] marker: "frost:t-of-n:<t>-<n>" */
export interface FrostConfig {
  threshold: number; // t
  participants: number; // n
}

export function frostConstraintString(cfg: FrostConfig): string {
  return `frost:t-of-n:${cfg.threshold}-${cfg.participants}`;
}

// ---------------------------------------------------------------------------
// §5.2 — GEC Manifest schema
// Base fields carried forward from -02 (inferred from Appendix C.2's
// canonical field inventory + manifest_signature's field list in the -04
// proposal) + -03's xpid_derivation_version + proposed -04 fields.
// ---------------------------------------------------------------------------

export interface GecManifestFields {
  // -02 base fields
  kernel_keypair_fingerprint: Sha256Hex;
  operator_identity: Sha256Hex;
  deployment_timestamp: Iso8601;
  hardware_backed: boolean;
  ptd_endpoint: string;
  ptd_current_version: string;
  kernel_version: string;
  loaded_policy_ids: string[];
  cedar_policy_hash: Sha256Hex;
  attestation_timestamp: Iso8601;
  deployment_constraints: string[];

  // -03 addition (§5.2)
  xpid_derivation_version: "2.0" | "1.1" | "1.0" | "none"; // v2.0: operator_identity anchor; 1.1/1.0 retained for backward-compatible correlation

  // -04 PROPOSED additions (§5.2, not yet merged — CONF-KIA-24/25)
  kernel_version_date: Iso8601Date;
  kernel_implementer_id: string;
}

export interface GecManifest {
  fields: GecManifestFields;
  /** Ed25519 signature over canonical JSON of all fields above. */
  manifest_signature: Ed25519SigB64;
}

// ---------------------------------------------------------------------------
// §6 — XPID
// ---------------------------------------------------------------------------

export type Xpid = string; // UUID-v5 string

// ---------------------------------------------------------------------------
// §7 — Event Log signing (INV-9)
// ---------------------------------------------------------------------------

export interface EventLogEntry {
  event_id: string;
  event_type: string;
  so_id?: string;
  session_id?: string;
  xpid?: Xpid;
  occurred_at: Iso8601;
  payload: Record<string, unknown>;
}

export interface SignedEventLogEntry {
  entry: EventLogEntry;
  kernel_keypair_fingerprint: Sha256Hex;
  kernel_signature: Ed25519SigB64;
}

// ---------------------------------------------------------------------------
// §8 — Revocation Registry (INV-11)
// ---------------------------------------------------------------------------

export interface RevocationEntry {
  jti: string;
  revoked_at: Iso8601;
  revocation_scope: "THIS_MANDATE_ONLY" | "CASCADE_TO_DESCENDANTS";
  originating_kernel: Sha256Hex;
}

// ---------------------------------------------------------------------------
// §6.5 — CAEP revocation propagation event
// ---------------------------------------------------------------------------

export interface CaepMandateRevokedEvent {
  event_type: "mandate_revoked";
  subject: { format: "xpid"; xpid: Xpid };
  jti_revoked: string;
  revocation_scope: "THIS_MANDATE_ONLY" | "CASCADE_TO_DESCENDANTS";
  originating_kernel: Sha256Hex;
  revoked_at: Iso8601;
}

// ---------------------------------------------------------------------------
// Deny / alert codes used by this implementation
// ---------------------------------------------------------------------------

export type KiaDenyCode =
  | "KIA_QUORUM_FAILURE"
  | "KIA_XPID_VERIFICATION_FAILED"
  | "KIA_JTI_REVOKED"
  | "KIA_MANIFEST_STALE"
  | "KIA_MANIFEST_SIGNATURE_INVALID"
  | "KIA_CLIENT_SUPPLIED_XPID_REJECTED"
  | "KIA_NONCE_REUSE_DETECTED";

export class KiaError extends Error {
  constructor(
    public code: KiaDenyCode,
    message: string,
  ) {
    super(message);
    this.name = "KiaError";
  }
}
