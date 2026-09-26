// SOOS ACD — Trust Hierarchy. draft-sato-soos-acd-01 §8.
//
// §8.1 is explicit that trust level "is not carried as an explicit
// field in the ACD Record" — resource providers DERIVE it by
// inspecting the referenced GEC Manifest and attestation endpoint.
// deriveTrustLevel() below is that derivation, run resource-provider-
// side (the same actor as validateAsResourceProvider() in gec-acd.ts).

import { GARLog, ALEType, type GAREntry } from '../deps/gar/gar-core.js';
import type {
  AcdRecord,
  AuditAccessGrant,
  AuditPrincipalCredential,
  AcdTrustLevel,
  GecManifestTrustFields,
  VeaCredential,
} from './types.js';

/**
 * §8.1 — three trust levels, evaluated highest-to-lowest. A deployment
 * must satisfy ALL of a level's stated conditions to claim it; falling
 * short of GOVERNMENT's or ELEVATED's conditions falls through to the
 * next level down rather than failing outright, since STANDARD is
 * explicitly "the default trust level for SOOS-governed agent
 * deployments" — there's no sub-STANDARD failure case in §8.1's text.
 */
export function deriveTrustLevel(manifest: GecManifestTrustFields): AcdTrustLevel {
  const isGovernment =
    manifest.conformance_level === 'L3' &&
    manifest.hardware_attestation_chain_to_deployment_authority &&
    !!manifest.publisher_key_scheme &&
    !!manifest.national_deployment_profile;
  if (isGovernment) return 'GOVERNMENT';

  const isElevated =
    manifest.conformance_level === 'L2' &&
    !!manifest.frost_threshold &&
    manifest.cap_enforcement_attestation_is_tee_backed;
  if (isElevated) return 'ELEVATED';

  return 'STANDARD'; // KEE-1 L1 or L2 conformance without the ELEVATED extras
}

/** Resource classes each trust level may be granted access to, per §8.1's prose (informative — not a formally enumerated list in the draft). */
export const RESOURCE_CLASS_ACCESS: Record<AcdTrustLevel, string[]> = {
  STANDARD: ['standard'],
  ELEVATED: ['standard', 'financial-data', 'personal-data-appi-gdpr'],
  GOVERNMENT: ['standard', 'financial-data', 'personal-data-appi-gdpr', 'government-apis', 'classified-infrastructure-data', 'fiea-regulated-infrastructure'],
};

export class AcdTrustHierarchy {
  constructor(private gar: GARLog) {}

  /** §8.2 — Audit Principal access to gar_audit_endpoint. Session-level scope only. */
  authenticateAuditPrincipal(
    record: AcdRecord,
    credential: AuditPrincipalCredential,
    verifyCredential: (cred: AuditPrincipalCredential) => boolean,
  ): AuditAccessGrant | null {
    const ok = verifyCredential(credential);
    this.emit(ALEType.ACD_HUMAN_QUERY, {
      acd_session_id: record.acd_session_id,
      principal_id: credential.principal_id,
      principal_kind: credential.principal_kind,
      credential_kind: 'AUDIT_PRINCIPAL',
      granted: ok,
    });
    if (!ok) return null;
    return {
      scope: 'SESSION_LEVEL',
      granted_at: new Date().toISOString(),
      includes_ptd_access: false,
      includes_cap_profile_hash_verification: false,
      includes_merkle_proof_access: false,
    };
  }

  /** §8.3 — VEA access. Full Audit Package scope, beyond standard Audit Principal. */
  authenticateVea(
    record: AcdRecord,
    credential: VeaCredential,
    verifyCredential: (cred: VeaCredential) => boolean,
  ): AuditAccessGrant | null {
    const ok = verifyCredential(credential);
    this.emit(ALEType.ACD_HUMAN_QUERY, {
      acd_session_id: record.acd_session_id,
      principal_id: credential.auditor_id,
      accrediting_authority: credential.accrediting_authority,
      credential_kind: 'VEA',
      granted: ok,
    });
    if (!ok) return null;
    return {
      scope: 'FULL_AUDIT_PACKAGE',
      granted_at: new Date().toISOString(),
      includes_ptd_access: true,
      includes_cap_profile_hash_verification: true,
      includes_merkle_proof_access: true,
    };
  }

  private emit(ale_type: ALEType, extra: Record<string, unknown>): GAREntry {
    return this.gar.append({
      ale_type,
      session_id: 'ACD',
      actor_id: 'AUDIT_PRINCIPAL',
      timestamp: new Date().toISOString(),
      causal_parent_id: null,
      ...extra,
    } as unknown as Omit<GAREntry, 'prev_span_hash' | 'own_span_hash'>);
  }
}
