// SOOS ACD — Four-Check Sequence, rebuilt against draft-sato-soos-kee-01
// §4.3 (P3 — ACD Four-Check Sequence), the actual authoritative source
// ACD-01 §7.4 cites but only partially restates. See svl/issue-log.md
// SDB-ACD-01/02/03 for the three points of drift this rebuild fixes,
// and a fourth finding (an internal ACD-01 self-inconsistency) that
// this rebuild resolves by following the MORE complete of ACD-01's own
// two conflicting ALE-059 field lists (§10, not §14.2 — see the log).
//
// Uses KIA's REAL GecManifest/assertManifestFresh (deps/kia/manifest.ts)
// and the REAL frostConstraintString() marker format (deps/kia/types.ts)
// — not the inferred GecManifestTrustFields subset ACD's Trust Hierarchy
// module used before this draft became available.

import { GARLog, ALEType, type GAREntry } from '../deps/gar/gar-core.js';
import { assertManifestFresh, assertManifestSignatureValid } from '../deps/kia/manifest.js';
import { KiaError, type GecManifest } from '../deps/kia/types.js';

export interface FourCheckInputsV2 {
  manifest: GecManifest;
  kernelPublicKey: Uint8Array;
  manifestRevoked: boolean; // Check 1 — Revocation Registry membership for this Manifest
  activeCedarPolicyHash: string; // Check 2 — SHA-256 of the CURRENT active Cedar Policy Set, computed by the caller over canonical serialization (KEE-1 §4.3 Check 2's exact requirement)
  claimedCedarPolicyHash: string; // the hash the caller is about to put in the ACD Record — Check 2 fails if these don't match
  kiaSigningKeyRevoked: boolean; // Check 3 (non-FROST path)
  frostThresholdKeyRevoked: boolean; // Check 3 (FROST path) — KEE-1's "(or FROST threshold key)" alternative, dropped from ACD-01's own restatement
  agentXpidRevokedOrCaepSignaled: boolean; // Check 4
}

export type FourCheckFailure =
  | { check: 1; reason: 'manifest_stale' | 'manifest_revoked' | 'manifest_signature_invalid' }
  | { check: 2; reason: 'cedar_policy_hash_stale' }
  | { check: 3; reason: 'kia_signing_key_revoked' | 'frost_threshold_key_revoked'; failed_layer: 3; failed_field: 'gec_signature' } // KEE-1 §4.3 Check 3's exact logging requirement
  | { check: 4; reason: 'xpid_revoked_or_caep_signaled' };

/** §4.3 — checks run IN ORDER; first failure wins (KEE-1: "The checks MUST be performed in the order listed"). */
export function runFourCheckSequence(input: FourCheckInputsV2, nowMs: number = Date.now()): FourCheckFailure | null {
  // Check 1 — Manifest Validity.
  try {
    assertManifestFresh(input.manifest, nowMs);
  } catch (e) {
    if (e instanceof KiaError) return { check: 1, reason: 'manifest_stale' };
    throw e;
  }
  if (input.manifestRevoked) return { check: 1, reason: 'manifest_revoked' };
  try {
    assertManifestSignatureValid(input.manifest, input.kernelPublicKey);
  } catch {
    return { check: 1, reason: 'manifest_signature_invalid' };
  }

  // Check 2 — Policy Currency. KEE-1: "computed over the canonical
  // serialization of the active Cedar Policy Set immediately before
  // signing" — enforced here as an equality check against a hash the
  // caller is required to have freshly computed, not a precomputed one.
  if (input.claimedCedarPolicyHash !== input.activeCedarPolicyHash) {
    return { check: 2, reason: 'cedar_policy_hash_stale' };
  }

  // Check 3 — KIA Attestation. Either signing path can fail this check.
  const usesFrost = input.manifest.fields.deployment_constraints.some((c) => c.startsWith('frost:t-of-n:'));
  if (usesFrost) {
    if (input.frostThresholdKeyRevoked) {
      return { check: 3, reason: 'frost_threshold_key_revoked', failed_layer: 3, failed_field: 'gec_signature' };
    }
  } else if (input.kiaSigningKeyRevoked) {
    return { check: 3, reason: 'kia_signing_key_revoked', failed_layer: 3, failed_field: 'gec_signature' };
  }

  // Check 4 — Revocation Status.
  if (input.agentXpidRevokedOrCaepSignaled) {
    return { check: 4, reason: 'xpid_revoked_or_caep_signaled' };
  }

  return null;
}

export class AcdFourCheckLogger {
  constructor(private gar: GARLog) {}

  logFailure(acd_session_id: string, resource_provider_id: string, failure: FourCheckFailure): void {
    const extra: Record<string, unknown> = {
      acd_session_id,
      resource_provider_id,
      failed_check: failure.check,
      reason: failure.reason,
      failure_timestamp: new Date().toISOString(),
    };
    if (failure.check === 3) {
      // KEE-1 §4.3 Check 3's specific requirement: "MUST log ALE-059
      // with failed_layer: 3, failed_field: 'gec_signature'" — ACD-01's
      // own §14.2 IANA registration table omits failed_check entirely
      // for this trigger (SDB-ACD-01); both field sets are emitted here
      // since §10's fuller definition is the one that's actually usable.
      extra.failed_layer = failure.failed_layer;
      extra.failed_field = failure.failed_field;
    }
    this.emit(ALEType.ACD_VALIDATION_FAILED, extra);
  }

  private emit(ale_type: ALEType, extra: Record<string, unknown>): GAREntry {
    return this.gar.append({
      ale_type,
      session_id: 'ACD',
      actor_id: 'GEC',
      timestamp: new Date().toISOString(),
      causal_parent_id: null,
      ...extra,
    } as unknown as Omit<GAREntry, 'prev_span_hash' | 'own_span_hash'>);
  }
}
