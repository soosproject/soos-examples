// SOOS ACD — GEC-side compliance handshake.
// draft-sato-soos-acd-01 §7 (Presentation Protocol), §7.4 (Four-Check
// Sequence), §10 (GAR Integration).

import { randomUUID } from 'crypto';
import { GARLog, ALEType, type GAREntry } from '../deps/gar/gar-core.js';
import { sha256Hex, canonicalJson } from '../deps/kia/canon.js';
import { runFourCheckSequence, type FourCheckInputsV2 } from './four-check-v2.js';
import {
  AcdError,
  type AcdRecord,
  type AcdRecordBody,
  type FourCheckInputs,
} from './types.js';

export interface AcdQueryRequest {
  resource_provider_id: string;
  requested_at: string;
}

export interface AcdQueryResult {
  ok: boolean;
  record?: AcdRecord;
  record_hash?: string; // §10.1 ALE-057 data-minimization: only the hash goes to GAR
  error?: { error: 'ACD_CHECK_FAILED'; failed_check: number; acd_session_id: string; timestamp: string };
}

export class AcdGec {
  constructor(private gar: GARLog) {}

  /**
   * §7.2 steps 1-4. `bodyBuilder` supplies everything the four checks
   * pass but the ACD Record body itself needs (Layer 1/2/3 fields) —
   * kept as a caller-supplied function since those fields come from the
   * kernel's own state (CAP profile, MJWT, KIA), not from ACD itself.
   *
   * PRE-KEE-1 SIMPLIFIED VERSION — built before KEE-1 was available,
   * using boolean flags for each check rather than KEE-1 §4.3's actual
   * mechanics (real GecManifest freshness, FROST threshold-key path,
   * canonical-hash comparison). Kept for the existing demo/corpus
   * scenarios that don't need that precision; use handleQueryV2() for
   * anything that does, e.g. verifying FROST-signed (ELEVATED/GOVERNMENT
   * trust level) deployments correctly.
   */
  handleQuery(
    request: AcdQueryRequest,
    checks: FourCheckInputs,
    bodyBuilder: (acd_session_id: string) => Omit<AcdRecordBody, 'acd_session_id'>,
    signer: (canonicalBody: string) => string,
  ): AcdQueryResult {
    const acd_session_id = randomUUID();
    const timestamp = new Date().toISOString();

    // ALE-056 — MUST be logged before the four-check sequence begins.
    this.emit(ALEType.ACD_QUERY_RECEIVED, {
      acd_session_id,
      resource_provider_id: request.resource_provider_id,
      request_timestamp: request.requested_at,
    });

    // §7.4 — four checks, in order. First failure wins.
    const failedCheck = this.runFourChecks(checks);
    if (failedCheck) {
      this.emit(ALEType.ACD_VALIDATION_FAILED, {
        acd_session_id,
        failed_check: failedCheck,
        resource_provider_id: request.resource_provider_id,
        failure_timestamp: timestamp,
      });
      return {
        ok: false,
        error: { error: 'ACD_CHECK_FAILED', failed_check: failedCheck, acd_session_id, timestamp },
      };
    }

    const body: AcdRecordBody = { acd_session_id, ...bodyBuilder(acd_session_id) };
    const canonicalBody = canonicalJson(body);
    const gec_signature = signer(canonicalBody);
    const record: AcdRecord = { ...body, gec_signature };
    const record_hash = sha256Hex(canonicalJson(record));

    // ALE-057 — data minimization: only the hash is stored in GAR, never the full body (§10.3).
    this.emit(ALEType.ACD_RECORD_ISSUED, {
      acd_session_id,
      record_hash,
      acd_validity_not_after: body.acd_validity_not_after,
      mjwt_jti: body.mjwt_jti,
    });

    return { ok: true, record, record_hash };
  }

  /**
   * §7.4 rebuilt against KEE-1 §4.3 directly (the actual authoritative
   * source) rather than ACD-01's own partial restatement — see
   * four-check-v2.ts's header and svl/issue-log.md SDB-ACD-01/02/03.
   * Differences from handleQuery()/FourCheckInputs: Check 3 covers the
   * FROST threshold-key signing path (required for the ELEVATED/
   * GOVERNMENT trust levels this same draft defines in §8.1), Check 2
   * compares against a real freshly-computed hash rather than a boolean
   * flag, and Check 1 uses KIA's real assertManifestFresh() /
   * assertManifestSignatureValid() instead of a boolean flag.
   */
  handleQueryV2(
    request: AcdQueryRequest,
    checks: FourCheckInputsV2,
    bodyBuilder: (acd_session_id: string) => Omit<AcdRecordBody, 'acd_session_id'>,
    signer: (canonicalBody: string) => string,
  ): AcdQueryResult {
    const acd_session_id = randomUUID();
    const timestamp = new Date().toISOString();

    this.emit(ALEType.ACD_QUERY_RECEIVED, {
      acd_session_id,
      resource_provider_id: request.resource_provider_id,
      request_timestamp: request.requested_at,
    });

    const failure = runFourCheckSequence(checks);
    if (failure) {
      const extra: Record<string, unknown> = {
        acd_session_id,
        resource_provider_id: request.resource_provider_id,
        failed_check: failure.check,
        reason: failure.reason,
        failure_timestamp: timestamp,
      };
      if (failure.check === 3) {
        // KEE-1 §4.3 Check 3's exact logging requirement.
        extra.failed_layer = failure.failed_layer;
        extra.failed_field = failure.failed_field;
      }
      this.emit(ALEType.ACD_VALIDATION_FAILED, extra);
      return {
        ok: false,
        error: { error: 'ACD_CHECK_FAILED', failed_check: failure.check, acd_session_id, timestamp },
      };
    }

    const body: AcdRecordBody = { acd_session_id, ...bodyBuilder(acd_session_id) };
    const canonicalBody = canonicalJson(body);
    const gec_signature = signer(canonicalBody);
    const record: AcdRecord = { ...body, gec_signature };
    const record_hash = sha256Hex(canonicalJson(record));

    this.emit(ALEType.ACD_RECORD_ISSUED, {
      acd_session_id,
      record_hash,
      acd_validity_not_after: body.acd_validity_not_after,
      mjwt_jti: body.mjwt_jti,
    });

    return { ok: true, record, record_hash };
  }

  /** §7.3 — resource-provider-side validation, Steps 1-6. Modeled here for
   *  completeness even though PEER's Gate 2 only needs the acd_session_id
   *  on success — a real resource provider runs this independently. */
  validateAsResourceProvider(
    record: AcdRecord,
    verifySignature: (record: AcdRecord) => boolean,
    queriedXpid: string,
    providerJurisdiction: string,
  ): { ok: boolean; failedStep?: number; reason?: string } {
    // Step 1 — signature verification. ACD-01's denial_reason enum
    // (FOUR_CHECK_FAILED | LAYER_INSPECTION_FAILED | EXPIRED |
    // XPID_MISMATCH) has no dedicated value for a resource-provider-side
    // signature failure — LAYER_INSPECTION_FAILED is the closest fit,
    // used here rather than misusing FOUR_CHECK_FAILED (that value is
    // for GEC-side §7.4 failures, a different step of the protocol).
    if (!verifySignature(record)) {
      this.logDenied(record.acd_session_id, 'LAYER_INSPECTION_FAILED');
      return { ok: false, failedStep: 1, reason: 'gec_signature verification failed' };
    }
    // Step 2 — XPID consistency.
    if (record.agent_xpid !== queriedXpid) {
      this.logDenied(record.acd_session_id, 'XPID_MISMATCH');
      return { ok: false, failedStep: 2, reason: 'agent_xpid does not match queried kernel XPID' };
    }
    // Step 3 — validity window.
    const now = Date.now();
    if (now < Date.parse(record.acd_validity_not_before) || now > Date.parse(record.acd_validity_not_after)) {
      this.logDenied(record.acd_session_id, 'EXPIRED');
      return { ok: false, failedStep: 3, reason: 'current time outside acd_validity window' };
    }
    // Step 4 — Layer 1 content: jurisdiction coverage.
    if (!record.jurisdictions.some((j) => j.jurisdiction_code === providerJurisdiction)) {
      this.logDenied(record.acd_session_id, 'LAYER_INSPECTION_FAILED');
      return { ok: false, failedStep: 4, reason: `jurisdictions does not cover provider jurisdiction ${providerJurisdiction}` };
    }
    // Step 5 — Layer 2 content: left to the provider's own policy (informational pass-through here).
    // Step 6 — Layer 3 content: operator_id non-null.
    if (!record.operator_id) {
      this.logDenied(record.acd_session_id, 'LAYER_INSPECTION_FAILED');
      return { ok: false, failedStep: 6, reason: 'operator_id is null/empty' };
    }

    this.emit(ALEType.ACD_VALIDATION_PASSED, {
      acd_session_id: record.acd_session_id,
      validation_timestamp: new Date().toISOString(),
    });
    return { ok: true };
  }

  private logDenied(acd_session_id: string, denial_reason: 'FOUR_CHECK_FAILED' | 'LAYER_INSPECTION_FAILED' | 'EXPIRED' | 'XPID_MISMATCH'): void {
    this.emit(ALEType.ACD_ACCESS_DENIED, { acd_session_id, denial_reason, denial_timestamp: new Date().toISOString() });
  }

  private runFourChecks(checks: FourCheckInputs): 1 | 2 | 3 | 4 | null {
    if (!checks.manifestCurrentAndUnrevoked) return 1;
    if (!checks.cedarPolicyHashIsFresh) return 2;
    if (checks.kiaSigningKeyRevoked) return 3;
    if (checks.agentXpidRevokedOrCaepSignaled) return 4;
    return null;
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
