// SOOS Step 12 — AEP-to-OTel Mapping (draft-sato-soos-aep-02 §12).
//
// SVL Phase A key question (from the plan's Step 12 block) resolved by
// reading §12.2 directly: soos.aep.cp_hash is "SHA-256 of Context
// Package" — computed the same way KIA's canon.ts computes every other
// canonical-JSON hash in this codebase (sorted keys, no whitespace),
// reused here rather than reinvented. No ambiguity in the draft text.

import { canonicalJson, sha256Hex } from '../deps/kia/canon.js';
import type { ContextPackage } from './types.js';

export function computeCpHash(cp: ContextPackage): string {
  return sha256Hex(canonicalJson(cp));
}

function emitSpan(name: string, attrs: Record<string, unknown>): void {
  const line = Object.entries(attrs)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`)
    .join(' ');
  console.log(`[otel:${name}] ${line}`);
}

export function emitSenseSpan(attrs: {
  session_id: string;
  iteration: number;
  trigger: string;
  cp_hash: string;
  session_xpid: string;
  session_state: string;
  so_current_state: string;
}): void {
  emitSpan('soos.aep.sense', {
    'soos.aep.session_id': attrs.session_id,
    'soos.aep.iteration': attrs.iteration,
    'soos.aep.trigger': attrs.trigger,
    'soos.aep.cp_hash': attrs.cp_hash,
    'soos.aep.session_xpid': attrs.session_xpid,
    'soos.aep.session_state': attrs.session_state,
    'soos.aep.so_current_state': attrs.so_current_state,
  });
}

export function emitReasonSpan(attrs: { session_id: string; iteration: number; reasoning_mode?: string; reason_duration_ms?: number }): void {
  emitSpan('soos.aep.reason', {
    'soos.aep.session_id': attrs.session_id,
    'soos.aep.iteration': attrs.iteration,
    // SHOULD, omit for ROUTINE (§12.2)
    'soos.aep.reasoning_mode': attrs.reasoning_mode && attrs.reasoning_mode !== 'ROUTINE' ? attrs.reasoning_mode : undefined,
    'soos.aep.reason_duration_ms': attrs.reason_duration_ms,
  });
}

export function emitPlanSpan(attrs: {
  session_id: string;
  iteration: number;
  plan_queries: string[];
  path_confidence: number;
  intended_cedar_action: string;
}): void {
  emitSpan('soos.aep.plan', {
    'soos.aep.session_id': attrs.session_id,
    'soos.aep.iteration': attrs.iteration,
    'soos.aep.plan_queries': attrs.plan_queries,
    'soos.aep.path_confidence': attrs.path_confidence,
    'soos.aep.intended_cedar_action': attrs.intended_cedar_action,
  });
}

export function emitActSpan(attrs: {
  session_id: string;
  iteration: number;
  idp_id: string;
  cedar_action: string;
  confidence: number;
  cp_hash_ref: string;
  plan_b_ref?: string;
}): void {
  emitSpan('soos.aep.act', {
    'soos.aep.session_id': attrs.session_id,
    'soos.aep.iteration': attrs.iteration,
    'soos.aep.idp_id': attrs.idp_id,
    'soos.aep.cedar_action': attrs.cedar_action,
    'soos.aep.confidence': attrs.confidence,
    'soos.aep.cp_hash_ref': attrs.cp_hash_ref,
    'soos.aep.plan_b_ref': attrs.plan_b_ref,
  });
}

export function emitObserveSpan(attrs: {
  session_id: string;
  iteration: number;
  observe_result: 'PERMIT' | 'DENY' | 'HEM_PENDING' | 'STALLED';
  deny_code?: string;
  prior_denial_count?: number;
  event_stream_entry_id?: string;
  cap_evaluation_result?: string;
  cedar_evaluation_result?: string;
}): void {
  // OTel-CONF-04: DENY/HEM_PENDING spans MUST NOT be suppressed — this
  // function has no branch that skips emission for any observe_result.
  emitSpan('soos.aep.observe', {
    'soos.aep.session_id': attrs.session_id,
    'soos.aep.iteration': attrs.iteration,
    'soos.aep.observe_result': attrs.observe_result,
    'soos.aep.deny_code': attrs.deny_code,
    'soos.aep.prior_denial_count': attrs.prior_denial_count,
    'soos.aep.event_stream_entry_id': attrs.event_stream_entry_id,
    'soos.aep.cap_evaluation_result': attrs.cap_evaluation_result,
    'soos.aep.cedar_evaluation_result': attrs.cedar_evaluation_result,
  });
}

/** OTel-CONF-02 — cp_hash (SENSE) and cp_hash_ref (ACT) of the same iteration MUST match. */
export function assertCpHashBinding(cpHashFromSense: string, cpHashRefFromAct: string): void {
  if (cpHashFromSense !== cpHashRefFromAct) {
    throw new Error(
      `OTel-CONF-02 violation: ACT cp_hash_ref (${cpHashRefFromAct}) does not match the prior SENSE span's cp_hash (${cpHashFromSense}) — ACT submitted without a valid prior SENSE delivery`,
    );
  }
}
