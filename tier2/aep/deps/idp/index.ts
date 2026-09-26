// Step 5 — IDP (Intent Declaration Primitive)
// Implements draft-sato-soos-idp-05.
//
// SDB-IDP-01 [logged this session]: §7.2's prose defines the
// CONFIDENCE_MISCALIBRATION_WARNING ratio as
// "high_conf_count : deny_hem_count" but the JSON schema comment right
// below it defines `ratio: deny_hem_count / high_conf_count` — the
// inverse. Built against the JSON schema comment (deny_hem_count /
// high_conf_count), matching the prose's own plain-language framing
// (">40% of high-confidence declarations resulted in DENY"). TODO:
// SDB-IDP-01 — confirm with Tom which direction is authoritative.
//
// SVL Phase A resolved: "within any window of 10 or more IDPs" (§7.2)
// is NOT a fixed sliding-10 window. Read literally, evaluation begins
// once >=10 IDPs have accumulated and then re-checks on every
// subsequent IDP over the *whole* accumulated set — cumulative-since-
// threshold, not a fixed-size window that drops old entries as new
// ones arrive. Implemented that way below.

import { randomUUID } from 'crypto';
import {
  resolveSOType,
  resolveSOTypeIdForSOInstance,
  SPO_URI_REGISTRY,
  type MandateBinding,
} from './stubs.js';

// =====================================================================
// IntentDeclaration schema (IDP-05 §4.1) — ~60L
// =====================================================================

export type ReasoningBasisType =
  | 'RULE_BASED'
  | 'INFERENCE'
  | 'INSTRUCTION'
  | 'UNCERTAINTY_REDUCTION'
  | 'MISSION_STAGE'
  | 'RETRY_CONTINUATION';

export type ReasoningMode =
  | 'ROUTINE'
  | 'PREDICTIVE'
  | 'DIAGNOSTIC'
  | 'CHANNEL_DEGRADED'
  | 'META'
  | 'COMPENSATING'
  | 'DELEGATION_AWARE'
  | 'HEM_INFORMED';

export type HemUrgency = 'NONE' | 'RECOMMENDED' | 'REQUIRED';

export interface DeclaredGoal {
  goal_id: string; // UUID v4
  description: string; // max 500 chars
}

export interface ReasoningBasis {
  type: ReasoningBasisType;
  description: string; // max 1000 chars
}

export interface DataResidency {
  jurisdiction: string;
  tier2_eligible: boolean;
  tier3_eligible: boolean;
  retention_days: number;
  anonymization_delay_days: number;
}

export interface IntentDeclaration {
  idp_id: string; // REQUIRED. UUID v4.
  session_id: string; // REQUIRED.
  so_id: string; // REQUIRED. UUID v4.
  mandate_id: string; // REQUIRED. Mandate JWT jti.
  mandate_reference?: string; // OPTIONAL. SPO URI. [NEW in -05]
  mission_ref?: string; // OPTIONAL.
  endorsed_eod_id?: string; // OPTIONAL/REQUIRED per Class. [NEW in -05]
  eod_id?: string; // OPTIONAL.
  plan_b_ref?: string; // OPTIONAL/REQUIRED when PLAN_B_ACTIVE.
  step_sequence: number; // REQUIRED. 1-based, monotonic.
  requested_action: string; // REQUIRED. Cedar action string.
  declared_goal: DeclaredGoal; // REQUIRED.
  reasoning_basis: ReasoningBasis; // REQUIRED.
  confidence_level: number; // REQUIRED. [0.0, 1.0].
  hem_urgency: HemUrgency; // REQUIRED.
  context_refs?: string[]; // OPTIONAL.
  audit_accessible?: boolean; // OPTIONAL. Default true.
  metadata?: Record<string, unknown>; // OPTIONAL.
  timestamp: string; // REQUIRED. ISO 8601 UTC.
  gec_instance_id?: string; // RECOMMENDED (L2/L3 REQUIRED).
  data_residency?: DataResidency; // OPTIONAL.
  reasoning_mode?: ReasoningMode; // OPTIONAL. ROUTINE when absent.
}

// =====================================================================
// Deny codes (IDP-05 §13 registry, as referenced through §5.2/§4.2/§4.6.3)
// =====================================================================

export enum IDPDenyCode {
  IDP_MISSING = 'IDP_MISSING',
  IDP_MALFORMED = 'IDP_MALFORMED',
  IDP_DUPLICATE = 'IDP_DUPLICATE',
  IDP_SO_MISMATCH = 'IDP_SO_MISMATCH',
  IDP_MANDATE_MISMATCH = 'IDP_MANDATE_MISMATCH',
  IDP_ENDORSED_EOD_REQUIRED = 'IDP_ENDORSED_EOD_REQUIRED',
  IDP_ENDORSED_EOD_INVALID = 'IDP_ENDORSED_EOD_INVALID',
  IDP_PLAN_B_REF_REQUIRED = 'IDP_PLAN_B_REF_REQUIRED',
  IDP_SPO_EXPIRED = 'IDP_SPO_EXPIRED',
  IDP_ACTION_OUTSIDE_SPO = 'IDP_ACTION_OUTSIDE_SPO',
  IDP_SPO_TYPE_MISMATCH = 'IDP_SPO_TYPE_MISMATCH',
  RETRY_WHAT_CHANGED_INVALID = 'RETRY_WHAT_CHANGED_INVALID', // AEP-02 layer, referenced here
}

export interface ValidationResult {
  ok: boolean;
  deny_code?: IDPDenyCode;
  detail?: string;
  warnings?: string[]; // e.g. RETRY_WHAT_CHANGED_WEAK, RETRY_WITHOUT_PRIOR_REF, EOD_ABSENT
  cedarContext?: Record<string, unknown>; // §5.4 Cedar context attributes, PERMIT path only
}

function fail(deny_code: IDPDenyCode, detail: string): ValidationResult {
  return { ok: false, deny_code, detail };
}

// =====================================================================
// Endorsed EOD / intake_endorsement operation (IDP-05 §4.6) — ~80L
// =====================================================================

export interface EOD {
  eod_id: string;
  derived?: boolean; // true for PD-EOD
  primary_outcome: { target_state: string };
  plan_b?: { plan_b_id: string; plan_b_target_state: string };
  mandate_reference?: string;
}

export interface IntakeEndorsementRequest {
  eod: EOD;
  mandate_jwt_jti: string; // stand-in for the full mandate_jwt string
  so_id: string; // SO Instance this session targets
  so_type_id: string;
  principal_credential: string; // opaque; recognized-or-not per Party Registry stub
  requested_at: string;
  request_id: string; // UUID v4, idempotency key
}

export interface EndorsedEOD {
  endorsed_eod_id: string; // UUID v4
  eod_id: string;
  eod_hash: string; // stub SHA-256 stand-in
  mandate_jwt_id: string;
  so_id_bound: string;
  primary_outcome_validated: boolean;
  plan_b_validated: boolean;
  scope_status: 'IN_SCOPE' | 'OUT_OF_SCOPE' | 'PARTIAL_SCOPE';
  scope_detail?: string;
  endorsed_at: string;
  gec_signature: string; // stub signature
  revoked: boolean;
}

export enum IntakeErrorCode {
  INTAKE_PRINCIPAL_UNRECOGNIZED = 'INTAKE_PRINCIPAL_UNRECOGNIZED',
  INTAKE_EOD_MALFORMED = 'INTAKE_EOD_MALFORMED',
  INTAKE_MANDATE_INVALID = 'INTAKE_MANDATE_INVALID',
  INTAKE_PRIMARY_OUTCOME_INVALID = 'INTAKE_PRIMARY_OUTCOME_INVALID',
  INTAKE_PLAN_B_INVALID = 'INTAKE_PLAN_B_INVALID',
  INTAKE_SPO_EXPIRED = 'INTAKE_SPO_EXPIRED',
  INTAKE_DUPLICATE = 'INTAKE_DUPLICATE',
}

export interface IntakeResult {
  ok: boolean;
  endorsed_eod?: EndorsedEOD;
  error_code?: IntakeErrorCode;
  detail?: string;
}

function stubHash(obj: unknown): string {
  // Not real SHA-256 — deterministic stand-in for demo purposes only.
  return `sha256-stub:${JSON.stringify(obj).length}:${Math.abs(
    JSON.stringify(obj).split('').reduce((a, c) => a + c.charCodeAt(0), 0)
  )}`;
}

function stubSign(obj: unknown): string {
  return `ed25519-stub-sig:${stubHash(obj)}`;
}

// =====================================================================
// GEC-side IDP engine
// =====================================================================

export interface EventLogEntry {
  event_id: string;
  event_type: string;
  occurred_at: string;
  payload: Record<string, unknown>;
}

interface SessionTracker {
  last_step_sequence: number;
  denial_counts: Map<string, number>; // requested_action -> count
}

interface CalibrationWindow {
  idp_count: number;
  high_conf_count: number;
  deny_hem_count: number;
  warning_active: boolean;
}

export class IDPGovernanceEngineComponent {
  private eventLog: EventLogEntry[] = [];
  private endorsedEODs: Map<string, EndorsedEOD> = new Map();
  private idpIds: Set<string> = new Set();
  private sessions: Map<string, SessionTracker> = new Map();
  private calibration: Map<string, CalibrationWindow> = new Map(); // key: agent_id or session_id
  private readonly miscalibrationThreshold: number;

  constructor(opts?: { miscalibrationThreshold?: number }) {
    this.miscalibrationThreshold = opts?.miscalibrationThreshold ?? 0.4; // §7.2 default
  }

  private commit(event_type: string, payload: Record<string, unknown>): EventLogEntry {
    const entry: EventLogEntry = {
      event_id: randomUUID(),
      event_type,
      occurred_at: new Date().toISOString(),
      payload,
    };
    this.eventLog.push(entry);
    return entry;
  }

  getEventLog(): EventLogEntry[] {
    return [...this.eventLog];
  }

  // -------------------------------------------------------------------
  // intake_endorsement() operation (IDP-05 §4.6) — ~80L total incl. types above
  // -------------------------------------------------------------------
  intakeEndorsement(req: IntakeEndorsementRequest): IntakeResult {
    // Idempotency (INTAKE_DUPLICATE)
    const existing = [...this.endorsedEODs.values()].find(
      (e) => e.eod_id === req.eod.eod_id && e.mandate_jwt_id === req.mandate_jwt_jti
    );
    if (existing) {
      return { ok: true, endorsed_eod: existing };
    }

    // Principal credential recognition — stub: any non-empty string
    // starting with "kia:" is "recognized" by the Party Registry stub.
    if (!req.principal_credential.startsWith('kia:')) {
      return {
        ok: false,
        error_code: IntakeErrorCode.INTAKE_PRINCIPAL_UNRECOGNIZED,
        detail: 'principal_credential not recognized by Party Registry stub',
      };
    }

    if (!req.eod.primary_outcome?.target_state) {
      return { ok: false, error_code: IntakeErrorCode.INTAKE_EOD_MALFORMED, detail: 'primary_outcome.target_state missing' };
    }

    const soType = resolveSOType(req.so_type_id);
    if (!soType) {
      return { ok: false, error_code: IntakeErrorCode.INTAKE_EOD_MALFORMED, detail: `unknown so_type_id ${req.so_type_id}` };
    }

    // SPO expiry check, when mandate_reference present on the EOD.
    if (req.eod.mandate_reference) {
      const spo = SPO_URI_REGISTRY[req.eod.mandate_reference];
      if (spo?.expires_at && new Date(spo.expires_at) < new Date()) {
        return { ok: false, error_code: IntakeErrorCode.INTAKE_SPO_EXPIRED, detail: 'mandate_reference SPO URI expired' };
      }
    }

    const primary_outcome_validated = soType.states.includes(req.eod.primary_outcome.target_state);
    if (!primary_outcome_validated) {
      return {
        ok: false,
        error_code: IntakeErrorCode.INTAKE_PRIMARY_OUTCOME_INVALID,
        detail: `target_state '${req.eod.primary_outcome.target_state}' not in ${req.so_type_id} state machine`,
      };
    }

    let plan_b_validated = true;
    if (req.eod.plan_b) {
      plan_b_validated = soType.states.includes(req.eod.plan_b.plan_b_target_state);
      if (!plan_b_validated) {
        return {
          ok: false,
          error_code: IntakeErrorCode.INTAKE_PLAN_B_INVALID,
          detail: `plan_b_target_state '${req.eod.plan_b.plan_b_target_state}' not in ${req.so_type_id} state machine`,
        };
      }
    }

    const scope_status: EndorsedEOD['scope_status'] = 'IN_SCOPE'; // both validations passed above

    const endorsed: EndorsedEOD = {
      endorsed_eod_id: randomUUID(),
      eod_id: req.eod.eod_id,
      eod_hash: stubHash(req.eod),
      mandate_jwt_id: req.mandate_jwt_jti,
      so_id_bound: req.so_id,
      primary_outcome_validated,
      plan_b_validated,
      scope_status,
      endorsed_at: new Date().toISOString(),
      gec_signature: '',
      revoked: false,
    };
    endorsed.gec_signature = stubSign({ ...endorsed, gec_signature: undefined });

    this.endorsedEODs.set(endorsed.endorsed_eod_id, endorsed);
    this.commit('ENDORSED_EOD', {
      endorsed_eod_id: endorsed.endorsed_eod_id,
      eod_hash: endorsed.eod_hash,
      mandate_jwt_id: endorsed.mandate_jwt_id,
      so_id_bound: endorsed.so_id_bound,
      gec_signature: endorsed.gec_signature,
    });

    return { ok: true, endorsed_eod: endorsed };
  }

  // -------------------------------------------------------------------
  // PD-EOD scope-bounding derivation (IDP-05 §4.7) — ~70L
  // -------------------------------------------------------------------
  derivePDEOD(params: {
    source_prompt: string;
    so_type_id: string;
    implied_target_state: string; // what the prompt appears to ask for
    derivation_model: string;
    derivation_confidence: number;
  }): EOD & {
    derived: true;
    source_prompt: string;
    derivation_model: string;
    derivation_confidence: number;
    derivation_warnings: string[];
  } {
    const soType = resolveSOType(params.so_type_id);
    const derivation_warnings: string[] = [];

    if (params.source_prompt.length > 2000) {
      throw new Error('PD-EOD rejected: source_prompt exceeds 2000 chars (IDP-05 §4.7.1)');
    }

    let target_state = params.implied_target_state;
    let scope_status: EndorsedEOD['scope_status'] = 'IN_SCOPE';

    if (!soType || !soType.states.includes(params.implied_target_state)) {
      // §4.7.2: MUST NOT silently clip to nearest in-scope state. The
      // PD-EOD MUST come back OUT_OF_SCOPE, not quietly constrained.
      scope_status = 'OUT_OF_SCOPE';
      derivation_warnings.push(
        `prompt implies target_state '${params.implied_target_state}', which is outside the ` +
          `${params.so_type_id} state machine (§4.7.2 scope-bounding rule) — GEC did NOT silently ` +
          `clip; returning OUT_OF_SCOPE for human review`
      );
      // Deliberately leave target_state as the (invalid) implied value —
      // the caller must not treat this EOD as usable; scope_status is
      // the authoritative signal, not target_state's validity.
    }

    const pdEod = {
      eod_id: randomUUID(),
      derived: true as const,
      primary_outcome: { target_state },
      mandate_reference: undefined,
      source_prompt: params.source_prompt,
      derivation_model: params.derivation_model,
      derivation_confidence: params.derivation_confidence,
      derivation_warnings,
    };

    this.commit('PD_EOD_DERIVED', {
      eod_id: pdEod.eod_id,
      so_type_id: params.so_type_id,
      scope_status,
      derivation_warnings,
    });

    return pdEod;
  }

  // -------------------------------------------------------------------
  // submitIDP() — §5.2 validation (a)-(l), §5.3 Event Log commitment
  // -------------------------------------------------------------------
  submitIDP(idp: IntentDeclaration, binding: MandateBinding, sessionState: { plan_b_active: boolean }): ValidationResult {
    const warnings: string[] = [];

    // (b) malformed check — minimal shape check, not full schema validation
    if (!idp.idp_id || !idp.session_id || !idp.so_id || !idp.mandate_id || !idp.requested_action) {
      return fail(IDPDenyCode.IDP_MALFORMED, 'one or more REQUIRED fields missing');
    }

    // (c) idp_id uniqueness
    if (this.idpIds.has(idp.idp_id)) {
      return fail(IDPDenyCode.IDP_DUPLICATE, `idp_id ${idp.idp_id} already committed`);
    }

    // (d) SO Instance binding
    if (idp.so_id !== binding.so_id) {
      return fail(IDPDenyCode.IDP_SO_MISMATCH, 'so_id does not match the governed object bound to mandate_jwt');
    }

    // (e) Mandate binding
    if (idp.mandate_id !== binding.mandate_id) {
      return fail(IDPDenyCode.IDP_MANDATE_MISMATCH, 'mandate_id does not match the jti claim of the presented mandate_jwt');
    }

    // (f) step_sequence monotonicity
    const tracker = this.sessions.get(idp.session_id) ?? { last_step_sequence: 0, denial_counts: new Map() };
    if (idp.step_sequence <= tracker.last_step_sequence) {
      return fail(IDPDenyCode.IDP_MALFORMED, `step_sequence ${idp.step_sequence} not greater than last committed ${tracker.last_step_sequence}`);
    }

    // (h) mandate_reference SPO structural validation
    if (idp.mandate_reference) {
      const spo = SPO_URI_REGISTRY[idp.mandate_reference];
      if (!spo) {
        return fail(IDPDenyCode.IDP_SPO_EXPIRED, `mandate_reference '${idp.mandate_reference}' does not resolve`);
      }
      if (spo.expires_at && new Date(spo.expires_at) < new Date()) {
        return fail(IDPDenyCode.IDP_SPO_EXPIRED, 'mandate_reference SPO URI resolves to an expired document');
      }
      const soType = resolveSOType(spo.so_type_id);
      if (!soType || !soType.action_space.includes(idp.requested_action)) {
        return fail(IDPDenyCode.IDP_ACTION_OUTSIDE_SPO, `${idp.requested_action} not within SPO action space`);
      }
      if (spo.so_type_id !== resolveSOTypeIdForSOInstance(idp.so_id)) {
        return fail(IDPDenyCode.IDP_SPO_TYPE_MISMATCH, 'mandate_reference SPO does not define this so_id SO Type');
      }
    }

    // (i) endorsed_eod_id validation
    let has_endorsed_eod = false;
    let eod_scope_status: EndorsedEOD['scope_status'] | undefined;
    if (idp.endorsed_eod_id) {
      const eod = this.endorsedEODs.get(idp.endorsed_eod_id);
      if (!eod || eod.revoked || eod.so_id_bound !== idp.so_id || eod.mandate_jwt_id !== idp.mandate_id) {
        return fail(IDPDenyCode.IDP_ENDORSED_EOD_INVALID, 'endorsed_eod_id does not match a valid ENDORSED_EOD entry');
      }
      has_endorsed_eod = true;
      eod_scope_status = eod.scope_status;
    } else if (binding.agent_class === 'CLASS_3') {
      return fail(IDPDenyCode.IDP_ENDORSED_EOD_REQUIRED, 'Class 3 agent submitted IDP without endorsed_eod_id');
    } else if (binding.agent_class === 'CLASS_2') {
      warnings.push('EOD_ABSENT');
    }

    // (j) PLAN_B_ACTIVE requires plan_b_ref
    if (sessionState.plan_b_active && !idp.plan_b_ref) {
      return fail(IDPDenyCode.IDP_PLAN_B_REF_REQUIRED, 'session_state PLAN_B_ACTIVE requires plan_b_ref');
    }

    // (k)/(l) RETRY_CONTINUATION — see validateRetryContinuation() below
    if (idp.reasoning_basis.type === 'RETRY_CONTINUATION') {
      const retryResult = this.validateRetryContinuation(idp);
      warnings.push(...(retryResult.warnings ?? []));
    }

    // All validation passed — commit IDP_SUBMITTED (§5.3), before Cedar evaluation
    tracker.last_step_sequence = idp.step_sequence;
    this.sessions.set(idp.session_id, tracker);
    this.idpIds.add(idp.idp_id);

    const prior_denial_count = tracker.denial_counts.get(idp.requested_action) ?? 0;

    this.commit('IDP_SUBMITTED', {
      idp,
      receipt_timestamp: new Date().toISOString(),
      mandate_id: idp.mandate_id,
      session_id: idp.session_id,
      audit_accessible: idp.audit_accessible ?? true,
      prior_denial_count,
      endorsed_eod_id: idp.endorsed_eod_id,
    });

    // Cedar context attributes (§5.4) — surfaced for the caller's Cedar
    // evaluation step, which is out of scope for Tier 1 sample code, but
    // the values themselves (has_endorsed_eod, eod_scope_status) are
    // exactly what a real Cedar policy would gate on.
    this.updateCalibration(idp, /*outcome resolved after Cedar eval, see recordOutcome()*/ undefined);

    return {
      ok: true,
      warnings: warnings.length ? warnings : undefined,
      cedarContext: {
        'idp.reasoning_basis.type': idp.reasoning_basis.type,
        'idp.confidence_level': idp.confidence_level,
        'idp.hem_urgency': idp.hem_urgency,
        'idp.reasoning_mode': idp.reasoning_mode ?? 'ROUTINE',
        'idp.prior_denial_count': prior_denial_count,
        'idp.has_endorsed_eod': has_endorsed_eod,
        'idp.eod_scope_status': eod_scope_status,
        'idp.plan_b_active': sessionState.plan_b_active,
        'idp.mandate_reference_valid': idp.mandate_reference ? true : undefined,
        'idp.miscalibration_score': this.calibration.get(idp.session_id)?.warning_active ? 1 : 0,
      },
    };
  }

  // -------------------------------------------------------------------
  // RETRY_CONTINUATION what_changed validator (§4.3, §5.2(k)/(l)) — ~50L
  // -------------------------------------------------------------------
  private validateRetryContinuation(idp: IntentDeclaration): { warnings: string[] } {
    const warnings: string[] = [];
    const desc = idp.reasoning_basis.description;

    // (l) context_refs must reference a prior IDP for the same action
    const hasPriorRef = (idp.context_refs ?? []).length > 0;
    if (!hasPriorRef) {
      warnings.push('RETRY_WITHOUT_PRIOR_REF');
    }

    // (k) description must reference a specific enrichment field name or
    // an observable Context Package change — heuristic: description must
    // mention "enrichment." followed by a field-like token, matching the
    // what_changed_guidance format generated in buildEnrichedDenyResponse().
    const referencesEnrichmentField = /enrichment\.[a-zA-Z_]+/.test(desc);
    if (!referencesEnrichmentField) {
      warnings.push('RETRY_WHAT_CHANGED_WEAK'); // §4.3 — WHAT_CHANGED_ABSENT declaration
    }

    return { warnings };
  }

  // -------------------------------------------------------------------
  // Outcome recording (§5.6) + Enriched DENY Response (§6) construction
  // -------------------------------------------------------------------
  recordDeny(
    idp: IntentDeclaration,
    deny_code: string,
    deny_reason: string,
    enrichment: Record<string, unknown>,
    available_actions: string[]
  ) {
    const tracker = this.sessions.get(idp.session_id)!;
    const count = (tracker.denial_counts.get(idp.requested_action) ?? 0) + 1;
    tracker.denial_counts.set(idp.requested_action, count);

    this.commit('CEDAR_DENY_RECORDED', {
      idp_id: idp.idp_id,
      deny_code,
      deny_reason,
      denied_at: new Date().toISOString(),
      prior_denial_count: count,
    });
    this.commit('ACTION_RESULT_RECORDED', {
      idp_id: idp.idp_id,
      result: 'DENY',
      result_detail: deny_reason,
      recorded_at: new Date().toISOString(),
    });

    this.updateCalibration(idp, 'DENY');

    const what_changed_guidance = this.buildWhatChangedGuidance(enrichment);

    return {
      deny_code,
      deny_reason,
      idp_echo: idp,
      available_actions,
      enrichment,
      prior_denial_count: count,
      last_deny_code: deny_code,
      what_changed_guidance,
    };
  }

  recordPermit(idp: IntentDeclaration, from_state: string, to_state: string) {
    this.commit('STATE_TRANSITIONED', {
      idp_id: idp.idp_id,
      from_state,
      to_state,
      cedar_action: idp.requested_action,
      transition_at: new Date().toISOString(),
    });
    this.commit('ACTION_RESULT_RECORDED', {
      idp_id: idp.idp_id,
      result: 'PERMIT',
      result_detail: `${from_state} -> ${to_state}`,
      recorded_at: new Date().toISOString(),
    });
    this.updateCalibration(idp, 'PERMIT');
  }

  recordHemPending(idp: IntentDeclaration, reason: string) {
    this.commit('ACTION_RESULT_RECORDED', {
      idp_id: idp.idp_id,
      result: 'HEM_PENDING',
      result_detail: reason,
      recorded_at: new Date().toISOString(),
    });
    this.updateCalibration(idp, 'HEM_PENDING');
  }

  private buildWhatChangedGuidance(enrichment: Record<string, unknown>): string {
    const fields = Object.keys(enrichment);
    if (fields.length === 0) {
      return 'The next retry must reference at least one enrichment field by name.';
    }
    const parts = fields.map((f) => `enrichment.${f}: ${JSON.stringify(enrichment[f])}`);
    return `The next retry must change reasoning_basis.description to reference ${parts.join(', or ')}.`;
  }

  // -------------------------------------------------------------------
  // CONFIDENCE_MISCALIBRATION_WARNING tracker (§7.2) — ~50L
  // Window key: session_id (cross-session analytics not implemented in
  // Tier 1 — agent_id-keyed cross-session tracking is a documented
  // extension point, not built here).
  // -------------------------------------------------------------------
  private updateCalibration(idp: IntentDeclaration, outcome: 'PERMIT' | 'DENY' | 'HEM_PENDING' | undefined) {
    const key = idp.session_id;
    const w = this.calibration.get(key) ?? {
      idp_count: 0,
      high_conf_count: 0,
      deny_hem_count: 0,
      warning_active: false,
    };

    // Only count once per IDP lifecycle — call with outcome=undefined at
    // submission time to register idp_count/high_conf_count, then again
    // with the resolved outcome to register deny_hem_count.
    if (outcome === undefined) {
      w.idp_count += 1;
      if (idp.confidence_level >= 0.8) w.high_conf_count += 1;
    } else if (outcome === 'DENY' || outcome === 'HEM_PENDING') {
      if (idp.confidence_level >= 0.8) w.deny_hem_count += 1;
    }

    if (w.idp_count >= 10 && w.high_conf_count > 0) {
      const ratio = w.deny_hem_count / w.high_conf_count; // SDB-IDP-01: schema-comment direction
      if (ratio > this.miscalibrationThreshold && !w.warning_active) {
        w.warning_active = true;
        this.commit('CONFIDENCE_MISCALIBRATION_WARNING', {
          agent_id: idp.mandate_id, // stand-in for agent_id — mandate_id ties 1:1 to agent for this demo
          session_id: idp.session_id,
          window_size: w.idp_count,
          high_conf_count: w.high_conf_count,
          deny_hem_count: w.deny_hem_count,
          ratio,
          threshold: this.miscalibrationThreshold,
        });
      } else if (ratio <= this.miscalibrationThreshold) {
        w.warning_active = false; // window clears
      }
    }

    this.calibration.set(key, w);
  }

  isMiscalibrationActive(session_id: string): boolean {
    return this.calibration.get(session_id)?.warning_active ?? false;
  }
}
