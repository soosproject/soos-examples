// SOOS Step 12 — AEP (Agentic Execution Protocol)
// Built against draft-sato-soos-aep-02.
//
// Integrates REAL modules from Steps 1 (GAR), 2 (SOV), 3 (MJWT),
// 5 (IDP), 6 (KIA), 7 (HEM), 9 (CAP) — not stubs. See src/gec-aep.ts
// for the orchestration. This file holds AEP's own schema: the pieces
// no earlier step already defines.
//
// Design note (not a gap): IDP's index.ts already has a lightweight
// `EOD`/`EndorsedEOD` pair (§4.6, built for AOP's intake_endorsement
// flow) with primary_outcome/plan_b at the SAME shape AEP-02 §6.2
// needs for GEC-side state-machine validation. AEP-02's own EOD (below)
// is the richer top-level session artifact — acceptance_envelope,
// submitter_mjwt_id, eod_signature, auto_activate_plan_b — that IDP's
// EOD doesn't carry. This module reuses IDPGovernanceEngineComponent's
// real intakeEndorsement() for the state-machine-validity half of EOD
// commit (§6.3(a)) rather than re-implementing that check, and adds the
// AEP-02-specific fields/lifecycle around it.

export type Uuid = string;
export type Iso8601 = string;

// ---------------------------------------------------------------------
// §6.2 — EOD Schema
// ---------------------------------------------------------------------

export interface SuccessCondition {
  condition_id: string;
  field: string;
  operator: 'eq' | 'neq' | 'gt' | 'gte' | 'lt' | 'lte' | 'in' | 'not_in';
  value: unknown;
  required: boolean;
}

export interface AcceptanceEnvelope {
  success_conditions: SuccessCondition[];
  partial_success?: SuccessCondition[];
  failure_conditions: SuccessCondition[];
}

export interface PlanB {
  plan_b_id: string;
  plan_b_target_state: string;
  plan_b_rationale: string;
  activation_conditions: SuccessCondition[];
  plan_b_acceptance_envelope: AcceptanceEnvelope;
}

export interface AepEod {
  eod_id: Uuid; // UUID v7
  eod_version: '1.0';
  session_id_ref: Uuid;
  submitted_at: Iso8601;
  primary_outcome: {
    target_state: string;
    target_phase?: string;
    confidence: number; // 0.0-1.0
    rationale: string;
  };
  acceptance_envelope: AcceptanceEnvelope;
  plan_b: PlanB | null;
  auto_activate_plan_b: boolean; // default false
  submitter_mjwt_id: string; // jti of Root Mandate JWT
  eod_signature: string;
}

export type EodOutcome = 'MATCHED' | 'PARTIAL' | 'PLAN_B_MATCHED' | 'UNMATCHED';

// ---------------------------------------------------------------------
// §7 — Context Package (minimal fields needed to drive the loop; the
// full Context Package schema carries SO Instance state snapshots and
// Proximity Events that are out of this sample's Tier 2 scope).
// ---------------------------------------------------------------------

export type ContextTrigger =
  | 'SESSION_START'
  | 'STATE_CHANGE'
  | 'HEM_RESOLUTION'
  | 'STALL_RESOLVED'
  | 'MANDATE_REVOCATION';

export interface ContextPackage {
  cp_id: Uuid;
  trigger: ContextTrigger;
  so_current_state: string;
  so_current_phase: string;
  declared_goal_state: string; // operative goal — primary or Plan B
  redirect_instruction?: string; // present on HEM_RESOLUTION -> REDIRECT
}

// ---------------------------------------------------------------------
// §9 — Transition Request (ACT step)
// ---------------------------------------------------------------------

export interface TransitionRequest {
  mandate_jwt: string;
  cedar_action: string;
  idp: import('../deps/idp/index.js').IntentDeclaration;
}

// ---------------------------------------------------------------------
// §10 — GEC Response (OBSERVE step)
// ---------------------------------------------------------------------

export interface PermitResponse {
  result: 'PERMIT';
  new_state: string;
  new_phase: string;
  event_stream_entry_id: string;
  aep_iteration: number;
}

export interface DenyResponse {
  result: 'DENY';
  deny_code: string;
  deny_reason: string;
  idp_ref: string;
  enrichment: Record<string, unknown>;
  aep_iteration: number;
  prior_denial_count: number;
  what_changed_guidance?: string;
}

export interface HemPendingResponse {
  result: 'HEM_PENDING';
  hem_id: string;
  trigger_class: string;
  urgency: 'ADVISORY' | 'RECOMMENDED' | 'REQUIRED';
  timeout_at: string | null;
}

export interface StalledResponse {
  result: 'STALLED';
  stall_reason: 'STALL_DENY_THRESHOLD' | 'STALL_PATH_EXHAUSTED' | 'STALL_PLAN_B_BLOCKED' | 'STALL_ITERATION_LIMIT';
  aep_iteration: number;
}

export type GecResponse = PermitResponse | DenyResponse | HemPendingResponse | StalledResponse;

// ---------------------------------------------------------------------
// §5 — Session Lifecycle states
// ---------------------------------------------------------------------

export type AepSessionState = 'ACTIVE' | 'HEM_PENDING' | 'STALLED' | 'PLAN_B_ACTIVE' | 'CLOSED';

export type AgentClass = 'CLASS_1' | 'CLASS_2' | 'CLASS_3';

export type ClosureReason =
  | 'GOAL_ACHIEVED'
  | 'PLAN_B_ACHIEVED'
  | 'MANDATE_EXPIRED'
  | 'AGENT_DECLARED'
  | 'GEE_CLOSED'
  | 'HEM_TERMINATED'
  | 'KERNEL_REJECTED'
  | 'MANDATE_REVOKED'
  | 'STALL_TIMEOUT'
  | 'CLUSTER_HALT';

export class AepDenyError extends Error {
  constructor(
    public code: string,
    message: string,
  ) {
    super(message);
    this.name = 'AepDenyError';
  }
}

/** §5.4(a) default — SO Type MAY override. */
export const DEFAULT_STALL_DENY_THRESHOLD = 5;
