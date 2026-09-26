// Step 5 — gen-corpus.ts
// Generates svl/corpus-b/idp/happy-path.json and edge-cases.json by
// actually running each scenario through IDPGovernanceEngineComponent —
// same discipline as GAR/SOV/MJWT/PT: SVL logs are captured implementation
// output, not hand-authored fixtures. 20 happy-path (HP-01..HP-20) match
// the plan's six named categories for Step 5; 21 edge/adversarial
// (EDGE-01..EDGE-21) cover every -05 deny/error code plus the calibration
// and PD-EOD scope-bounding boundary conditions.

import { randomUUID } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import {
  IDPGovernanceEngineComponent,
  type IntentDeclaration,
} from './index';
import { SO_INSTANCE_TYPE_MAP, type MandateBinding } from './stubs';

interface CorpusEntry {
  id: string;
  scenario: string;
  spec_ref: string;
  input: unknown;
  outcome: unknown;
  notes?: string;
}

const happyPath: CorpusEntry[] = [];
const edgeCases: CorpusEntry[] = [];

function freshEngine() {
  return new IDPGovernanceEngineComponent();
}

function baseIDP(overrides: Partial<IntentDeclaration> & { so_id: string; mandate_id: string; session_id: string }): IntentDeclaration {
  return {
    idp_id: randomUUID(),
    step_sequence: 1,
    requested_action: 'atp:booking:confirm',
    declared_goal: { goal_id: randomUUID(), description: 'Corpus scenario goal' },
    reasoning_basis: { type: 'RULE_BASED', description: 'Standing instruction execution' },
    confidence_level: 0.8,
    hem_urgency: 'NONE',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

function record(bucket: CorpusEntry[], id: string, scenario: string, spec_ref: string, input: unknown, outcome: unknown, notes?: string) {
  bucket.push({ id, scenario, spec_ref, input, outcome, notes });
}

// =====================================================================
// HAPPY PATH — HP-01..HP-20
// =====================================================================

// HP-01..HP-04: intake_endorsement flow
{
  const engine = freshEngine();
  const req1 = {
    eod: { eod_id: randomUUID(), primary_outcome: { target_state: 'CONFIRMED' } },
    mandate_jwt_jti: 'mandate-hp-01', so_id: 'so-hp-01', so_type_id: 'atp/booking-object/1.0',
    principal_credential: 'kia:principal-001', requested_at: new Date().toISOString(), request_id: randomUUID(),
  };
  const res1 = engine.intakeEndorsement(req1);
  record(happyPath, 'IDP-HP-001', 'intake_endorsement — simple booking, no plan_b', '§4.6.1-4.6.2', req1, res1);

  const req2 = {
    eod: { eod_id: randomUUID(), primary_outcome: { target_state: 'CONFIRMED' }, plan_b: { plan_b_id: 'pb-hp-02', plan_b_target_state: 'PRE_ACTIVITY' } },
    mandate_jwt_jti: 'mandate-hp-02', so_id: 'so-hp-02', so_type_id: 'atp/booking-object/1.0',
    principal_credential: 'kia:principal-002', requested_at: new Date().toISOString(), request_id: randomUUID(),
  };
  const res2 = engine.intakeEndorsement(req2);
  record(happyPath, 'IDP-HP-002', 'intake_endorsement — with plan_b, both validated', '§4.6.2 plan_b_validated', req2, res2);

  const reqId3 = randomUUID();
  const eod3 = { eod_id: randomUUID(), primary_outcome: { target_state: 'CONFIRMED' } };
  const req3a = { eod: eod3, mandate_jwt_jti: 'mandate-hp-03', so_id: 'so-hp-03', so_type_id: 'atp/booking-object/1.0', principal_credential: 'kia:principal-003', requested_at: new Date().toISOString(), request_id: reqId3 };
  const res3a = engine.intakeEndorsement(req3a);
  const res3b = engine.intakeEndorsement(req3a); // duplicate request_id
  record(happyPath, 'IDP-HP-003', 'intake_endorsement — idempotent duplicate request_id returns same Endorsed EOD', '§4.6.3 INTAKE_DUPLICATE', req3a, { first: res3a.endorsed_eod?.endorsed_eod_id, second: res3b.endorsed_eod?.endorsed_eod_id, same: res3a.endorsed_eod?.endorsed_eod_id === res3b.endorsed_eod?.endorsed_eod_id });

  const req4 = {
    eod: { eod_id: randomUUID(), primary_outcome: { target_state: 'CONFIRMED' } },
    mandate_jwt_jti: 'mandate-hp-04', so_id: 'so-hp-04', so_type_id: 'atp/booking-object/1.0',
    principal_credential: 'kia:principal-004', requested_at: new Date().toISOString(), request_id: randomUUID(),
  };
  const res4 = engine.intakeEndorsement(req4);
  record(happyPath, 'IDP-HP-004', 'intake_endorsement — CLASS_2 agent EOD (endorsement itself is class-agnostic)', '§4.6', req4, res4);
}

// HP-05..HP-08: endorsed_eod_id carrying through session -> PERMIT
{
  const engine = freshEngine();
  const binding: MandateBinding = { mandate_id: 'mandate-hp-05', so_id: 'so-hp-05', human_principal_id: 'human-tom', agent_class: 'CLASS_3' };
  const intake = engine.intakeEndorsement({
    eod: { eod_id: randomUUID(), primary_outcome: { target_state: 'CONFIRMED' } },
    mandate_jwt_jti: binding.mandate_id, so_id: binding.so_id, so_type_id: 'atp/booking-object/1.0',
    principal_credential: 'kia:principal-005', requested_at: new Date().toISOString(), request_id: randomUUID(),
  });
  const idp = baseIDP({ session_id: 's-hp-05', so_id: binding.so_id, mandate_id: binding.mandate_id, endorsed_eod_id: intake.endorsed_eod!.endorsed_eod_id });
  const v = engine.submitIDP(idp, binding, { plan_b_active: false });
  record(happyPath, 'IDP-HP-005', 'Class 3 IDP with endorsed_eod_id -> validation PERMIT, has_endorsed_eod=true', '§4.2 endorsed_eod_id, §5.4', idp, v);

  const bindingC2: MandateBinding = { mandate_id: 'mandate-hp-06', so_id: 'so-hp-06', human_principal_id: 'human-tom', agent_class: 'CLASS_2' };
  const idp2 = baseIDP({ session_id: 's-hp-06', so_id: bindingC2.so_id, mandate_id: bindingC2.mandate_id });
  const v2 = engine.submitIDP(idp2, bindingC2, { plan_b_active: false });
  record(happyPath, 'IDP-HP-006', 'Class 2 IDP without endorsed_eod_id -> accepted with EOD_ABSENT warning (not rejected)', '§4.2 "Class 2 ... GEC MUST log EOD_ABSENT"', idp2, v2);

  const bindingC1: MandateBinding = { mandate_id: 'mandate-hp-07', so_id: 'so-hp-07', human_principal_id: 'human-tom', agent_class: 'CLASS_1' };
  const idp3 = baseIDP({ session_id: 's-hp-07', so_id: bindingC1.so_id, mandate_id: bindingC1.mandate_id, mandate_reference: 'spo://myauberge/atp-booking-standard/1.0' });
  const v3 = engine.submitIDP(idp3, bindingC1, { plan_b_active: false });
  record(happyPath, 'IDP-HP-007', 'IDP with valid mandate_reference -> SPO structural validation passes, mandate_reference_valid=true', '§4.2 mandate_reference (a)-(c)', idp3, v3);

  const bindingChain: MandateBinding = { mandate_id: 'mandate-hp-08', so_id: 'so-hp-08', human_principal_id: 'human-tom', agent_class: 'CLASS_1' };
  const steps = [1, 2, 3].map((n) => {
    const idpN = baseIDP({ session_id: 's-hp-08', so_id: bindingChain.so_id, mandate_id: bindingChain.mandate_id, step_sequence: n });
    const r = engine.submitIDP(idpN, bindingChain, { plan_b_active: false });
    if (r.ok) engine.recordPermit(idpN, 'DRAFT', 'CONFIRMED');
    return { step_sequence: n, ok: r.ok };
  });
  record(happyPath, 'IDP-HP-008', 'Multiple sequential IDPs, step_sequence strictly increasing, all PERMIT', '§4.2 step_sequence monotonicity', { session: 's-hp-08' }, { steps });
}

// HP-09..HP-12: RETRY_CONTINUATION with what_changed_guidance
{
  const engine = freshEngine();
  const binding: MandateBinding = { mandate_id: 'mandate-hp-09', so_id: 'so-hp-09', human_principal_id: 'human-tom', agent_class: 'CLASS_1' };
  const idpDenied = baseIDP({ session_id: 's-hp-09', so_id: binding.so_id, mandate_id: binding.mandate_id, step_sequence: 1, requested_action: 'atp:booking:cancel' });
  engine.submitIDP(idpDenied, binding, { plan_b_active: false });
  const deny = engine.recordDeny(idpDenied, 'POLICY_DENY', 'not permitted within 24h', { confidence_level_required: 0.95 }, ['atp:booking:suspend']);
  const retry = baseIDP({
    session_id: 's-hp-09', so_id: binding.so_id, mandate_id: binding.mandate_id, step_sequence: 2,
    requested_action: 'atp:booking:suspend', confidence_level: 0.96,
    reasoning_basis: { type: 'RETRY_CONTINUATION', description: 'Prior cancel denied. Raising confidence per enrichment.confidence_level_required (0.95) and switching action.' },
    context_refs: [idpDenied.idp_id],
  });
  const vRetry = engine.submitIDP(retry, binding, { plan_b_active: false });
  record(happyPath, 'IDP-HP-009', 'RETRY_CONTINUATION description references enrichment field by name -> no warnings', '§4.3 RETRY_CONTINUATION, §6.2 what_changed_guidance', { deny_what_changed_guidance: deny.what_changed_guidance, retry }, vRetry);

  record(happyPath, 'IDP-HP-010', 'RETRY_CONTINUATION context_refs correctly points to prior denied idp_id -> no RETRY_WITHOUT_PRIOR_REF', '§5.2(l)', { context_refs: retry.context_refs }, { warnings: vRetry.warnings ?? [] });

  const engine2 = freshEngine();
  const binding2: MandateBinding = { mandate_id: 'mandate-hp-11', so_id: 'so-hp-11', human_principal_id: 'human-tom', agent_class: 'CLASS_1' };
  const denied2 = baseIDP({ session_id: 's-hp-11', so_id: binding2.so_id, mandate_id: binding2.mandate_id, step_sequence: 1, requested_action: 'atp:booking:cancel' });
  engine2.submitIDP(denied2, binding2, { plan_b_active: false });
  engine2.recordDeny(denied2, 'POLICY_DENY', 'insufficient confidence', { confidence_level_required: 0.9 }, []);
  const retry2 = baseIDP({
    session_id: 's-hp-11', so_id: binding2.so_id, mandate_id: binding2.mandate_id, step_sequence: 2, confidence_level: 0.92,
    reasoning_basis: { type: 'RETRY_CONTINUATION', description: 'Raised confidence to satisfy enrichment.confidence_level_required.' },
    context_refs: [denied2.idp_id],
  });
  const v2r = engine2.submitIDP(retry2, binding2, { plan_b_active: false });
  if (v2r.ok) engine2.recordPermit(retry2, 'CONFIRMED', 'CANCELLED');
  record(happyPath, 'IDP-HP-011', 'RETRY_CONTINUATION following DENY leads to PERMIT on second attempt', '§4.3, §5.6.1', retry2, v2r);

  record(happyPath, 'IDP-HP-012', 'RETRY_CONTINUATION session full audit trail: IDP_SUBMITTED < CEDAR_DENY_RECORDED < ACTION_RESULT_RECORDED < IDP_SUBMITTED < STATE_TRANSITIONED', '§5.6.4', {}, { events: engine2.getEventLog().map((e) => e.event_type) });
}

// HP-13..HP-15: PD-EOD derivation (in-scope)
{
  const engine = freshEngine();
  const pd1 = engine.derivePDEOD({ source_prompt: 'Confirm the booking once the payment clears.', so_type_id: 'atp/booking-object/1.0', implied_target_state: 'CONFIRMED', derivation_model: 'gec-prompt-derivation-v1', derivation_confidence: 0.95 });
  record(happyPath, 'IDP-HP-013', 'PD-EOD derivation, in-scope target, high derivation_confidence', '§4.7.1-4.7.2', { source_prompt: pd1.source_prompt }, { derived: pd1.derived, target_state: pd1.primary_outcome.target_state, warnings: pd1.derivation_warnings });

  const pd2 = engine.derivePDEOD({ source_prompt: 'Move it to in-journey status, I think.', so_type_id: 'atp/booking-object/1.0', implied_target_state: 'IN_JOURNEY', derivation_model: 'gec-prompt-derivation-v1', derivation_confidence: 0.55 });
  record(happyPath, 'IDP-HP-014', 'PD-EOD derivation, in-scope target, low derivation_confidence (still IN_SCOPE — confidence and scope are independent)', '§4.7.1', { source_prompt: pd2.source_prompt }, { derived: pd2.derived, target_state: pd2.primary_outcome.target_state, derivation_confidence: pd2.derivation_confidence });

  const longPrompt = 'Please confirm the booking. '.repeat(60).slice(0, 1990); // near 2000-char ceiling, still valid
  const pd3 = engine.derivePDEOD({ source_prompt: longPrompt, so_type_id: 'atp/booking-object/1.0', implied_target_state: 'CONFIRMED', derivation_model: 'gec-prompt-derivation-v1', derivation_confidence: 0.8 });
  record(happyPath, 'IDP-HP-015', 'PD-EOD derivation, source_prompt near the 2000-char ceiling — accepted', '§4.7.1 source_prompt max 2000 chars', { prompt_length: longPrompt.length }, { derived: pd3.derived });
}

// HP-16..HP-18: PLAN_B_ACTIVE with plan_b_ref
{
  const engine = freshEngine();
  const binding: MandateBinding = { mandate_id: 'mandate-hp-16', so_id: 'so-hp-16', human_principal_id: 'human-tom', agent_class: 'CLASS_1' };
  const idp = baseIDP({ session_id: 's-hp-16', so_id: binding.so_id, mandate_id: binding.mandate_id, requested_action: 'atp:booking:suspend', plan_b_ref: 'plan-b-hp-16' });
  const v = engine.submitIDP(idp, binding, { plan_b_active: true });
  record(happyPath, 'IDP-HP-016', 'PLAN_B_ACTIVE session with plan_b_ref present -> accepted, idp.plan_b_active=true in Cedar context', '§4.2 plan_b_ref, §5.4', idp, v);

  const engine2 = freshEngine();
  const binding2: MandateBinding = { mandate_id: 'mandate-hp-17', so_id: 'so-hp-17', human_principal_id: 'human-tom', agent_class: 'CLASS_1' };
  const intake = engine2.intakeEndorsement({
    eod: { eod_id: randomUUID(), primary_outcome: { target_state: 'CONFIRMED' }, plan_b: { plan_b_id: 'plan-b-hp-17', plan_b_target_state: 'PRE_ACTIVITY' } },
    mandate_jwt_jti: binding2.mandate_id, so_id: binding2.so_id, so_type_id: 'atp/booking-object/1.0',
    principal_credential: 'kia:principal-017', requested_at: new Date().toISOString(), request_id: randomUUID(),
  });
  const idp2 = baseIDP({ session_id: 's-hp-17', so_id: binding2.so_id, mandate_id: binding2.mandate_id, endorsed_eod_id: intake.endorsed_eod!.endorsed_eod_id, plan_b_ref: 'plan-b-hp-17', requested_action: 'atp:booking:suspend' });
  const v2 = engine2.submitIDP(idp2, binding2, { plan_b_active: true });
  record(happyPath, 'IDP-HP-017', 'Full chain: intake_endorsement plan_b_validated=true -> PLAN_B_ACTIVE IDP referencing the same plan_b_id', '§4.6.2 plan_b_validated + §4.2 plan_b_ref', { endorsed_plan_b_validated: intake.endorsed_eod!.plan_b_validated }, v2);

  const engine3 = freshEngine();
  const binding3: MandateBinding = { mandate_id: 'mandate-hp-18', so_id: 'so-hp-18', human_principal_id: 'human-tom', agent_class: 'CLASS_1' };
  const idp3 = baseIDP({ session_id: 's-hp-18', so_id: binding3.so_id, mandate_id: binding3.mandate_id, plan_b_ref: 'plan-b-hp-18', requested_action: 'atp:booking:suspend' });
  engine3.submitIDP(idp3, binding3, { plan_b_active: true });
  engine3.recordPermit(idp3, 'PRE_ACTIVITY', 'PRE_ACTIVITY'); // resume-in-place, plan B path
  record(happyPath, 'IDP-HP-018', 'PLAN_B_ACTIVE transition committed — STATE_TRANSITIONED recorded with plan_b_ref context intact', '§5.6.1', idp3, { events: engine3.getEventLog().map((e) => e.event_type) });
}

// HP-19..HP-20: calibration — clean window, then trigger at cycle 10
{
  const engine = freshEngine();
  const binding: MandateBinding = { mandate_id: 'mandate-hp-19', so_id: 'so-hp-19', human_principal_id: 'human-tom', agent_class: 'CLASS_1' };
  for (let i = 1; i <= 10; i++) {
    const idp = baseIDP({ session_id: 's-hp-19', so_id: binding.so_id, mandate_id: binding.mandate_id, step_sequence: i, confidence_level: 0.85, requested_action: `atp:booking:action-${i}` });
    engine.submitIDP(idp, binding, { plan_b_active: false });
    if (i <= 3) engine.recordDeny(idp, 'POLICY_DENY', 'demo denial', {}, []); // 3/10 = 0.30 < 0.40 threshold
    else engine.recordPermit(idp, 'CONFIRMED', 'PRE_ACTIVITY');
  }
  record(happyPath, 'IDP-HP-019', 'Calibration window reaches 10 IDPs with ratio 0.30 (below 0.40 threshold) -> no warning fires', '§7.2', { ratio: '3/10' }, { miscalibration_active: engine.isMiscalibrationActive('s-hp-19') });

  const engine2 = freshEngine();
  const binding2: MandateBinding = { mandate_id: 'mandate-hp-20', so_id: 'so-hp-20', human_principal_id: 'human-tom', agent_class: 'CLASS_1' };
  for (let i = 1; i <= 10; i++) {
    const idp = baseIDP({ session_id: 's-hp-20', so_id: binding2.so_id, mandate_id: binding2.mandate_id, step_sequence: i, confidence_level: 0.85, requested_action: `atp:booking:action-${i}` });
    engine2.submitIDP(idp, binding2, { plan_b_active: false });
    if (i <= 5) engine2.recordDeny(idp, 'POLICY_DENY', 'demo denial', {}, []); // 5/10 = 0.50 > 0.40
    else engine2.recordPermit(idp, 'CONFIRMED', 'PRE_ACTIVITY');
  }
  const warningEvent = engine2.getEventLog().find((e) => e.event_type === 'CONFIDENCE_MISCALIBRATION_WARNING');
  record(happyPath, 'IDP-HP-020', 'CONFIDENCE_MISCALIBRATION_WARNING trigger exactly at cycle 10, ratio 0.50 > 0.40 threshold', '§7.2, §5.4 idp.miscalibration_score', { ratio: '5/10' }, { warning_event: warningEvent?.payload });
}

// =====================================================================
// EDGE / ADVERSARIAL — EDGE-01..EDGE-21
// =====================================================================

function bindingFor(n: number, agent_class: MandateBinding['agent_class'] = 'CLASS_1'): MandateBinding {
  return { mandate_id: `mandate-edge-${n}`, so_id: `so-edge-${n}`, human_principal_id: 'human-tom', agent_class };
}

// E-01: malformed (required field missing)
{
  const engine = freshEngine();
  const binding = bindingFor(1);
  const idp = baseIDP({ session_id: 's-edge-01', so_id: binding.so_id, mandate_id: binding.mandate_id, requested_action: '' as any });
  const v = engine.submitIDP(idp, binding, { plan_b_active: false });
  record(edgeCases, 'IDP-EDGE-001', 'IDP_MALFORMED — requested_action empty', '§5.2(b)', idp, v);
}

// E-02: duplicate idp_id
{
  const engine = freshEngine();
  const binding = bindingFor(2);
  const idp = baseIDP({ session_id: 's-edge-02', so_id: binding.so_id, mandate_id: binding.mandate_id });
  engine.submitIDP(idp, binding, { plan_b_active: false });
  const v = engine.submitIDP(idp, binding, { plan_b_active: false }); // same idp_id again
  record(edgeCases, 'IDP-EDGE-002', 'IDP_DUPLICATE — idp_id resubmitted', '§5.2(c)', idp, v);
}

// E-03: so_id mismatch
{
  const engine = freshEngine();
  const binding = bindingFor(3);
  const idp = baseIDP({ session_id: 's-edge-03', so_id: 'so-not-bound', mandate_id: binding.mandate_id });
  const v = engine.submitIDP(idp, binding, { plan_b_active: false });
  record(edgeCases, 'IDP-EDGE-003', 'IDP_SO_MISMATCH — so_id does not match bound mandate', '§5.2(d)', idp, v);
}

// E-04: mandate_id mismatch
{
  const engine = freshEngine();
  const binding = bindingFor(4);
  const idp = baseIDP({ session_id: 's-edge-04', so_id: binding.so_id, mandate_id: 'mandate-not-bound' });
  const v = engine.submitIDP(idp, binding, { plan_b_active: false });
  record(edgeCases, 'IDP-EDGE-004', 'IDP_MANDATE_MISMATCH — mandate_id does not match jti of presented mandate_jwt', '§5.2(e)', idp, v);
}

// E-05: step_sequence non-monotonic
{
  const engine = freshEngine();
  const binding = bindingFor(5);
  const idp1 = baseIDP({ session_id: 's-edge-05', so_id: binding.so_id, mandate_id: binding.mandate_id, step_sequence: 3 });
  engine.submitIDP(idp1, binding, { plan_b_active: false });
  const idp2 = baseIDP({ session_id: 's-edge-05', so_id: binding.so_id, mandate_id: binding.mandate_id, step_sequence: 2 });
  const v = engine.submitIDP(idp2, binding, { plan_b_active: false });
  record(
    edgeCases, 'IDP-EDGE-005',
    'step_sequence 2 submitted after step_sequence 3 already committed -> rejected',
    '§5.2(f), §4.2 step_sequence',
    idp2, v,
    'SDB-IDP-02 [new]: §5.2(f) says the GEC SHOULD reject a non-monotonic step_sequence but the -05 deny code registry (§13) has no dedicated code for this condition — sample maps it to IDP_MALFORMED as the closest existing code (Type I mapping), pending confirmation a dedicated code (e.g. IDP_STEP_SEQUENCE_INVALID) is not intended elsewhere in the suite.'
  );
}

// E-06: Class 3 without endorsed_eod_id
{
  const engine = freshEngine();
  const binding = bindingFor(6, 'CLASS_3');
  const idp = baseIDP({ session_id: 's-edge-06', so_id: binding.so_id, mandate_id: binding.mandate_id });
  const v = engine.submitIDP(idp, binding, { plan_b_active: false });
  record(edgeCases, 'IDP-EDGE-006', 'IDP_ENDORSED_EOD_REQUIRED — Class 3 agent, no endorsed_eod_id', '§4.2, §5.2(i), §13', idp, v);
}

// E-07: endorsed_eod_id invalid (unknown UUID)
{
  const engine = freshEngine();
  const binding = bindingFor(7, 'CLASS_3');
  const idp = baseIDP({ session_id: 's-edge-07', so_id: binding.so_id, mandate_id: binding.mandate_id, endorsed_eod_id: randomUUID() });
  const v = engine.submitIDP(idp, binding, { plan_b_active: false });
  record(edgeCases, 'IDP-EDGE-007', 'IDP_ENDORSED_EOD_INVALID — endorsed_eod_id not found in Event Log', '§4.2, §5.2(i), §13', idp, v);
}

// E-08: endorsed_eod_id bound to a different so_id
{
  const engine = freshEngine();
  const binding = bindingFor(8, 'CLASS_3');
  const intake = engine.intakeEndorsement({
    eod: { eod_id: randomUUID(), primary_outcome: { target_state: 'CONFIRMED' } },
    mandate_jwt_jti: binding.mandate_id, so_id: 'so-edge-08-DIFFERENT', so_type_id: 'atp/booking-object/1.0',
    principal_credential: 'kia:principal-08', requested_at: new Date().toISOString(), request_id: randomUUID(),
  });
  const idp = baseIDP({ session_id: 's-edge-08', so_id: binding.so_id, mandate_id: binding.mandate_id, endorsed_eod_id: intake.endorsed_eod!.endorsed_eod_id });
  const v = engine.submitIDP(idp, binding, { plan_b_active: false });
  record(edgeCases, 'IDP-EDGE-008', 'IDP_ENDORSED_EOD_INVALID — endorsed_eod_id exists but bound to a different so_id', '§4.2 "covers the so_id ... of this IDP"', idp, v);
}

// E-09: PLAN_B_ACTIVE without plan_b_ref
{
  const engine = freshEngine();
  const binding = bindingFor(9);
  const idp = baseIDP({ session_id: 's-edge-09', so_id: binding.so_id, mandate_id: binding.mandate_id, requested_action: 'atp:booking:suspend' });
  const v = engine.submitIDP(idp, binding, { plan_b_active: true });
  record(edgeCases, 'IDP-EDGE-009', 'IDP_PLAN_B_REF_REQUIRED — PLAN_B_ACTIVE session, plan_b_ref absent', '§4.2 plan_b_ref, §5.2(j), CONF-AEP-14', idp, v);
}

// E-10: mandate_reference resolves to an expired SPO
{
  const engine = freshEngine();
  const binding = bindingFor(10);
  const idp = baseIDP({ session_id: 's-edge-10', so_id: binding.so_id, mandate_id: binding.mandate_id, mandate_reference: 'spo://myauberge/atp-booking-legacy/0.9' });
  const v = engine.submitIDP(idp, binding, { plan_b_active: false });
  record(edgeCases, 'IDP-EDGE-010', 'IDP_SPO_EXPIRED — mandate_reference SPO URI resolves to an expired document', '§4.2(a), §13', idp, v);
}

// E-11: mandate_reference does not resolve at all
{
  const engine = freshEngine();
  const binding = bindingFor(11);
  const idp = baseIDP({ session_id: 's-edge-11', so_id: binding.so_id, mandate_id: binding.mandate_id, mandate_reference: 'spo://nonexistent/uri/0.0' });
  const v = engine.submitIDP(idp, binding, { plan_b_active: false });
  record(
    edgeCases, 'IDP-EDGE-011',
    'mandate_reference does not resolve to any known SPO document',
    '§4.2(a)',
    idp, v,
    'Type I note: §4.2(a) only names IDP_SPO_EXPIRED for "resolves to an expired document" — it does not give a distinct code for "does not resolve at all." Sample uses IDP_SPO_EXPIRED for both, on the reading that an unresolvable URI is a degenerate case of "not currently valid." Not logged as an SDB — narrower reading than SDB-IDP-02, flagged here for visibility only.'
  );
}

// E-12: requested_action outside SPO action space
{
  const engine = freshEngine();
  const binding = bindingFor(12);
  const idp = baseIDP({ session_id: 's-edge-12', so_id: binding.so_id, mandate_id: binding.mandate_id, mandate_reference: 'spo://myauberge/atp-booking-standard/1.0', requested_action: 'atp:booking:delete_forever' });
  const v = engine.submitIDP(idp, binding, { plan_b_active: false });
  record(edgeCases, 'IDP-EDGE-012', 'IDP_ACTION_OUTSIDE_SPO — requested_action not in the SPO action space', '§4.2(b), §13', idp, v);
}

// E-13: mandate_reference SPO type mismatch vs so_id's actual SO Type
{
  const engine = freshEngine();
  const binding = bindingFor(13);
  // so-edge-13 is not registered in SO_INSTANCE_TYPE_MAP -> defaults to
  // atp/booking-object/1.0 in the fixture, so register it explicitly as
  // a mission-object instance to force a genuine mismatch.
  const stubs = { SO_INSTANCE_TYPE_MAP };
  stubs.SO_INSTANCE_TYPE_MAP['so-edge-13'] = 'atp/mission-object/1.0';
  const idp = baseIDP({ session_id: 's-edge-13', so_id: 'so-edge-13', mandate_id: binding.mandate_id, mandate_reference: 'spo://myauberge/atp-booking-standard/1.0' });
  const v = engine.submitIDP(idp, { ...binding, so_id: 'so-edge-13' }, { plan_b_active: false });
  record(edgeCases, 'IDP-EDGE-013', 'IDP_SPO_TYPE_MISMATCH — mandate_reference SPO defines atp/booking-object/1.0 but so_id is a mission-object instance', '§4.2(c), §13', idp, v);
}

// E-14: intake_endorsement — unrecognized principal
{
  const engine = freshEngine();
  const req = { eod: { eod_id: randomUUID(), primary_outcome: { target_state: 'CONFIRMED' } }, mandate_jwt_jti: 'mandate-edge-14', so_id: 'so-edge-14', so_type_id: 'atp/booking-object/1.0', principal_credential: 'not-a-kia-credential', requested_at: new Date().toISOString(), request_id: randomUUID() };
  const res = engine.intakeEndorsement(req);
  record(edgeCases, 'IDP-EDGE-014', 'INTAKE_PRINCIPAL_UNRECOGNIZED — credential not recognized by Party Registry stub', '§4.6.1, §4.6.3', req, res);
}

// E-15: intake_endorsement — malformed EOD (no primary_outcome)
{
  const engine = freshEngine();
  const req = { eod: { eod_id: randomUUID(), primary_outcome: undefined as any }, mandate_jwt_jti: 'mandate-edge-15', so_id: 'so-edge-15', so_type_id: 'atp/booking-object/1.0', principal_credential: 'kia:principal-15', requested_at: new Date().toISOString(), request_id: randomUUID() };
  const res = engine.intakeEndorsement(req);
  record(edgeCases, 'IDP-EDGE-015', 'INTAKE_EOD_MALFORMED — primary_outcome missing', '§4.6.3', req, res);
}

// E-16: intake_endorsement — primary_outcome target_state not in state machine
{
  const engine = freshEngine();
  const req = { eod: { eod_id: randomUUID(), primary_outcome: { target_state: 'NOT_A_REAL_STATE' } }, mandate_jwt_jti: 'mandate-edge-16', so_id: 'so-edge-16', so_type_id: 'atp/booking-object/1.0', principal_credential: 'kia:principal-16', requested_at: new Date().toISOString(), request_id: randomUUID() };
  const res = engine.intakeEndorsement(req);
  record(edgeCases, 'IDP-EDGE-016', 'INTAKE_PRIMARY_OUTCOME_INVALID — target_state not in SO Type state machine', '§4.6.3', req, res);
}

// E-17: intake_endorsement — plan_b target_state not in state machine
{
  const engine = freshEngine();
  const req = { eod: { eod_id: randomUUID(), primary_outcome: { target_state: 'CONFIRMED' }, plan_b: { plan_b_id: 'pb-17', plan_b_target_state: 'NOT_A_REAL_STATE' } }, mandate_jwt_jti: 'mandate-edge-17', so_id: 'so-edge-17', so_type_id: 'atp/booking-object/1.0', principal_credential: 'kia:principal-17', requested_at: new Date().toISOString(), request_id: randomUUID() };
  const res = engine.intakeEndorsement(req);
  record(edgeCases, 'IDP-EDGE-017', 'INTAKE_PLAN_B_INVALID — plan_b_target_state not in SO Type state machine', '§4.6.3', req, res);
}

// E-18: RETRY_CONTINUATION without enrichment reference -> RETRY_WHAT_CHANGED_WEAK (warning, not reject)
{
  const engine = freshEngine();
  const binding = bindingFor(18);
  const denied = baseIDP({ session_id: 's-edge-18', so_id: binding.so_id, mandate_id: binding.mandate_id, step_sequence: 1, requested_action: 'atp:booking:cancel' });
  engine.submitIDP(denied, binding, { plan_b_active: false });
  engine.recordDeny(denied, 'POLICY_DENY', 'denied', { confidence_level_required: 0.9 }, []);
  const weakRetry = baseIDP({
    session_id: 's-edge-18', so_id: binding.so_id, mandate_id: binding.mandate_id, step_sequence: 2,
    reasoning_basis: { type: 'RETRY_CONTINUATION', description: 'Trying again, think it will work this time.' }, // no enrichment.* reference
    context_refs: [denied.idp_id],
  });
  const v = engine.submitIDP(weakRetry, binding, { plan_b_active: false });
  record(edgeCases, 'IDP-EDGE-018', 'RETRY_WHAT_CHANGED_WEAK — RETRY_CONTINUATION description does not reference a specific enrichment field (warning, not reject — accepted with warning per §13 registry note)', '§4.3, §13', weakRetry, v);
}

// E-19: RETRY_CONTINUATION with empty context_refs -> RETRY_WITHOUT_PRIOR_REF
{
  const engine = freshEngine();
  const binding = bindingFor(19);
  const idp = baseIDP({
    session_id: 's-edge-19', so_id: binding.so_id, mandate_id: binding.mandate_id,
    reasoning_basis: { type: 'RETRY_CONTINUATION', description: 'Retrying per enrichment.confidence_level_required.' },
    context_refs: [],
  });
  const v = engine.submitIDP(idp, binding, { plan_b_active: false });
  record(edgeCases, 'IDP-EDGE-019', 'RETRY_WITHOUT_PRIOR_REF — RETRY_CONTINUATION with no context_refs to a prior IDP_SUBMITTED', '§5.2(l)', idp, v);
}

// E-20: PD-EOD scope-bounding — OUT_OF_SCOPE prompt must not silently clip
{
  const engine = freshEngine();
  const pd = engine.derivePDEOD({ source_prompt: 'Please refund the guest directly to their credit card.', so_type_id: 'atp/booking-object/1.0', implied_target_state: 'REFUNDED', derivation_model: 'gec-prompt-derivation-v1', derivation_confidence: 0.7 });
  record(edgeCases, 'IDP-EDGE-020', 'PD-EOD scope-bounding — prompt implies out-of-scope target_state; GEC must NOT silently clip, must surface derivation_warnings', '§4.7.2', { source_prompt: pd.source_prompt, implied_target_state: 'REFUNDED' }, { derivation_warnings: pd.derivation_warnings });
}

// E-21: calibration ratio exactly at threshold (0.40) must NOT fire (rule is >, not >=), and window at 9 IDPs must not evaluate yet
{
  const engine = freshEngine();
  const binding = bindingFor(21);
  for (let i = 1; i <= 9; i++) {
    const idp = baseIDP({ session_id: 's-edge-21', so_id: binding.so_id, mandate_id: binding.mandate_id, step_sequence: i, confidence_level: 0.85, requested_action: `atp:booking:action-${i}` });
    engine.submitIDP(idp, binding, { plan_b_active: false });
    if (i <= 4) engine.recordDeny(idp, 'POLICY_DENY', 'demo denial', {}, []);
    else engine.recordPermit(idp, 'CONFIRMED', 'PRE_ACTIVITY');
  }
  const atNine = engine.isMiscalibrationActive('s-edge-21');

  // 10th IDP brings ratio to exactly 4/10 = 0.40 — must NOT fire (threshold is exclusive: "greater than")
  const idp10 = baseIDP({ session_id: 's-edge-21', so_id: binding.so_id, mandate_id: binding.mandate_id, step_sequence: 10, confidence_level: 0.85, requested_action: 'atp:booking:action-10' });
  engine.submitIDP(idp10, binding, { plan_b_active: false });
  engine.recordPermit(idp10, 'CONFIRMED', 'PRE_ACTIVITY'); // stays at 4/10, not a 5th denial
  const atTenExactThreshold = engine.isMiscalibrationActive('s-edge-21');

  record(
    edgeCases, 'IDP-EDGE-021',
    'Calibration boundary: window <10 never evaluates; ratio exactly at 0.40 threshold does not fire (§7.2 "greater than a configurable threshold" is a strict inequality)',
    '§7.2',
    { window_at_9: 9, ratio_at_10: '4/10 = 0.40' },
    { miscalibration_active_at_9_idps: atNine, miscalibration_active_at_exact_threshold: atTenExactThreshold }
  );
}

// =====================================================================
// Write output
// =====================================================================

const outDir = path.join(__dirname, 'svl', 'corpus-b', 'idp');
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, 'happy-path.json'), JSON.stringify(happyPath, null, 2));
fs.writeFileSync(path.join(outDir, 'edge-cases.json'), JSON.stringify(edgeCases, null, 2));

console.log(`Wrote ${happyPath.length} happy-path logs -> svl/corpus-b/idp/happy-path.json`);
console.log(`Wrote ${edgeCases.length} edge-case logs -> svl/corpus-b/idp/edge-cases.json`);
