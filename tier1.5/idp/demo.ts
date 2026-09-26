// Step 5 — demo.ts
// Walkthrough: intake_endorsement -> endorsed_eod_id carried through
// session -> PERMIT -> DENY + RETRY_CONTINUATION with what_changed_guidance
// reference -> PD-EOD derivation (in-scope, then OUT_OF_SCOPE) ->
// PLAN_B_ACTIVE requiring plan_b_ref -> CONFIDENCE_MISCALIBRATION_WARNING
// triggered at the 10-IDP cumulative window.
//
// This is a representative walkthrough, not the full SVL corpus. Per the
// plan's own convention (MJWT Step 3: demo.ts covers a handful of named
// scenarios; the full 20 happy-path + 21 edge-case logs live in
// svl/corpus-b/idp/), the complete 20-log corpus is a follow-up SVL task,
// not built in this pass.

import { randomUUID } from 'crypto';
import { IDPGovernanceEngineComponent, type IntentDeclaration } from './index';
import type { MandateBinding } from './stubs';

function line(title: string) {
  console.log(`\n--- ${title} ---`);
}

function baseIDP(overrides: Partial<IntentDeclaration>): IntentDeclaration {
  return {
    idp_id: randomUUID(),
    session_id: 'session-demo-001',
    so_id: 'so-booking-azusa-001',
    mandate_id: 'mandate-jti-demo-001',
    step_sequence: 1,
    requested_action: 'atp:booking:confirm',
    declared_goal: { goal_id: randomUUID(), description: 'Confirm the Azusa booking for the human principal' },
    reasoning_basis: { type: 'RULE_BASED', description: 'Booking window opened; confirming per standing instruction' },
    confidence_level: 0.9,
    hem_urgency: 'NONE',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

async function main() {
  const engine = new IDPGovernanceEngineComponent();
  const binding: MandateBinding = {
    mandate_id: 'mandate-jti-demo-001',
    so_id: 'so-booking-azusa-001',
    human_principal_id: 'human-tom',
    agent_class: 'CLASS_3',
  };

  // -------------------------------------------------------------
  // 1. intake_endorsement flow
  // -------------------------------------------------------------
  line('1. intake_endorsement — EOD submitted before session begins');
  const intake = engine.intakeEndorsement({
    eod: {
      eod_id: randomUUID(),
      primary_outcome: { target_state: 'CONFIRMED' },
      plan_b: { plan_b_id: 'plan-b-001', plan_b_target_state: 'PRE_ACTIVITY' },
    },
    mandate_jwt_jti: binding.mandate_id,
    so_id: binding.so_id,
    so_type_id: 'atp/booking-object/1.0',
    principal_credential: 'kia:human-tom-cred-001',
    requested_at: new Date().toISOString(),
    request_id: randomUUID(),
  });
  console.log(`  ok: ${intake.ok}`);
  console.log(`  scope_status: ${intake.endorsed_eod?.scope_status}`);
  console.log(`  endorsed_eod_id: ${intake.endorsed_eod?.endorsed_eod_id}`);

  const endorsed_eod_id = intake.endorsed_eod!.endorsed_eod_id;

  // -------------------------------------------------------------
  // 2. endorsed_eod_id carried through the session, PERMIT
  // -------------------------------------------------------------
  line('2. IDP submitted carrying endorsed_eod_id -> PERMIT');
  const idp1 = baseIDP({ step_sequence: 1, endorsed_eod_id });
  const result1 = engine.submitIDP(idp1, binding, { plan_b_active: false });
  console.log(`  validation ok: ${result1.ok}`);
  if (result1.ok) {
    engine.recordPermit(idp1, 'DRAFT', 'CONFIRMED');
    console.log('  -> STATE_TRANSITIONED DRAFT -> CONFIRMED');
  }

  // -------------------------------------------------------------
  // 3. DENY, then RETRY_CONTINUATION referencing what_changed_guidance
  // -------------------------------------------------------------
  line('3. DENY on a follow-up action, then RETRY_CONTINUATION');
  const idp2 = baseIDP({
    idp_id: randomUUID(),
    step_sequence: 2,
    endorsed_eod_id,
    requested_action: 'atp:booking:cancel',
    confidence_level: 0.85,
  });
  engine.submitIDP(idp2, binding, { plan_b_active: false });
  const denyResp = engine.recordDeny(
    idp2,
    'POLICY_DENY',
    'Cancellation not permitted within 24h of activity start',
    { confidence_level_required: 0.95, requested_action_alternative: 'atp:booking:suspend' },
    ['atp:booking:suspend']
  );
  console.log(`  deny_code: ${denyResp.deny_code}`);
  console.log(`  what_changed_guidance: ${denyResp.what_changed_guidance}`);

  const idp3 = baseIDP({
    idp_id: randomUUID(),
    step_sequence: 3,
    endorsed_eod_id,
    requested_action: 'atp:booking:suspend',
    confidence_level: 0.6,
    reasoning_basis: {
      type: 'RETRY_CONTINUATION',
      description:
        'Prior atp:booking:cancel was denied (POLICY_DENY). Per what_changed_guidance, ' +
        'switching to enrichment.requested_action_alternative (atp:booking:suspend) instead ' +
        'of cancellation, which does not require the confidence_level_required threshold.',
    },
    context_refs: [idp2.idp_id],
  });
  const validation3 = engine.submitIDP(idp3, binding, { plan_b_active: false });
  console.log(`  retry validation ok: ${validation3.ok}, warnings: ${validation3.warnings ?? '(none)'}`);
  engine.recordPermit(idp3, 'CONFIRMED', 'PRE_ACTIVITY');

  // -------------------------------------------------------------
  // 4. PD-EOD derivation — in-scope, then an OUT_OF_SCOPE prompt
  // -------------------------------------------------------------
  line('4. PD-EOD derivation — in-scope target');
  const pdEodOk = engine.derivePDEOD({
    source_prompt: 'Please move the Azusa booking into the journey phase once the guest checks in.',
    so_type_id: 'atp/booking-object/1.0',
    implied_target_state: 'IN_JOURNEY',
    derivation_model: 'gec-prompt-derivation-v1',
    derivation_confidence: 0.88,
  });
  console.log(`  derived: ${pdEodOk.derived}, target_state: ${pdEodOk.primary_outcome.target_state}`);
  console.log(`  derivation_warnings: ${pdEodOk.derivation_warnings.length ? pdEodOk.derivation_warnings : '(none)'}`);

  line('4b. PD-EOD derivation — OUT_OF_SCOPE prompt (must NOT silently clip)');
  const pdEodBad = engine.derivePDEOD({
    source_prompt: 'Please refund the guest directly to their credit card.',
    so_type_id: 'atp/booking-object/1.0',
    implied_target_state: 'REFUNDED', // not in the booking state machine
    derivation_model: 'gec-prompt-derivation-v1',
    derivation_confidence: 0.7,
  });
  console.log(`  target_state (unusable, scope-bounding rejected): ${pdEodBad.primary_outcome.target_state}`);
  console.log(`  derivation_warnings: ${pdEodBad.derivation_warnings.join(' | ')}`);

  // -------------------------------------------------------------
  // 5. PLAN_B_ACTIVE requires plan_b_ref
  // -------------------------------------------------------------
  line('5. PLAN_B_ACTIVE state — plan_b_ref required');
  const idp4NoRef = baseIDP({
    idp_id: randomUUID(),
    step_sequence: 4,
    endorsed_eod_id,
    requested_action: 'atp:booking:suspend',
  });
  const rejectedNoRef = engine.submitIDP(idp4NoRef, binding, { plan_b_active: true });
  console.log(`  without plan_b_ref -> ok: ${rejectedNoRef.ok}, deny_code: ${rejectedNoRef.deny_code}`);

  const idp4WithRef = baseIDP({
    idp_id: randomUUID(),
    step_sequence: 4,
    endorsed_eod_id,
    requested_action: 'atp:booking:suspend',
    plan_b_ref: 'plan-b-001',
  });
  const acceptedWithRef = engine.submitIDP(idp4WithRef, binding, { plan_b_active: true });
  console.log(`  with plan_b_ref -> ok: ${acceptedWithRef.ok}`);

  // -------------------------------------------------------------
  // 6. CONFIDENCE_MISCALIBRATION_WARNING at the 10-IDP cumulative window
  // -------------------------------------------------------------
  line('6. CONFIDENCE_MISCALIBRATION_WARNING — cumulative window, >40% high-conf DENY/HEM_PENDING');
  const session2 = 'session-demo-002';
  const binding2: MandateBinding = {
    ...binding,
    mandate_id: 'mandate-jti-demo-002',
    so_id: 'so-booking-azusa-002',
    agent_class: 'CLASS_1', // isolates calibration behavior from endorsed_eod_id requirements
  };
  for (let i = 1; i <= 10; i++) {
    const idp = baseIDP({
      idp_id: randomUUID(),
      session_id: session2,
      so_id: binding2.so_id,
      mandate_id: binding2.mandate_id,
      step_sequence: i,
      confidence_level: 0.85, // all HIGH confidence
      requested_action: `atp:booking:action-${i}`,
    });
    const v = engine.submitIDP(idp, binding2, { plan_b_active: false });
    if (!v.ok) {
      throw new Error(`unexpected validation failure at i=${i}: ${v.deny_code} — ${v.detail}`);
    }
    // 5 of 10 high-confidence declarations get DENY/HEM_PENDING -> ratio 0.5 > 0.4 threshold
    if (i <= 5) {
      engine.recordDeny(idp, 'POLICY_DENY', `synthetic denial ${i}`, { note: 'demo-only' }, []);
    } else {
      engine.recordPermit(idp, 'CONFIRMED', 'PRE_ACTIVITY');
    }
  }
  console.log(`  miscalibration active for ${session2}: ${engine.isMiscalibrationActive(session2)}`);
  const warningEvent = engine.getEventLog().find((e) => e.event_type === 'CONFIDENCE_MISCALIBRATION_WARNING');
  console.log(`  event: ${JSON.stringify(warningEvent?.payload)}`);

  line('Event Log summary');
  console.log(`Total events committed: ${engine.getEventLog().length}`);
  for (const e of engine.getEventLog()) {
    console.log(`  ${e.event_type}`);
  }
}

main();
