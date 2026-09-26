// SOOS Step 12 — AEP demo. draft-sato-soos-aep-02.
import { randomUUID } from 'crypto';
import { GARLog, KIAStubSigner } from '../deps/gar/gar-core.js';
import { RevocationRegistry } from '../deps/kia/event-log.js';
import { sha256Hex } from '../deps/kia/canon.js';
import { EventStream, GECMediator, GECStubSigner, SovereignObject } from '../deps/sov/sov-core.js';
import { IDPGovernanceEngineComponent, type IntentDeclaration } from '../deps/idp/index.js';
import { generateDemoKeypair, buildRootMandateClaims, signMandate } from '../deps/mjwt/index.js';
import type { CedarPolicyResult } from '../deps/cap/cedar-semantics.js';
import type { CeeEvaluationInput } from '../deps/cap/cee.js';
import { AepGec } from './gec-aep.js';
import type { AepEod } from './types.js';

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

async function main() {
  const gar = new GARLog();
  const signer = new KIAStubSigner();
  const sovSigner = new GECStubSigner();
  const sovStream = new EventStream();
  const sovMediator = new GECMediator(sovStream, sovSigner);
  const revocationRegistry = new RevocationRegistry();
  const idp = new IDPGovernanceEngineComponent();

  // Party Registry: agent_provider_id (here, the agent's `wid`) -> KIA entry
  const agentWid = 'agent-provider-booking-001';
  const partyRegistry = new Map([
    [agentWid, { active: true, keypairFingerprint: 'fp-' + randomUUID(), operatorIdentity: sha256Hex('myauberge-operator-root-pubkey'), registryEntryHash: sha256Hex('party-entry:' + agentWid) }],
  ]);

  const gec = new AepGec(gar, signer, sovSigner, sovStream, sovMediator, revocationRegistry, idp, partyRegistry);

  // ---------------------------------------------------------------------
  section('Setup — Root Mandate (Class 3 agent) + SO Instance');
  // ---------------------------------------------------------------------

  const keys = await generateDemoKeypair();
  const publicKey = keys.publicKey as unknown as CryptoKey;
  const privateKey = keys.privateKey as unknown as CryptoKey;
  const publicJwk = keys.publicJwk;
  const humanPrincipalId = 'principal-tom-001';
  const so = new SovereignObject({
    so_type_id: 'atp/booking-object/1.0',
    human_principal_id: humanPrincipalId,
    gec_id: 'gec-instance-001',
    current_state: 'DRAFT',
  });

  const gecInstanceId = 'gec-instance-001';
  sovMediator.create(so, gecInstanceId);

  const rootClaims = buildRootMandateClaims({
    human_principal_id: humanPrincipalId,
    agent_wid: agentWid,
    so_id: so.so_id,
    so_type_id: so.so_type_id,
    cedar_actions: ['atp:booking:confirm', 'atp:booking:cancel', 'atp:booking:suspend'],
    mandate_ceiling: 3,
    aud: gecInstanceId,
    exp: Math.floor(Date.now() / 1000) + 3600,
    agent_public_jwk: publicJwk,
  });
  const rootToken = await signMandate(rootClaims, privateKey, 'demo-key-1');

  // ---------------------------------------------------------------------
  section('1. Session Initiation (§5.1) — XPID binding + EOD submission (Class 3)');
  // ---------------------------------------------------------------------

  const eod: Omit<AepEod, 'session_id_ref'> = {
    eod_id: randomUUID(),
    eod_version: '1.0',
    submitted_at: new Date().toISOString(),
    primary_outcome: { target_state: 'CONFIRMED', confidence: 0.85, rationale: 'Standard booking confirmation flow.' },
    acceptance_envelope: {
      success_conditions: [{ condition_id: 'sc-1', field: 'current_state', operator: 'eq', value: 'CONFIRMED', required: true }],
      failure_conditions: [{ condition_id: 'fc-1', field: 'current_state', operator: 'eq', value: 'CANCELLED', required: true }],
    },
    plan_b: {
      plan_b_id: randomUUID(),
      plan_b_target_state: 'PRE_ACTIVITY',
      plan_b_rationale: 'If confirmation is repeatedly denied, fall back to holding the booking in pre-activity review rather than losing it entirely.',
      activation_conditions: [{ condition_id: 'ac-1', field: 'consecutive_denies', operator: 'gte', value: 5, required: true }],
      plan_b_acceptance_envelope: {
        success_conditions: [{ condition_id: 'pb-sc-1', field: 'current_state', operator: 'eq', value: 'PRE_ACTIVITY', required: true }],
        failure_conditions: [],
      },
    },
    auto_activate_plan_b: true,
    submitter_mjwt_id: rootClaims.jti,
    eod_signature: 'stub-signature',
  };

  const session = await gec.initiateSession({
    rootMandateToken: rootToken,
    issuerPublicKey: publicKey,
    so,
    agent_class: 'CLASS_3',
    agentProviderId: agentWid,
    gecInstanceId,
    gecConformanceLevel: 1,
    eod,
  });
  console.log('Session initiated:', { session_id: session.session_id, session_xpid: session.session_xpid, state: session.state });

  const ceeInput: Omit<CeeEvaluationInput, 'actionPattern'> = {
    jurisdictions: ['JP'],
    tier0Records: [],
    tier1Records: [],
    tier2Records: [],
    activePcrs: [],
    conflictResolution: 'MOST_PROTECTIVE',
    nowMs: Date.now(),
  };
  const permitPolicies: CedarPolicyResult[] = [{ policy_id: 'allow-confirm', tier: 'TIER_1', decision: 'PERMIT' }];
  const forbidPolicies: CedarPolicyResult[] = [{ policy_id: 'forbid-confirm-review-pending', tier: 'TIER_1', decision: 'FORBID' }];

  let stepSeq = 1;
  function buildIdp(action: string, extra: Partial<IntentDeclaration> = {}): IntentDeclaration {
    return {
      idp_id: randomUUID(),
      session_id: session.session_id,
      so_id: so.so_id,
      mandate_id: session.root_mandate.jti,
      endorsed_eod_id: session.endorsed_eod_id ?? undefined,
      step_sequence: stepSeq++,
      requested_action: action,
      declared_goal: { goal_id: randomUUID(), description: 'Confirm the booking per the EOD primary outcome.' },
      reasoning_basis: { type: 'RULE_BASED', description: 'Standard confirmation path, no prior denial.' },
      confidence_level: 0.9,
      hem_urgency: 'NONE',
      timestamp: new Date().toISOString(),
      ...extra,
    };
  }

  // ---------------------------------------------------------------------
  section('2. SENSE (SESSION_START) + REASON + PLAN');
  // ---------------------------------------------------------------------

  gec.sense(session, 'SESSION_START');
  gec.reason(session, 'ROUTINE');
  gec.plan(session, ['transition_graph'], 0.9, 'atp:booking:confirm');

  // ---------------------------------------------------------------------
  section('3. ACT — Transition Request -> PERMIT');
  // ---------------------------------------------------------------------

  const permitResult = await gec.act(
    session,
    { mandate_jwt: rootToken, cedar_action: 'atp:booking:confirm', idp: buildIdp('atp:booking:confirm') },
    publicKey,
    undefined,
    permitPolicies,
    ceeInput,
  );
  console.log('ACT result:', permitResult);

  // ---------------------------------------------------------------------
  section('4. DENY + RETRY_CONTINUATION');
  // ---------------------------------------------------------------------

  gec.sense(session, 'STATE_CHANGE');
  const denyResult = await gec.act(
    session,
    { mandate_jwt: rootToken, cedar_action: 'atp:booking:confirm', idp: buildIdp('atp:booking:confirm') },
    publicKey,
    undefined,
    forbidPolicies,
    ceeInput,
  );
  console.log('DENY result:', denyResult);

  gec.sense(session, 'STATE_CHANGE');
  const retryResult = await gec.act(
    session,
    {
      mandate_jwt: rootToken,
      cedar_action: 'atp:booking:confirm',
      idp: buildIdp('atp:booking:confirm', {
        reasoning_basis: {
          type: 'RETRY_CONTINUATION',
          description: 'Retrying after review — references enrichment.review_status per the prior DENY.',
        },
        context_refs: [denyResult.result === 'DENY' ? denyResult.idp_ref : ''],
      }),
    },
    publicKey,
    undefined,
    forbidPolicies,
    ceeInput,
  );
  console.log('RETRY_CONTINUATION result:', retryResult);

  // ---------------------------------------------------------------------
  section('5. Drive to STALL_DENY_THRESHOLD -> STALLED -> automatic Plan B activation');
  // ---------------------------------------------------------------------

  let last;
  for (let i = 0; i < 4; i++) {
    gec.sense(session, 'STATE_CHANGE');
    last = await gec.act(
      session,
      { mandate_jwt: rootToken, cedar_action: 'atp:booking:confirm', idp: buildIdp('atp:booking:confirm', {
        reasoning_basis: { type: 'RETRY_CONTINUATION', description: `Retry ${i + 3} — still references enrichment.review_status.` },
        context_refs: ['prior'],
      }) },
      publicKey,
      undefined,
      forbidPolicies,
      ceeInput,
    );
  }
  console.log('Final result after repeated DENYs:', last);
  console.log('Session state:', session.state, '| operative_goal_state:', session.operative_goal_state, '| plan_b_activated:', session.plan_b_activated);

  // ---------------------------------------------------------------------
  section('5b. PLAN_B_ACTIVE — ACT with plan_b_ref -> reach Plan B outcome');
  // ---------------------------------------------------------------------

  gec.sense(session, 'STATE_CHANGE');
  const planBResult = await gec.act(
    session,
    {
      mandate_jwt: rootToken,
      cedar_action: 'atp:booking:suspend', // Plan B target: PRE_ACTIVITY
      idp: buildIdp('atp:booking:suspend', {
        plan_b_ref: session.eod?.eod_id,
        declared_goal: { goal_id: randomUUID(), description: 'Hold booking in pre-activity review per activated Plan B.' },
        reasoning_basis: { type: 'MISSION_STAGE', description: 'Executing pre-declared Plan B after primary path exhausted.' },
      }),
    },
    publicKey,
    undefined,
    permitPolicies, // Plan B path is permitted
    ceeInput,
  );
  console.log('Plan B ACT result:', planBResult);

  // ---------------------------------------------------------------------
  section('6. Session Closure');
  // ---------------------------------------------------------------------

  const planBAchieved = planBResult.result === 'PERMIT' && planBResult.new_state === session.eod?.plan_b?.plan_b_target_state;
  gec.closeSession(session, planBAchieved ? 'PLAN_B_ACHIEVED' : 'STALL_TIMEOUT', planBAchieved);

  // ---------------------------------------------------------------------
  section('Summary');
  // ---------------------------------------------------------------------
  console.log(`GAR entries recorded: ${gar.all().length}`);
  console.log(`IDP event log entries: ${idp.getEventLog().length}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
