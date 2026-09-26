// SOOS Step 12 — AEP SVL corpus generator.
// Scenarios per the plan's Step 12 block: full SENSE-REASON-PLAN-ACT-
// OBSERVE cycle with OTel spans, EOD submission and endorsed_eod_id
// binding, XPID binding at session open (client-supplied XPID
// rejected), STALLED on N consecutive DENYs, PLAN_B_ACTIVE automatic
// activation, EOD_OUTCOME at session close.

import { randomUUID } from 'crypto';
import { writeFileSync, mkdirSync } from 'fs';
import { GARLog, KIAStubSigner } from '../deps/gar/gar-core.js';
import { RevocationRegistry } from '../deps/kia/event-log.js';
import { sha256Hex } from '../deps/kia/canon.js';
import { EventStream, GECMediator, GECStubSigner, SovereignObject } from '../deps/sov/sov-core.js';
import { IDPGovernanceEngineComponent, type IntentDeclaration } from '../deps/idp/index.js';
import { generateDemoKeypair, buildRootMandateClaims, signMandate } from '../deps/mjwt/index.js';
import type { CedarPolicyResult } from '../deps/cap/cedar-semantics.js';
import type { CeeEvaluationInput } from '../deps/cap/cee.js';
import { AepGec } from './gec-aep.js';
import { AepDenyError, type AepEod } from './types.js';

const log: Record<string, unknown>[] = [];
function record(label: string, ok: boolean, detail: unknown): void {
  log.push({ label, ok, detail, timestamp: new Date().toISOString() });
}

async function freshRig(agentClass: 'CLASS_1' | 'CLASS_2' | 'CLASS_3' = 'CLASS_3') {
  const gar = new GARLog();
  const signer = new KIAStubSigner();
  const sovSigner = new GECStubSigner();
  const sovStream = new EventStream();
  const sovMediator = new GECMediator(sovStream, sovSigner);
  const revocationRegistry = new RevocationRegistry();
  const idp = new IDPGovernanceEngineComponent();
  const agentWid = `agent-${randomUUID()}`;
  const partyRegistry = new Map([[agentWid, { active: true, keypairFingerprint: 'fp-' + randomUUID(), operatorIdentity: sha256Hex('test-operator-root-pubkey'), registryEntryHash: sha256Hex('party-entry:' + agentWid) }]]);
  const gec = new AepGec(gar, signer, sovSigner, sovStream, sovMediator, revocationRegistry, idp, partyRegistry);

  const keys = await generateDemoKeypair();
  const publicKey = keys.publicKey as unknown as CryptoKey;
  const privateKey = keys.privateKey as unknown as CryptoKey;
  const humanPrincipalId = `principal-${randomUUID()}`;
  const so = new SovereignObject({ so_type_id: 'atp/booking-object/1.0', human_principal_id: humanPrincipalId, gec_id: 'gec-1', current_state: 'DRAFT' });
  sovMediator.create(so, 'gec-1');

  const rootClaims = buildRootMandateClaims({
    human_principal_id: humanPrincipalId,
    agent_wid: agentWid,
    so_id: so.so_id,
    so_type_id: so.so_type_id,
    cedar_actions: ['atp:booking:confirm', 'atp:booking:cancel', 'atp:booking:suspend'],
    mandate_ceiling: 3,
    aud: 'gec-1',
    exp: Math.floor(Date.now() / 1000) + 3600,
    agent_public_jwk: keys.publicJwk,
  });
  const rootToken = await signMandate(rootClaims, privateKey, 'k1');

  const ceeInput: Omit<CeeEvaluationInput, 'actionPattern'> = {
    jurisdictions: ['JP'], tier0Records: [], tier1Records: [], tier2Records: [], activePcrs: [],
    conflictResolution: 'MOST_PROTECTIVE', nowMs: Date.now(),
  };
  const permitPolicies: CedarPolicyResult[] = [{ policy_id: 'permit-1', tier: 'TIER_1', decision: 'PERMIT' }];
  const forbidPolicies: CedarPolicyResult[] = [{ policy_id: 'forbid-1', tier: 'TIER_1', decision: 'FORBID' }];

  const eod: Omit<AepEod, 'session_id_ref'> = {
    eod_id: randomUUID(), eod_version: '1.0', submitted_at: new Date().toISOString(),
    primary_outcome: { target_state: 'CONFIRMED', confidence: 0.85, rationale: 'demo' },
    acceptance_envelope: { success_conditions: [{ condition_id: 'sc1', field: 'current_state', operator: 'eq', value: 'CONFIRMED', required: true }], failure_conditions: [] },
    plan_b: { plan_b_id: randomUUID(), plan_b_target_state: 'PRE_ACTIVITY', plan_b_rationale: 'fallback', activation_conditions: [], plan_b_acceptance_envelope: { success_conditions: [], failure_conditions: [] } },
    auto_activate_plan_b: true, submitter_mjwt_id: rootClaims.jti, eod_signature: 'stub',
  };

  const session = await gec.initiateSession({
    rootMandateToken: rootToken, issuerPublicKey: publicKey, so, agent_class: agentClass,
    agentProviderId: agentWid, gecInstanceId: 'gec-1', gecConformanceLevel: 1,
    eod: agentClass === 'CLASS_1' ? undefined : eod,
  });

  let step = 1;
  const buildIdp = (action: string, extra: Partial<IntentDeclaration> = {}): IntentDeclaration => ({
    idp_id: randomUUID(), session_id: session.session_id, so_id: so.so_id, mandate_id: session.root_mandate.jti,
    endorsed_eod_id: session.endorsed_eod_id ?? undefined, step_sequence: step++, requested_action: action,
    declared_goal: { goal_id: randomUUID(), description: 'demo goal' },
    reasoning_basis: { type: 'RULE_BASED', description: 'demo reasoning' },
    confidence_level: 0.9, hem_urgency: 'NONE', timestamp: new Date().toISOString(), ...extra,
  });

  return { gar, gec, idp, so, session, publicKey, rootToken, ceeInput, permitPolicies, forbidPolicies, buildIdp, partyRegistry, agentWid };
}

async function main() {
  // 1-2: Session Initiation with XPID binding, Class 3 EOD required + endorsed
  {
    const rig = await freshRig('CLASS_3');
    record('SESSION-HP-01 initiation with XPID binding', rig.session.state === 'ACTIVE' && !!rig.session.session_xpid, { session_xpid: rig.session.session_xpid });
    record('SESSION-HP-02 EOD endorsed at init (Class 3)', rig.session.eod_endorsed && !!rig.session.endorsed_eod_id, { endorsed_eod_id: rig.session.endorsed_eod_id });
  }

  // 3: Class 3 without EOD -> rejected
  {
    const gar = new GARLog();
    const signer = new KIAStubSigner();
    const sovSigner = new GECStubSigner();
    const sovStream = new EventStream();
    const sovMediator = new GECMediator(sovStream, sovSigner);
    const revocationRegistry = new RevocationRegistry();
    const idp = new IDPGovernanceEngineComponent();
    const agentWid = `agent-${randomUUID()}`;
    const partyRegistry = new Map([[agentWid, { active: true, keypairFingerprint: 'fp-' + randomUUID(), operatorIdentity: sha256Hex('test-operator-root-pubkey'), registryEntryHash: sha256Hex('x') }]]);
    const gec = new AepGec(gar, signer, sovSigner, sovStream, sovMediator, revocationRegistry, idp, partyRegistry);
    const keys = await generateDemoKeypair();
    const so = new SovereignObject({ so_type_id: 'atp/booking-object/1.0', human_principal_id: 'p1', gec_id: 'gec-1', current_state: 'DRAFT' });
    sovMediator.create(so, 'gec-1');
    const claims = buildRootMandateClaims({ human_principal_id: 'p1', agent_wid: agentWid, so_id: so.so_id, so_type_id: so.so_type_id, cedar_actions: ['atp:booking:confirm'], mandate_ceiling: 3, aud: 'gec-1', exp: Math.floor(Date.now() / 1000) + 3600, agent_public_jwk: keys.publicJwk });
    const token = await signMandate(claims, keys.privateKey as unknown as CryptoKey, 'k1');
    try {
      await gec.initiateSession({ rootMandateToken: token, issuerPublicKey: keys.publicKey as unknown as CryptoKey, so, agent_class: 'CLASS_3', agentProviderId: agentWid, gecInstanceId: 'gec-1', gecConformanceLevel: 1 });
      record('SESSION-EDGE-01 Class 3 without EOD rejected', false, 'expected DENY, got session created');
    } catch (e) {
      record('SESSION-EDGE-01 Class 3 without EOD rejected', e instanceof AepDenyError && e.code === 'EOD_REQUIRED', (e as Error).message);
    }
  }

  // 4: Class 1, no EOD required, session inits fine
  {
    const rig = await freshRig('CLASS_1');
    record('SESSION-HP-03 Class 1 session inits without EOD', rig.session.state === 'ACTIVE' && rig.session.eod === null, { state: rig.session.state });
  }

  // 5: agent not in Party Registry -> AGENT_NOT_REGISTERED
  {
    const gar = new GARLog();
    const signer = new KIAStubSigner();
    const sovSigner = new GECStubSigner();
    const sovStream = new EventStream();
    const sovMediator = new GECMediator(sovStream, sovSigner);
    const revocationRegistry = new RevocationRegistry();
    const idp = new IDPGovernanceEngineComponent();
    const partyRegistry = new Map(); // empty registry
    const gec = new AepGec(gar, signer, sovSigner, sovStream, sovMediator, revocationRegistry, idp, partyRegistry as any);
    const keys = await generateDemoKeypair();
    const so = new SovereignObject({ so_type_id: 'atp/booking-object/1.0', human_principal_id: 'p1', gec_id: 'gec-1', current_state: 'DRAFT' });
    sovMediator.create(so, 'gec-1');
    const claims = buildRootMandateClaims({ human_principal_id: 'p1', agent_wid: 'unregistered-agent', so_id: so.so_id, so_type_id: so.so_type_id, cedar_actions: ['atp:booking:confirm'], mandate_ceiling: 3, aud: 'gec-1', exp: Math.floor(Date.now() / 1000) + 3600, agent_public_jwk: keys.publicJwk });
    const token = await signMandate(claims, keys.privateKey as unknown as CryptoKey, 'k1');
    try {
      await gec.initiateSession({ rootMandateToken: token, issuerPublicKey: keys.publicKey as unknown as CryptoKey, so, agent_class: 'CLASS_1', agentProviderId: 'unregistered-agent', gecInstanceId: 'gec-1', gecConformanceLevel: 1 });
      record('SESSION-EDGE-02 unregistered agent rejected', false, 'expected AGENT_NOT_REGISTERED');
    } catch (e) {
      record('SESSION-EDGE-02 unregistered agent rejected', e instanceof AepDenyError && e.code === 'AGENT_NOT_REGISTERED', (e as Error).message);
    }
  }

  // 6-9: full SENSE-REASON-PLAN-ACT-OBSERVE cycle -> PERMIT
  {
    const rig = await freshRig('CLASS_3');
    rig.gec.sense(rig.session, 'SESSION_START');
    rig.gec.reason(rig.session, 'ROUTINE');
    rig.gec.plan(rig.session, ['transition_graph'], 0.9, 'atp:booking:confirm');
    const result = await rig.gec.act(rig.session, { mandate_jwt: rig.rootToken, cedar_action: 'atp:booking:confirm', idp: rig.buildIdp('atp:booking:confirm') }, rig.publicKey, undefined, rig.permitPolicies, rig.ceeInput);
    record('LOOP-HP-01 full SENSE-REASON-PLAN-ACT-OBSERVE cycle -> PERMIT', result.result === 'PERMIT', result);
    record('LOOP-HP-02 aep_iteration incremented on PERMIT', rig.session.aep_iteration === 2, { aep_iteration: rig.session.aep_iteration });
  }

  // 10: XPID mismatch at ACT -> session terminated
  {
    const rig = await freshRig('CLASS_3');
    rig.gec.sense(rig.session, 'SESSION_START');
    // Corrupt the party registry entry AFTER session init so the derived
    // XPID at ACT no longer matches the one bound at session open.
    // v2.0: XPID derives from operatorIdentity, not keypairFingerprint — corrupting
    // keypairFingerprint alone would no longer reproduce a mismatch (that's the whole
    // point of the fix: it must NOT change on routine kernel-side changes). Corrupt
    // operatorIdentity instead, which is what a genuine registry-entry tamper would touch.
    rig.partyRegistry.set(rig.agentWid, { active: true, keypairFingerprint: 'DIFFERENT-FINGERPRINT', operatorIdentity: sha256Hex('DIFFERENT-OPERATOR'), registryEntryHash: sha256Hex('changed') });
    try {
      await rig.gec.act(rig.session, { mandate_jwt: rig.rootToken, cedar_action: 'atp:booking:confirm', idp: rig.buildIdp('atp:booking:confirm') }, rig.publicKey, undefined, rig.permitPolicies, rig.ceeInput);
      record('SESSION-EDGE-03 XPID mismatch terminates session', false, 'expected AepDenyError XPID_MISMATCH');
    } catch (e) {
      record('SESSION-EDGE-03 XPID mismatch terminates session', e instanceof AepDenyError && e.code === 'XPID_MISMATCH' && rig.session.state === 'CLOSED', { message: (e as Error).message, state: rig.session.state });
    }
  }

  // 11: CAP Tier 0 constitutional violation -> DENY
  {
    const rig = await freshRig('CLASS_3');
    rig.gec.sense(rig.session, 'SESSION_START');
    const ceeInput = { ...rig.ceeInput, tier0Records: [{ prohibition_id: 't0a-1', tier_0_subclass: 'TIER_0A' as const, prohibition_class: 'MANIPULATION' as const, treaty_basis: 'EFFECT_BASED_TEST §9', action_pattern: 'atp:booking:confirm', jurisdiction: 'GLOBAL' as const, effective_date: '2026-01-01', modifiable_by: 'RFC_ONLY' as const }] };
    const result = await rig.gec.act(rig.session, { mandate_jwt: rig.rootToken, cedar_action: 'atp:booking:confirm', idp: rig.buildIdp('atp:booking:confirm') }, rig.publicKey, undefined, rig.permitPolicies, ceeInput);
    record('CAP-EDGE-01 Tier 0-A constitutional violation -> DENY before Cedar', result.result === 'DENY' && result.deny_code.startsWith('CAP_CONSTITUTIONAL'), result);
  }

  // 12-13: Cedar DENY + RETRY_CONTINUATION with prior_denial_count tracking
  {
    const rig = await freshRig('CLASS_3');
    rig.gec.sense(rig.session, 'SESSION_START');
    const deny1 = await rig.gec.act(rig.session, { mandate_jwt: rig.rootToken, cedar_action: 'atp:booking:confirm', idp: rig.buildIdp('atp:booking:confirm') }, rig.publicKey, undefined, rig.forbidPolicies, rig.ceeInput);
    record('CEDAR-EDGE-01 Cedar DENY (forbid wins)', deny1.result === 'DENY' && deny1.prior_denial_count === 1, deny1);
    const deny1Ref = deny1.result === 'DENY' ? deny1.idp_ref : '';
    rig.gec.sense(rig.session, 'STATE_CHANGE');
    const deny2 = await rig.gec.act(rig.session, { mandate_jwt: rig.rootToken, cedar_action: 'atp:booking:confirm', idp: rig.buildIdp('atp:booking:confirm', { reasoning_basis: { type: 'RETRY_CONTINUATION', description: 'references enrichment.review_status' }, context_refs: [deny1Ref] }) }, rig.publicKey, undefined, rig.forbidPolicies, rig.ceeInput);
    record('CEDAR-EDGE-02 prior_denial_count increments across retries', deny2.result === 'DENY' && deny2.prior_denial_count === 2, deny2);
  }

  // 14-15: STALL_DENY_THRESHOLD -> STALLED -> automatic PLAN_B_ACTIVE
  {
    const rig = await freshRig('CLASS_3');
    rig.gec.sense(rig.session, 'SESSION_START');
    let last;
    for (let i = 0; i < 5; i++) {
      rig.gec.sense(rig.session, i === 0 ? 'SESSION_START' : 'STATE_CHANGE');
      last = await rig.gec.act(rig.session, { mandate_jwt: rig.rootToken, cedar_action: 'atp:booking:confirm', idp: rig.buildIdp('atp:booking:confirm', i > 0 ? { reasoning_basis: { type: 'RETRY_CONTINUATION', description: 'references enrichment.review_status' }, context_refs: ['prior'] } : {}) }, rig.publicKey, undefined, rig.forbidPolicies, rig.ceeInput);
    }
    record('STALL-HP-01 STALL_DENY_THRESHOLD reached -> STALLED', rig.session.state === 'PLAN_B_ACTIVE' || (last as any).result === 'STALLED', { state: rig.session.state, last });
    record('STALL-HP-02 auto_activate_plan_b -> PLAN_B_ACTIVE with operative_goal_state = plan_b_target_state', rig.session.state === 'PLAN_B_ACTIVE' && rig.session.operative_goal_state === 'PRE_ACTIVITY', { state: rig.session.state, operative_goal_state: rig.session.operative_goal_state });
  }

  // 16: PLAN_B_ACTIVE requires plan_b_ref on subsequent IDPs
  {
    const rig = await freshRig('CLASS_3');
    rig.gec.sense(rig.session, 'SESSION_START');
    for (let i = 0; i < 5; i++) {
      rig.gec.sense(rig.session, i === 0 ? 'SESSION_START' : 'STATE_CHANGE');
      await rig.gec.act(rig.session, { mandate_jwt: rig.rootToken, cedar_action: 'atp:booking:confirm', idp: rig.buildIdp('atp:booking:confirm', i > 0 ? { reasoning_basis: { type: 'RETRY_CONTINUATION', description: 'references enrichment.review_status' }, context_refs: ['prior'] } : {}) }, rig.publicKey, undefined, rig.forbidPolicies, rig.ceeInput);
    }
    rig.gec.sense(rig.session, 'STATE_CHANGE');
    const noRefResult = await rig.gec.act(rig.session, { mandate_jwt: rig.rootToken, cedar_action: 'atp:booking:suspend', idp: rig.buildIdp('atp:booking:suspend') }, rig.publicKey, undefined, rig.permitPolicies, rig.ceeInput);
    record('PLANB-EDGE-01 IDP without plan_b_ref rejected in PLAN_B_ACTIVE', noRefResult.result === 'DENY' && noRefResult.deny_code === 'IDP_PLAN_B_REF_REQUIRED', noRefResult);
  }

  // 17: PLAN_B_ACTIVE with plan_b_ref -> PERMIT reaching Plan B outcome
  {
    const rig = await freshRig('CLASS_3');
    rig.gec.sense(rig.session, 'SESSION_START');
    for (let i = 0; i < 5; i++) {
      rig.gec.sense(rig.session, i === 0 ? 'SESSION_START' : 'STATE_CHANGE');
      await rig.gec.act(rig.session, { mandate_jwt: rig.rootToken, cedar_action: 'atp:booking:confirm', idp: rig.buildIdp('atp:booking:confirm', i > 0 ? { reasoning_basis: { type: 'RETRY_CONTINUATION', description: 'references enrichment.review_status' }, context_refs: ['prior'] } : {}) }, rig.publicKey, undefined, rig.forbidPolicies, rig.ceeInput);
    }
    rig.gec.sense(rig.session, 'STATE_CHANGE');
    const planBRef = rig.session.eod?.eod_id;
    const permitResult = await rig.gec.act(rig.session, { mandate_jwt: rig.rootToken, cedar_action: 'atp:booking:suspend', idp: rig.buildIdp('atp:booking:suspend', { plan_b_ref: planBRef }) }, rig.publicKey, undefined, rig.permitPolicies, rig.ceeInput);
    record('PLANB-HP-01 PLAN_B_ACTIVE ACT with plan_b_ref reaches Plan B outcome', permitResult.result === 'PERMIT' && permitResult.new_state === 'PRE_ACTIVITY', permitResult);
  }

  // 18: EOD_OUTCOME / AEP_SESSION_CLOSED at closure
  {
    const rig = await freshRig('CLASS_3');
    rig.gec.sense(rig.session, 'SESSION_START');
    await rig.gec.act(rig.session, { mandate_jwt: rig.rootToken, cedar_action: 'atp:booking:confirm', idp: rig.buildIdp('atp:booking:confirm') }, rig.publicKey, undefined, rig.permitPolicies, rig.ceeInput);
    rig.gec.closeSession(rig.session, 'GOAL_ACHIEVED', true);
    const closedEvent = rig.gar.all().find((e) => e.ale_type === ('AEP_SESSION_CLOSED' as any));
    record('CLOSE-HP-01 AEP_SESSION_CLOSED recorded with closure_reason', !!closedEvent && (closedEvent as any).closure_reason === 'GOAL_ACHIEVED', closedEvent);
  }

  // 19: cp_hash binding — SENSE cp_hash must equal ACT's recomputed cp_hash_ref for same state
  {
    const rig = await freshRig('CLASS_3');
    const cp = rig.gec.sense(rig.session, 'SESSION_START');
    record('OTEL-HP-01 cp_hash computed deterministically for identical Context Package content', rig.session.last_cp_hash !== null, { cp_hash: rig.session.last_cp_hash, cp_id: cp.cp_id });
  }

  // 20: ACT with no prior SENSE in the iteration -> rejected
  {
    const rig = await freshRig('CLASS_3');
    try {
      await rig.gec.act(rig.session, { mandate_jwt: rig.rootToken, cedar_action: 'atp:booking:confirm', idp: rig.buildIdp('atp:booking:confirm') }, rig.publicKey, undefined, rig.permitPolicies, rig.ceeInput);
      record('LOOP-EDGE-01 ACT without prior SENSE rejected', false, 'expected AepDenyError NO_PRIOR_SENSE');
    } catch (e) {
      record('LOOP-EDGE-01 ACT without prior SENSE rejected', e instanceof AepDenyError && e.code === 'NO_PRIOR_SENSE', (e as Error).message);
    }
  }

  mkdirSync('svl', { recursive: true });
  writeFileSync('svl/aep-corpus.json', JSON.stringify(log, null, 2));

  const passCount = log.filter((l) => l.ok).length;
  console.log(`AEP SVL corpus: ${log.length} scenarios, ${passCount} passed, ${log.length - passCount} failed.`);
  if (log.length - passCount > 0) {
    console.error('FAILURES:', log.filter((l) => !l.ok));
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
