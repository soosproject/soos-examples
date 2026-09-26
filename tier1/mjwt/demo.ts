/**
 * MJWT demo — draft-sato-soos-mjwt-02
 * Run: tsx tier1/mjwt/demo.ts
 *
 * Scenario data drawn from svl/corpus-b/mjwt/happy-path.json (H-01..H-04, H-20)
 * and edge-cases.json (E-02, E-10, E-16), and MJWT-02 Appendix A.
 */
import {
  buildRootMandateClaims,
  issueChildMandate,
  signMandate,
  verifyMandate,
  generateDemoKeypair,
  type MJWTClaims,
  type GECVerificationContext,
  type ConsentScope,
} from './index';

function line(title: string) {
  console.log(`\n--- ${title} ---`);
}

async function main() {
  // STUB: HMAC/GEC key management. Production: derived from KIA Governance
  // Identity Keypair (KEE-1 P2). Two separate keypairs here: one for the
  // human principal (Root Mandate issuer) and one for the GEC (Child Mandate issuer).
  const humanKeys = await generateDemoKeypair();
  const gecKeys = await generateDemoKeypair();
  const agentKeys = await generateDemoKeypair();
  const subAgentKeys = await generateDemoKeypair();

  const consentScope: ConsentScope = {
    data_subject_id: 'ps-hp-001-sha256-truncated',
    consent_reference: 'https://consent.myauberge.jp/records/c-2026-001',
    consent_timestamp: '2026-06-15T08:00:00Z',
    consenting_party: 'SELF',
    purpose_codes: ['BOOKING', 'AI_AGENT_OPERATION'],
    data_categories: ['contact', 'travel_preference'],
    jurisdiction: 'JP',
    governing_law: 'APPI:2003:Art17',
    expiry: '2099-08-15T08:00:00Z', // far future so the happy-path demo doesn't hit MJWT_CONSENT_EXPIRED
    sub_agent_scope: 'RESTRICT',
  };

  // --- H-01 / H-02: Root Mandate issuance + full verification -------------
  line('H-01: Root Mandate issuance (hp-001 -> ota-booking-agent-v2)');
  const gecInstanceId = 'kernel-fp:myauberge-gec-001';
  const rootClaims: MJWTClaims = buildRootMandateClaims({
    human_principal_id: 'hp-001',
    agent_wid: 'wimse:agent:ota-booking-agent-v2',
    so_id: '019547ab-1234-7abc-8def-000000000099',
    so_type_id: 'atp/booking-object/1.0',
    cedar_actions: ['atp:booking:confirm', 'atp:booking:cancel', 'atp:booking:suspend'],
    mandate_ceiling: 2,
    aud: gecInstanceId,
    exp: Math.floor(Date.now() / 1000) + 86400,
    permitted_states: ['CONFIRMED', 'PRE_ACTIVITY', 'IN_JOURNEY'],
    permitted_phases: ['ACTIVE'],
    mission_ref: 'mission-uuid-azusa-journey-2026-06-15',
    consent_scope: consentScope,
    agent_public_jwk: agentKeys.publicJwk,
  });
  const rootToken = await signMandate(rootClaims, humanKeys.privateKey, 'hp-001-ed25519-key-1');
  console.log(`jti: ${rootClaims.jti}`);
  console.log(`cedar_actions: ${rootClaims.cedar_actions.join(', ')}`);
  console.log(`sub_agent_scope: ${rootClaims.sub_agent_scope}`);

  line('H-02: GEC verifies Root Mandate — all 13 steps');
  const rootCtx: GECVerificationContext = {
    gec_instance_id: gecInstanceId,
    gec_conformance_level: 2,
    so_current_state: 'IN_JOURNEY',
    so_current_phase: 'ACTIVE',
    so_human_principal_id: 'hp-001',
    requested_cedar_action: 'atp:booking:suspend',
    idp_mission_ref: 'mission-uuid-azusa-journey-2026-06-15',
    cedar_policy_requires_consent: true,
    cedar_policy_purpose_code: 'BOOKING',
    revoked_jtis: new Set(),
  };
  const rootResult = await verifyMandate(rootToken, humanKeys.publicKey, rootCtx);
  console.log(`Result: ${rootResult.ok ? 'PERMIT' : `DENY (${rootResult.deny_code})`}`);

  // --- H-03 / H-04: Child Mandate — narrowed, verified with Narrowing Property
  line('H-03: Child Mandate issuance (GEC -> weather-monitor-agent-v1), narrowed');
  const childClaims = issueChildMandate({
    parent: rootClaims,
    issuer_gec_id: 'gec-myauberge-001',
    agent_wid: 'wimse:agent:weather-monitor-agent-v1',
    agent_public_jwk: subAgentKeys.publicJwk,
    cedar_actions: ['atp:booking:suspend'],
    exp: rootClaims.exp - 43200, // earlier than parent — dimension (e)
    permitted_states: ['IN_JOURNEY'],
    permitted_phases: ['ACTIVE'],
    consent_scope: { ...consentScope, purpose_codes: ['BOOKING'], data_categories: [], sub_agent_scope: 'NONE' },
    sub_agent_scope: 'NONE', // narrowed from parent's RESTRICT — permitted per §5.2(g)
  });
  const childToken = await signMandate(childClaims, gecKeys.privateKey, 'gec-myauberge-001-key-1');
  console.log(`parent_mandate_id: ${childClaims.parent_mandate_id}`);
  console.log(`delegation_chain length: ${childClaims.delegation_chain?.length}`);
  console.log(`sub_agent_scope narrowed: RESTRICT -> ${childClaims.sub_agent_scope}`);

  line('H-04 / H-20: GEC verifies Child Mandate — Narrowing Property + consent Step 13');
  const childCtx: GECVerificationContext = {
    ...rootCtx,
    so_current_state: 'IN_JOURNEY',
  };
  const childResult = await verifyMandate(childToken, gecKeys.publicKey, childCtx, rootClaims);
  console.log(`Result: ${childResult.ok ? 'PERMIT' : `DENY (${childResult.deny_code})`}`);

  // --- E-10: NARROWING_VIOLATION — attempted authority expansion ----------
  line('E-10: NARROWING_VIOLATION — child attempts a cedar_action outside parent scope');
  try {
    issueChildMandate({
      parent: rootClaims,
      issuer_gec_id: 'gec-myauberge-001',
      agent_wid: 'wimse:agent:rogue-sub-agent',
      agent_public_jwk: subAgentKeys.publicJwk,
      cedar_actions: ['atp:booking:confirm', 'atp:booking:delete_forever'], // not in parent's cedar_actions
      exp: rootClaims.exp,
    });
    console.log('UNEXPECTED: issuance succeeded');
  } catch (e) {
    console.log(`Rejected at issuance: ${(e as Error).message}`);
  }

  // --- E-02: MJWT_ALG_INVALID — alg:none bypass attempt -------------------
  line('E-02: MJWT_ALG_INVALID — forged alg:none token, must fail at Step 2, before Step 3');
  const forgedHeader = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url');
  const forgedPayload = Buffer.from(JSON.stringify({ ...rootClaims })).toString('base64url');
  const forgedToken = `${forgedHeader}.${forgedPayload}.`;
  const forgedResult = await verifyMandate(forgedToken, humanKeys.publicKey, rootCtx);
  console.log(`Result: ${forgedResult.ok ? 'PERMIT' : `DENY (${forgedResult.deny_code}) at step ${forgedResult.failed_step}`}`);

  // --- E-16: MJWT_CONSENT_ABSENT — consent_scope missing ------------------
  line('E-16: MJWT_CONSENT_ABSENT — Cedar policy requires consent, MJWT carries none');
  const noConsentParams: Parameters<typeof buildRootMandateClaims>[0] = {
    human_principal_id: 'hp-001',
    agent_wid: 'wimse:agent:ota-booking-agent-v2',
    so_id: rootClaims.so_id,
    so_type_id: rootClaims.so_type_id,
    cedar_actions: rootClaims.cedar_actions,
    mandate_ceiling: 2,
    aud: gecInstanceId,
    exp: rootClaims.exp,
    permitted_states: rootClaims.permitted_states,
    permitted_phases: rootClaims.permitted_phases,
    agent_public_jwk: agentKeys.publicJwk,
    // consent_scope intentionally omitted
  };
  const noConsentClaims = buildRootMandateClaims(noConsentParams);
  const noConsentToken = await signMandate(noConsentClaims, humanKeys.privateKey, 'hp-001-ed25519-key-1');
  const noConsentResult = await verifyMandate(noConsentToken, humanKeys.publicKey, rootCtx);
  console.log(`Result: ${noConsentResult.ok ? 'PERMIT' : `DENY (${noConsentResult.deny_code}) — ${noConsentResult.detail}`}`);

  console.log('\nDemo complete. Full happy-path (20) and edge-case (21) corpora: svl/corpus-b/mjwt/');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
