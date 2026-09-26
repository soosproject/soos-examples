// SOOS ACD demo. draft-sato-soos-acd-01.
import { randomUUID } from 'crypto';
import { GARLog } from '../deps/gar/gar-core.js';
import { AcdGec } from './gec-acd.js';
import { AcdTrustHierarchy, deriveTrustLevel, RESOURCE_CLASS_ACCESS } from './trust-hierarchy.js';
import type { AcdRecordBody, AuditPrincipalCredential, FourCheckInputs, GecManifestTrustFields, VeaCredential } from './types.js';
import { issueGecManifest } from '../deps/kia/manifest.js';
import { frostConstraintString } from '../deps/kia/types.js';
import type { FourCheckInputsV2 } from './four-check-v2.js';
import nacl from 'tweetnacl';

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

const gar = new GARLog();
const acd = new AcdGec(gar);

const bodyBuilder = (acd_session_id: string): Omit<AcdRecordBody, 'acd_session_id'> => ({
  agent_xpid: 'xpid:myauberge:booking-agent-01',
  governing_law: 'Japanese Civil Code and APPI Law No. 57 of 2003',
  primary_jurisdiction: 'JP',
  jurisdictions: [{ jurisdiction_code: 'JP', regulatory_regime: ['APPI', 'AI-Agent-Governance-v1'], ptd_endpoint: 'https://kernel.myauberge.jp/ptd/jp' }],
  terms_of_use_uri: 'https://myauberge.jp/terms',
  liability_scope: 'OPERATOR',
  acd_validity_not_before: new Date().toISOString(),
  acd_validity_not_after: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
  cap_profile_id: 'myauberge-k.k.-japan-v2.3.1',
  cap_profile_hash: 'a04a1f3fff1fa07e998e86f7f7a27ae3',
  prohibition_tier_summary: { tier_0a: 5, tier_0b: 4, tier_1: 12, tier_2: 3 },
  gec_manifest_ref: 'manifest:myauberge:v3',
  cedar_policy_hash: 'cedar-hash-stub',
  cap_enforcement_attestation: 'https://kernel.myauberge.jp/kia/attestation/v3',
  hem_status: 'ACTIVE',
  ptd_endpoint: 'https://kernel.myauberge.jp/ptd/jp',
  operator_id: 'urn:soos:kia:myauberge-k.k.:jp:v3',
  principal_hierarchy_summary: 'Two-tier: Operator (MyAuberge K.K.) -> User Principal',
  redress_uri: 'https://myauberge.jp/agent-redress',
  human_escalation_path: 'AVAILABLE',
  gar_audit_endpoint: 'https://kernel.myauberge.jp/gar/audit',
  acd_timestamp: new Date().toISOString(),
  delegation_chain_depth: 0,
  parent_kernel_id: null,
  mandate_scope_type: 'FULL',
  mjwt_jti: randomUUID(),
});

const passingChecks: FourCheckInputs = {
  manifestCurrentAndUnrevoked: true,
  cedarPolicyHashIsFresh: true,
  kiaSigningKeyRevoked: false,
  agentXpidRevokedOrCaepSignaled: false,
};

section('1. Successful compliance handshake');
const result = acd.handleQuery({ resource_provider_id: 'kia:ponyhouse.farm:supplier-agent-01', requested_at: new Date().toISOString() }, passingChecks, bodyBuilder, (body) => `ed25519-stub-sig:${body.length}`);
console.log({ ok: result.ok, acd_session_id: result.record?.acd_session_id, record_hash: result.record_hash });

section('2. Four-check failure (Check 3: KIA signing key revoked)');
const failResult = acd.handleQuery(
  { resource_provider_id: 'kia:ponyhouse.farm:supplier-agent-01', requested_at: new Date().toISOString() },
  { ...passingChecks, kiaSigningKeyRevoked: true },
  bodyBuilder,
  (body) => `ed25519-stub-sig:${body.length}`,
);
console.log(failResult.error);

section('3. Resource-provider-side validation of the successful record');
if (result.record) {
  const validation = acd.validateAsResourceProvider(result.record, () => true, result.record.agent_xpid, 'JP');
  console.log(validation);
}

section('4. Trust Hierarchy — trust level derivation (§8.1)');

const standardManifest: GecManifestTrustFields = { conformance_level: 'L1', cap_enforcement_attestation_is_tee_backed: false, hardware_attestation_chain_to_deployment_authority: false };
const elevatedManifest: GecManifestTrustFields = { conformance_level: 'L2', frost_threshold: 'frost:t-of-n:2-3', cap_enforcement_attestation_is_tee_backed: true, hardware_attestation_chain_to_deployment_authority: false };
const governmentManifest: GecManifestTrustFields = { conformance_level: 'L3', hardware_attestation_chain_to_deployment_authority: true, publisher_key_scheme: '2-of-3: Digital Agency + IPA + operator', national_deployment_profile: 'Japan Deployment Profile', cap_enforcement_attestation_is_tee_backed: true };

for (const [label, manifest] of [['STANDARD deployment', standardManifest], ['ELEVATED deployment', elevatedManifest], ['GOVERNMENT deployment', governmentManifest]] as const) {
  const level = deriveTrustLevel(manifest);
  console.log(`${label} -> ${level}, may access: ${RESOURCE_CLASS_ACCESS[level].join(', ')}`);
}

section('5. Audit Principal access (§8.2)');

const trustHierarchy = new AcdTrustHierarchy(gar);
if (result.record) {
  const auditCred: AuditPrincipalCredential = { principal_id: 'kia:ponyhouse.farm:compliance-team', principal_kind: 'RESOURCE_PROVIDER', credential_token: 'stub-token' };
  const grant = trustHierarchy.authenticateAuditPrincipal(result.record, auditCred, () => true);
  console.log(grant);
}

section('6. Verified External Auditor access (§8.3) — full Audit Package scope');

if (result.record) {
  const veaCred: VeaCredential = { auditor_id: 'vea:deloitte-tohmatsu:audit-001', accrediting_authority: 'Japan FSA-designated VEA program', credential_token: 'stub-vea-token' };
  const veaGrant = trustHierarchy.authenticateVea(result.record, veaCred, () => true);
  console.log(veaGrant);
}

section('7. Four-check sequence rebuilt against KEE-1 §4.3 (handleQueryV2)');

const kernelKeypair = nacl.sign.keyPair();
const frostManifest = issueGecManifest({
  kernelKeypair,
  operatorIdentity: 'sha256:operator-stub',
  hardwareBacked: true,
  ptdEndpoint: 'https://ponyhouse.farm/ptd/jp',
  ptdCurrentVersion: '1.0',
  kernelVersion: '3.2.0',
  loadedPolicyIds: ['cap-profile-v1'],
  cedarPolicyHash: 'active-policy-hash-abc123',
  deploymentConstraints: [frostConstraintString({ threshold: 2, participants: 3 })],
  implementsXpid: true,
  kernelVersionDate: '2026-06-01',
  kernelImplementerId: 'ponyhouse-farm-internal',
});

const acdV2 = new AcdGec(gar);
const v2Checks: FourCheckInputsV2 = {
  manifest: frostManifest,
  kernelPublicKey: kernelKeypair.publicKey,
  manifestRevoked: false,
  activeCedarPolicyHash: 'active-policy-hash-abc123',
  claimedCedarPolicyHash: 'active-policy-hash-abc123',
  kiaSigningKeyRevoked: false, // irrelevant — this manifest uses FROST
  frostThresholdKeyRevoked: false,
  agentXpidRevokedOrCaepSignaled: false,
};
const v2Result = acdV2.handleQueryV2({ resource_provider_id: 'provider-01', requested_at: new Date().toISOString() }, v2Checks, bodyBuilder, (b) => `ed25519-stub-sig:${b.length}`);
console.log({ ok: v2Result.ok, acd_session_id: v2Result.record?.acd_session_id, usesFrost: true });

section('8. handleQueryV2 — FROST threshold key revoked (KEE-1 Check 3 FROST path, dropped from ACD-01\'s own restatement)');

const v2FrostFail = acdV2.handleQueryV2(
  { resource_provider_id: 'provider-01', requested_at: new Date().toISOString() },
  { ...v2Checks, frostThresholdKeyRevoked: true },
  bodyBuilder,
  (b) => `ed25519-stub-sig:${b.length}`,
);
console.log(v2FrostFail.error);

section('Summary');
console.log(`GAR entries recorded: ${gar.all().length}`);
