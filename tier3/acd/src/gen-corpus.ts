// SOOS ACD SVL corpus generator.
import { randomUUID } from 'crypto';
import { writeFileSync, mkdirSync } from 'fs';
import { GARLog } from '../deps/gar/gar-core.js';
import { AcdGec } from './gec-acd.js';
import { AcdTrustHierarchy, deriveTrustLevel } from './trust-hierarchy.js';
import type { AcdRecordBody, AuditPrincipalCredential, FourCheckInputs, GecManifestTrustFields, VeaCredential } from './types.js';
import { issueGecManifest } from '../deps/kia/manifest.js';
import { frostConstraintString } from '../deps/kia/types.js';
import type { FourCheckInputsV2 } from './four-check-v2.js';
import nacl from 'tweetnacl';

const gar = new GARLog();
const acd = new AcdGec(gar);
const log: Record<string, unknown>[] = [];
function record(label: string, ok: boolean, detail: unknown): void {
  log.push({ label, ok, detail, timestamp: new Date().toISOString() });
}

const passingChecks: FourCheckInputs = {
  manifestCurrentAndUnrevoked: true,
  cedarPolicyHashIsFresh: true,
  kiaSigningKeyRevoked: false,
  agentXpidRevokedOrCaepSignaled: false,
};

function bodyBuilder(overrides: Partial<Omit<AcdRecordBody, 'acd_session_id'>> = {}) {
  return (_acd_session_id: string): Omit<AcdRecordBody, 'acd_session_id'> => ({
    agent_xpid: 'xpid:demo:agent-01',
    governing_law: 'Demo Law',
    primary_jurisdiction: 'JP',
    jurisdictions: [{ jurisdiction_code: 'JP', regulatory_regime: ['APPI'], ptd_endpoint: 'https://demo/ptd/jp' }],
    terms_of_use_uri: 'https://demo/terms',
    liability_scope: 'OPERATOR',
    acd_validity_not_before: new Date(Date.now() - 1000).toISOString(),
    acd_validity_not_after: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
    cap_profile_id: 'demo-profile-v1',
    cap_profile_hash: 'hash-stub',
    prohibition_tier_summary: { tier_0a: 1, tier_0b: 1, tier_1: 1, tier_2: 1 },
    gec_manifest_ref: 'manifest:demo',
    cedar_policy_hash: 'cedar-hash-stub',
    cap_enforcement_attestation: 'https://demo/attestation',
    hem_status: 'ACTIVE',
    ptd_endpoint: 'https://demo/ptd/jp',
    operator_id: 'urn:soos:kia:demo:jp:v1',
    principal_hierarchy_summary: 'Single-tier',
    redress_uri: 'https://demo/redress',
    human_escalation_path: 'AVAILABLE',
    gar_audit_endpoint: 'https://demo/gar/audit',
    acd_timestamp: new Date().toISOString(),
    delegation_chain_depth: 0,
    parent_kernel_id: null,
    mandate_scope_type: 'FULL',
    mjwt_jti: randomUUID(),
    ...overrides,
  });
}

const signer = (body: string) => `ed25519-stub-sig:${body.length}`;

// 1: happy path handshake
{
  const result = acd.handleQuery({ resource_provider_id: 'provider-01', requested_at: new Date().toISOString() }, passingChecks, bodyBuilder(), signer);
  record('ACD-HP-01 successful handshake issues record + acd_session_id', result.ok && !!result.record?.acd_session_id, { ok: result.ok, session: result.record?.acd_session_id });
}

// 2: record body never stored, only hash (data minimization ALE-057)
{
  const result = acd.handleQuery({ resource_provider_id: 'provider-01', requested_at: new Date().toISOString() }, passingChecks, bodyBuilder(), signer);
  const issuedEntry = gar.all().find((e: any) => e.ale_type === 'ACD_RECORD_ISSUED' && e.acd_session_id === result.record?.acd_session_id);
  record('ACD-HP-02 ALE-057 stores only record_hash, not full body', !!issuedEntry && (issuedEntry as any).record_hash === result.record_hash && !('agent_xpid' in (issuedEntry as any)), issuedEntry);
}

// 3-6: four-check failures, one per check
const checkFailureCases: [string, Partial<FourCheckInputs>, 1 | 2 | 3 | 4][] = [
  ['manifest not current/unrevoked', { manifestCurrentAndUnrevoked: false }, 1],
  ['cedar policy hash stale', { cedarPolicyHashIsFresh: false }, 2],
  ['KIA signing key revoked', { kiaSigningKeyRevoked: true }, 3],
  ['agent XPID revoked/CAEP signaled', { agentXpidRevokedOrCaepSignaled: true }, 4],
];
for (const [label, override, expectedCheck] of checkFailureCases) {
  const result = acd.handleQuery({ resource_provider_id: 'provider-01', requested_at: new Date().toISOString() }, { ...passingChecks, ...override }, bodyBuilder(), signer);
  record(`ACD-EDGE-0${expectedCheck} four-check failure: ${label}`, !result.ok && result.error?.failed_check === expectedCheck, result.error);
}

// 7: resource-provider-side validation happy path
{
  const result = acd.handleQuery({ resource_provider_id: 'provider-01', requested_at: new Date().toISOString() }, passingChecks, bodyBuilder(), signer);
  const validation = acd.validateAsResourceProvider(result.record!, () => true, result.record!.agent_xpid, 'JP');
  record('ACD-HP-03 resource-provider-side validation passes', validation.ok, validation);
}

// 8: provider-side validation — signature failure
{
  const result = acd.handleQuery({ resource_provider_id: 'provider-01', requested_at: new Date().toISOString() }, passingChecks, bodyBuilder(), signer);
  const validation = acd.validateAsResourceProvider(result.record!, () => false, result.record!.agent_xpid, 'JP');
  record('ACD-EDGE-05 provider-side signature verification failure', !validation.ok && validation.failedStep === 1, validation);
}

// 9: provider-side validation — XPID mismatch
{
  const result = acd.handleQuery({ resource_provider_id: 'provider-01', requested_at: new Date().toISOString() }, passingChecks, bodyBuilder(), signer);
  const validation = acd.validateAsResourceProvider(result.record!, () => true, 'xpid:different-kernel', 'JP');
  record('ACD-EDGE-06 provider-side XPID mismatch', !validation.ok && validation.failedStep === 2, validation);
}

// 10: provider-side validation — jurisdiction not covered
{
  const result = acd.handleQuery({ resource_provider_id: 'provider-01', requested_at: new Date().toISOString() }, passingChecks, bodyBuilder(), signer);
  const validation = acd.validateAsResourceProvider(result.record!, () => true, result.record!.agent_xpid, 'DE');
  record('ACD-EDGE-07 provider-side jurisdiction not covered', !validation.ok && validation.failedStep === 4, validation);
}

// 11: expired validity window
{
  const result = acd.handleQuery(
    { resource_provider_id: 'provider-01', requested_at: new Date().toISOString() },
    passingChecks,
    bodyBuilder({ acd_validity_not_after: new Date(Date.now() - 1000).toISOString() }),
    signer,
  );
  const validation = acd.validateAsResourceProvider(result.record!, () => true, result.record!.agent_xpid, 'JP');
  record('ACD-EDGE-08 expired acd_validity_not_after rejected', !validation.ok && validation.failedStep === 3, validation);
}

// 12: trust level derivation — STANDARD (baseline L1, no extras)
{
  const manifest: GecManifestTrustFields = { conformance_level: 'L1', cap_enforcement_attestation_is_tee_backed: false, hardware_attestation_chain_to_deployment_authority: false };
  const level = deriveTrustLevel(manifest);
  record('ACD-HP-04 trust level derivation — STANDARD baseline', level === 'STANDARD', { level });
}

// 13: trust level derivation — ELEVATED (L2 + FROST + TEE attestation)
{
  const manifest: GecManifestTrustFields = { conformance_level: 'L2', frost_threshold: 'frost:t-of-n:2-3', cap_enforcement_attestation_is_tee_backed: true, hardware_attestation_chain_to_deployment_authority: false };
  const level = deriveTrustLevel(manifest);
  record('ACD-HP-05 trust level derivation — ELEVATED (FROST + TEE)', level === 'ELEVATED', { level });
}

// 14: trust level derivation — L2 without FROST falls through to STANDARD, not ELEVATED
{
  const manifest: GecManifestTrustFields = { conformance_level: 'L2', cap_enforcement_attestation_is_tee_backed: true, hardware_attestation_chain_to_deployment_authority: false };
  const level = deriveTrustLevel(manifest);
  record('ACD-EDGE-09 L2 without frost_threshold falls through to STANDARD (not ELEVATED)', level === 'STANDARD', { level });
}

// 15: trust level derivation — GOVERNMENT (L3 + hardware chain + 2-of-3 publisher key + national profile)
{
  const manifest: GecManifestTrustFields = { conformance_level: 'L3', hardware_attestation_chain_to_deployment_authority: true, publisher_key_scheme: '2-of-3: Digital Agency + IPA + operator', national_deployment_profile: 'Japan Deployment Profile', cap_enforcement_attestation_is_tee_backed: true };
  const level = deriveTrustLevel(manifest);
  record('ACD-HP-06 trust level derivation — GOVERNMENT (full chain)', level === 'GOVERNMENT', { level });
}

// 16: trust level derivation — L3 without hardware attestation chain falls through, not GOVERNMENT
{
  const manifest: GecManifestTrustFields = { conformance_level: 'L3', hardware_attestation_chain_to_deployment_authority: false, publisher_key_scheme: '2-of-3', national_deployment_profile: 'Japan Deployment Profile', cap_enforcement_attestation_is_tee_backed: true };
  const level = deriveTrustLevel(manifest);
  record('ACD-EDGE-10 L3 without hardware_attestation_chain falls through (not GOVERNMENT)', level !== 'GOVERNMENT', { level });
}

// 17: Audit Principal access granted
{
  const result = acd.handleQuery({ resource_provider_id: 'provider-01', requested_at: new Date().toISOString() }, passingChecks, bodyBuilder(), signer);
  const trustHierarchy = new AcdTrustHierarchy(gar);
  const cred: AuditPrincipalCredential = { principal_id: 'internal-audit-01', principal_kind: 'INTERNAL_AUDIT_TEAM', credential_token: 'tok' };
  const grant = trustHierarchy.authenticateAuditPrincipal(result.record!, cred, () => true);
  record('ACD-HP-07 Audit Principal access granted -> SESSION_LEVEL scope', grant?.scope === 'SESSION_LEVEL' && !grant.includes_merkle_proof_access, grant);
}

// 18: Audit Principal access denied -> null grant, still logged
{
  const result = acd.handleQuery({ resource_provider_id: 'provider-01', requested_at: new Date().toISOString() }, passingChecks, bodyBuilder(), signer);
  const trustHierarchy = new AcdTrustHierarchy(gar);
  const cred: AuditPrincipalCredential = { principal_id: 'unverified-01', principal_kind: 'REGULATOR', credential_token: 'bad-tok' };
  const grant = trustHierarchy.authenticateAuditPrincipal(result.record!, cred, () => false);
  const loggedEntry = gar.all().find((e: any) => e.ale_type === 'ACD_HUMAN_QUERY' && e.principal_id === 'unverified-01');
  record('ACD-EDGE-11 Audit Principal access denied -> null grant, still logged (ALE-061)', grant === null && !!loggedEntry && (loggedEntry as any).granted === false, { grant, loggedEntry });
}

// 19: VEA access granted -> FULL_AUDIT_PACKAGE with all scope extras
{
  const result = acd.handleQuery({ resource_provider_id: 'provider-01', requested_at: new Date().toISOString() }, passingChecks, bodyBuilder(), signer);
  const trustHierarchy = new AcdTrustHierarchy(gar);
  const cred: VeaCredential = { auditor_id: 'vea-01', accrediting_authority: 'operator', credential_token: 'tok' };
  const grant = trustHierarchy.authenticateVea(result.record!, cred, () => true);
  record('ACD-HP-08 VEA access granted -> FULL_AUDIT_PACKAGE with PTD + Merkle proof access', grant?.scope === 'FULL_AUDIT_PACKAGE' && grant.includes_ptd_access && grant.includes_merkle_proof_access, grant);
}

// 20-26: handleQueryV2 — rebuilt against KEE-1 §4.3 directly
function makeManifest(frost: boolean, ageSeconds = 0) {
  const kernelKeypair = nacl.sign.keyPair();
  const manifest = issueGecManifest({
    kernelKeypair,
    operatorIdentity: 'sha256:operator-stub',
    hardwareBacked: true,
    ptdEndpoint: 'https://demo/ptd/jp',
    ptdCurrentVersion: '1.0',
    kernelVersion: '1.0.0',
    loadedPolicyIds: ['profile-v1'],
    cedarPolicyHash: 'active-hash-xyz',
    deploymentConstraints: frost ? [frostConstraintString({ threshold: 2, participants: 3 })] : [],
    implementsXpid: true,
    kernelVersionDate: '2026-01-01',
    kernelImplementerId: 'demo-implementer',
  });
  if (ageSeconds > 0) {
    manifest.fields.attestation_timestamp = new Date(Date.now() - ageSeconds * 1000).toISOString();
  }
  return { manifest, kernelKeypair };
}

// 20: V2 happy path, FROST-signed deployment
{
  const { manifest, kernelKeypair } = makeManifest(true);
  const acdV2 = new AcdGec(new GARLog());
  const checks: FourCheckInputsV2 = { manifest, kernelPublicKey: kernelKeypair.publicKey, manifestRevoked: false, activeCedarPolicyHash: 'active-hash-xyz', claimedCedarPolicyHash: 'active-hash-xyz', kiaSigningKeyRevoked: false, frostThresholdKeyRevoked: false, agentXpidRevokedOrCaepSignaled: false };
  const result = acdV2.handleQueryV2({ resource_provider_id: 'p1', requested_at: new Date().toISOString() }, checks, bodyBuilder(), signer);
  record('ACD-V2-HP-01 FROST-signed deployment passes all 4 checks', result.ok, { ok: result.ok });
}

// 21: V2 happy path, non-FROST (plain KIA key) deployment
{
  const { manifest, kernelKeypair } = makeManifest(false);
  const acdV2 = new AcdGec(new GARLog());
  const checks: FourCheckInputsV2 = { manifest, kernelPublicKey: kernelKeypair.publicKey, manifestRevoked: false, activeCedarPolicyHash: 'active-hash-xyz', claimedCedarPolicyHash: 'active-hash-xyz', kiaSigningKeyRevoked: false, frostThresholdKeyRevoked: false, agentXpidRevokedOrCaepSignaled: false };
  const result = acdV2.handleQueryV2({ resource_provider_id: 'p1', requested_at: new Date().toISOString() }, checks, bodyBuilder(), signer);
  record('ACD-V2-HP-02 non-FROST (plain KIA key) deployment passes all 4 checks', result.ok, { ok: result.ok });
}

// 22: V2 Check 3 FROST path — threshold key revoked (the case ACD-01's own restatement dropped)
{
  const { manifest, kernelKeypair } = makeManifest(true);
  const acdV2 = new AcdGec(new GARLog());
  const checks: FourCheckInputsV2 = { manifest, kernelPublicKey: kernelKeypair.publicKey, manifestRevoked: false, activeCedarPolicyHash: 'active-hash-xyz', claimedCedarPolicyHash: 'active-hash-xyz', kiaSigningKeyRevoked: false, frostThresholdKeyRevoked: true, agentXpidRevokedOrCaepSignaled: false };
  const result = acdV2.handleQueryV2({ resource_provider_id: 'p1', requested_at: new Date().toISOString() }, checks, bodyBuilder(), signer);
  record('ACD-V2-EDGE-01 Check 3 FROST threshold key revoked -> fails (KEE-1 path ACD-01 restatement dropped)', !result.ok && result.error?.failed_check === 3, result.error);
}

// 23: V2 Check 3 non-FROST path — KIA signing key revoked
{
  const { manifest, kernelKeypair } = makeManifest(false);
  const acdV2 = new AcdGec(new GARLog());
  const checks: FourCheckInputsV2 = { manifest, kernelPublicKey: kernelKeypair.publicKey, manifestRevoked: false, activeCedarPolicyHash: 'active-hash-xyz', claimedCedarPolicyHash: 'active-hash-xyz', kiaSigningKeyRevoked: true, frostThresholdKeyRevoked: false, agentXpidRevokedOrCaepSignaled: false };
  const result = acdV2.handleQueryV2({ resource_provider_id: 'p1', requested_at: new Date().toISOString() }, checks, bodyBuilder(), signer);
  record('ACD-V2-EDGE-02 Check 3 non-FROST KIA signing key revoked -> fails', !result.ok && result.error?.failed_check === 3, result.error);
}

// 24: V2 Check 3 failure logs failed_layer:3/failed_field:"gec_signature" per KEE-1's exact requirement
{
  const { manifest, kernelKeypair } = makeManifest(false);
  const gar = new GARLog();
  const acdV2 = new AcdGec(gar);
  const checks: FourCheckInputsV2 = { manifest, kernelPublicKey: kernelKeypair.publicKey, manifestRevoked: false, activeCedarPolicyHash: 'active-hash-xyz', claimedCedarPolicyHash: 'active-hash-xyz', kiaSigningKeyRevoked: true, frostThresholdKeyRevoked: false, agentXpidRevokedOrCaepSignaled: false };
  acdV2.handleQueryV2({ resource_provider_id: 'p1', requested_at: new Date().toISOString() }, checks, bodyBuilder(), signer);
  const entry = gar.all().find((e: any) => e.ale_type === 'ACD_VALIDATION_FAILED');
  record('ACD-V2-HP-03 Check 3 failure logs failed_layer:3 + failed_field:"gec_signature" (KEE-1 exact requirement)', (entry as any)?.failed_layer === 3 && (entry as any)?.failed_field === 'gec_signature', entry);
}

// 25: V2 Check 2 — canonical policy hash mismatch (claimed vs active) fails, catching a stale/precomputed hash
{
  const { manifest, kernelKeypair } = makeManifest(false);
  const acdV2 = new AcdGec(new GARLog());
  const checks: FourCheckInputsV2 = { manifest, kernelPublicKey: kernelKeypair.publicKey, manifestRevoked: false, activeCedarPolicyHash: 'active-hash-xyz', claimedCedarPolicyHash: 'stale-precomputed-hash', kiaSigningKeyRevoked: false, frostThresholdKeyRevoked: false, agentXpidRevokedOrCaepSignaled: false };
  const result = acdV2.handleQueryV2({ resource_provider_id: 'p1', requested_at: new Date().toISOString() }, checks, bodyBuilder(), signer);
  record('ACD-V2-EDGE-03 Check 2 stale/precomputed cedar_policy_hash rejected', !result.ok && result.error?.failed_check === 2, result.error);
}

// 26: V2 Check 1 — stale manifest (attestation_timestamp beyond staleness window) fails via KIA's real assertManifestFresh()
{
  const { manifest, kernelKeypair } = makeManifest(false, 100000); // ~27.8 hours old, beyond the 24h default limit
  const acdV2 = new AcdGec(new GARLog());
  const checks: FourCheckInputsV2 = { manifest, kernelPublicKey: kernelKeypair.publicKey, manifestRevoked: false, activeCedarPolicyHash: 'active-hash-xyz', claimedCedarPolicyHash: 'active-hash-xyz', kiaSigningKeyRevoked: false, frostThresholdKeyRevoked: false, agentXpidRevokedOrCaepSignaled: false };
  const result = acdV2.handleQueryV2({ resource_provider_id: 'p1', requested_at: new Date().toISOString() }, checks, bodyBuilder(), signer);
  record('ACD-V2-EDGE-04 Check 1 stale manifest rejected via real KIA assertManifestFresh()', !result.ok && result.error?.failed_check === 1, result.error);
}

mkdirSync('svl', { recursive: true });
writeFileSync('svl/acd-corpus.json', JSON.stringify(log, null, 2));
const passCount = log.filter((l) => l.ok).length;
console.log(`ACD SVL corpus: ${log.length} scenarios, ${passCount} passed, ${log.length - passCount} failed.`);
if (log.length - passCount > 0) {
  console.error('FAILURES:', log.filter((l) => !l.ok));
  process.exitCode = 1;
}
