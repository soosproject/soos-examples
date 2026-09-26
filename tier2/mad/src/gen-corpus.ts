// SOOS Step 11 — MAD SVL corpus generator.
// Runs the live implementation (not hand-authored) to produce the log
// set the plan's Step 11 block calls for: "SACR issuance 7-step flow,
// XPID derivation (UUID5 with KIA_NS), hub-only enforcement
// (DirectSubAgentComm Cedar DENY), R-1 revocation (PARTIAL), R-3
// (UNKNOWN), max_spawn_depth decrement enforcement, MANDATE_HOLD
// propagation [-> substituted with CONTINUATION_AWAITING_PRINCIPAL,
// see SDB-MAD-01 in issue-log.md]."
//
// Scoped corpus (7 scenario families below produce ~20+ individual GAR
// entries when run), same scale as Step 6 (KIA)'s scoped 7HP+8edge
// corpus rather than the full 20HP+21edge pattern — MAD-03's surface
// area (SACR + hub-only + XPID + 7 revocation triggers) is broad enough
// that a full happy-path/edge split per sub-mechanism would roughly
// double this; flagged here rather than silently narrowed.

import { randomUUID } from 'crypto';
import { writeFileSync, mkdirSync } from 'fs';
import { GARLog, KIAStubSigner } from '../deps/gar/gar-core.js';
import { RevocationRegistry } from '../deps/kia/event-log.js';
import { MadGec } from './gec.js';
import { DelegationTree, RevocationEngine } from './revocation.js';
import { deriveSubAgentXpid } from './xpid.js';
import { MadDenyError, type AuthorizedParentScope, type SpawnRequest } from './types.js';

const gar = new GARLog();
const signer = new KIAStubSigner();
const revocationRegistry = new RevocationRegistry();
const gec = new MadGec(gar, signer, revocationRegistry);
const tree = new DelegationTree();
const revocation = new RevocationEngine(gar, signer, revocationRegistry, tree, gec);

const log: Record<string, unknown>[] = [];
function record(label: string, ok: boolean, detail: unknown): void {
  log.push({ label, ok, detail, timestamp: new Date().toISOString() });
}

function baseParentScope(overrides: Partial<AuthorizedParentScope> = {}): AuthorizedParentScope {
  return {
    session_id: 'session-parent',
    cedar_action_set: ['atp:booking:confirm', 'atp:booking:cancel'],
    tool_access: ['flight_search', 'hotel_search'],
    max_spawn_depth: 2,
    hub_only: true,
    revoked: false,
    ...overrides,
  };
}

function baseRequest(overrides: Partial<SpawnRequest> = {}): SpawnRequest {
  return {
    parent_assignment_id: `assignment-${randomUUID()}`,
    parent_session_id: 'session-parent',
    parent_mandate_id: `mjwt-${randomUUID()}`,
    parent_xpid: randomUUID(),
    scope_constraints: {
      cedar_action_subset: ['atp:booking:confirm'],
      so_type_scope: ['atp/booking-object/1.0'],
      resource_envelope: {},
      tool_subset: ['flight_search'],
    },
    can_decompose: false,
    max_spawn_depth: 0,
    hub_only: true,
    ...overrides,
  };
}

// 1-4: SACR issuance 7-step flow — happy path + three rejection edges
{
  const parentScope = baseParentScope();
  const req = baseRequest({ parent_session_id: parentScope.session_id });
  tree.register({ session_id: parentScope.session_id, mandate_id: req.parent_mandate_id, parent_session_id: null, responsive: true });
  const sacr = gec.spawnSubAgent(req, parentScope);
  record('SACR-HP-01 issuance happy path', true, { sacr_id: sacr.sacr_id });
}
{
  const parentScope = baseParentScope();
  const req = baseRequest({ scope_constraints: { ...baseRequest().scope_constraints, tool_subset: ['flight_search', 'NOT_A_PARENT_TOOL'] } });
  try {
    gec.spawnSubAgent(req, parentScope);
    record('SACR-EDGE-01 tool_subset violation', false, 'expected DENY, got PERMIT');
  } catch (e) {
    record('SACR-EDGE-01 tool_subset violation', e instanceof MadDenyError && e.code === 'TOOL_SUBSET_VIOLATION', (e as Error).message);
  }
}
{
  const parentScope = baseParentScope({ max_spawn_depth: 1 });
  const req = baseRequest({ max_spawn_depth: 1 });
  try {
    gec.spawnSubAgent(req, parentScope);
    record('SACR-EDGE-02 spawn_depth_exceeded', false, 'expected DENY, got PERMIT');
  } catch (e) {
    record('SACR-EDGE-02 spawn_depth_exceeded', e instanceof MadDenyError && e.code === 'SPAWN_DEPTH_EXCEEDED', (e as Error).message);
  }
}
{
  const parentScope = baseParentScope();
  const req = baseRequest({ scope_constraints: { ...baseRequest().scope_constraints, cedar_action_subset: ['atp:booking:confirm', 'atp:mission:advance'] } });
  try {
    gec.spawnSubAgent(req, parentScope);
    record('SACR-EDGE-03 mandate_narrowing_violation (INV-4)', false, 'expected DENY, got PERMIT');
  } catch (e) {
    record('SACR-EDGE-03 mandate_narrowing_violation (INV-4)', e instanceof MadDenyError && e.code === 'MANDATE_NARROWING_VIOLATION', (e as Error).message);
  }
}

// 5-6: XPID derivation
{
  const parentXpid = randomUUID();
  const sacrId = randomUUID();
  const xpid1 = deriveSubAgentXpid(parentXpid, sacrId);
  const xpid2 = deriveSubAgentXpid(parentXpid, sacrId);
  record('XPID-HP-01 deterministic derivation', xpid1 === xpid2, { xpid1, xpid2 });
}
{
  const xpidA = deriveSubAgentXpid(randomUUID(), randomUUID());
  const xpidB = deriveSubAgentXpid(randomUUID(), randomUUID());
  record('XPID-EDGE-01 distinct inputs produce distinct XPIDs', xpidA !== xpidB, { xpidA, xpidB });
}

// 7-8: hub-only enforcement
{
  const parentScope = baseParentScope();
  const req = baseRequest({ hub_only: true });
  tree.register({ session_id: parentScope.session_id, mandate_id: req.parent_mandate_id, parent_session_id: null, responsive: true });
  const sacrA = gec.spawnSubAgent(req, parentScope);
  const sacrB = gec.spawnSubAgent(baseRequest({ hub_only: true }), parentScope);
  tree.register({ session_id: sacrA.ephemeral_kia_ref, mandate_id: `mjwt-${randomUUID()}`, parent_session_id: parentScope.session_id, responsive: true });
  tree.register({ session_id: sacrB.ephemeral_kia_ref, mandate_id: `mjwt-${randomUUID()}`, parent_session_id: parentScope.session_id, responsive: true });
  try {
    gec.checkDirectSubAgentComm(sacrA.ephemeral_kia_ref, sacrB.ephemeral_kia_ref, 'STATUS_UPDATE');
    record('HUB-EDGE-01 DirectSubAgentComm DENY under hub_only:true', false, 'expected DENY, got PERMIT');
  } catch (e) {
    record('HUB-EDGE-01 DirectSubAgentComm DENY under hub_only:true', e instanceof MadDenyError && e.code === 'HUB_ONLY_VIOLATION', (e as Error).message);
  }
}
{
  const parentScope = baseParentScope({ hub_only: true });
  const req = baseRequest({ hub_only: false });
  try {
    gec.spawnSubAgent(req, parentScope);
    record('HUB-EDGE-02 hub_only:false rejected from hub_only:true parent (CONF-MAD-HUB-04)', false, 'expected DENY, got PERMIT');
  } catch (e) {
    record('HUB-EDGE-02 hub_only:false rejected from hub_only:true parent (CONF-MAD-HUB-04)', e instanceof MadDenyError && e.code === 'HUB_OVERRIDE_NOT_PERMITTED', (e as Error).message);
  }
}

// 9: max_spawn_depth decrement enforcement (distinct from SACR-EDGE-02: this
// verifies the VALID boundary case — exactly (parent - 1) is accepted)
{
  const parentScope = baseParentScope({ max_spawn_depth: 3 });
  const req = baseRequest({ max_spawn_depth: 2 }); // exactly parent (3) - 1
  const sacr = gec.spawnSubAgent(req, parentScope);
  record('DEPTH-HP-01 boundary depth (parent-1) accepted', sacr.max_spawn_depth === 2, { max_spawn_depth: sacr.max_spawn_depth });
}

// 10-11: R-1 revocation (PARTIAL always) + CONTINUATION_AWAITING_PRINCIPAL
// (substitute for the plan's non-existent "MANDATE_HOLD" term — SDB-MAD-01)
{
  const sessionId = `session-r1-${randomUUID()}`;
  tree.register({ session_id: sessionId, mandate_id: `mjwt-${randomUUID()}`, parent_session_id: null, responsive: true });
  const result = revocation.trigger('R-1', sessionId);
  record('R1-HP-01 CAP Tier 0-A violation -> PARTIAL', result.completion_state === 'PARTIAL', result);
  const held = gar.getSession(sessionId).some((e) => e.ale_type === ('CONTINUATION_AWAITING_PRINCIPAL' as any));
  record('R1-HP-02 CONTINUATION_AWAITING_PRINCIPAL recorded (SDB-MAD-01 substitution for "MANDATE_HOLD")', held, {});
}

// 12: R-3 revocation (UNKNOWN always) + selective cascade
{
  const parentId = `session-r3-parent-${randomUUID()}`;
  const responsiveChild = `session-r3-responsive-${randomUUID()}`;
  const nonResponsiveChild = `session-r3-nonresponsive-${randomUUID()}`;
  tree.register({ session_id: parentId, mandate_id: `mjwt-${randomUUID()}`, parent_session_id: null, responsive: false });
  tree.register({ session_id: responsiveChild, mandate_id: `mjwt-${randomUUID()}`, parent_session_id: parentId, responsive: true });
  tree.register({ session_id: nonResponsiveChild, mandate_id: `mjwt-${randomUUID()}`, parent_session_id: parentId, responsive: false });
  const result = revocation.trigger('R-3', parentId);
  const selectiveCorrect = result.completion_state === 'UNKNOWN' && result.revoked_sessions.includes(nonResponsiveChild) && !result.revoked_sessions.includes(responsiveChild);
  record('R3-HP-01 non-response -> UNKNOWN, selective cascade (responsive child survives)', selectiveCorrect, result);
}

// 13: R-2 CLEAN (detected before execution)
{
  const sessionId = `session-r2-clean-${randomUUID()}`;
  tree.register({ session_id: sessionId, mandate_id: `mjwt-${randomUUID()}`, parent_session_id: null, responsive: true });
  const result = revocation.trigger('R-2', sessionId, { haltTiming: 'BEFORE_ACTION' });
  record('R2-EDGE-01 scope boundary detected pre-execution -> CLEAN', result.completion_state === 'CLEAN', result);
}

// 14: R-2 PARTIAL (irreversible action already taken)
{
  const sessionId = `session-r2-partial-${randomUUID()}`;
  tree.register({ session_id: sessionId, mandate_id: `mjwt-${randomUUID()}`, parent_session_id: null, responsive: true });
  const result = revocation.trigger('R-2', sessionId, { haltTiming: 'AFTER_IRREVERSIBLE_ACTION' });
  record('R2-EDGE-02 scope boundary post-irreversible-action -> PARTIAL', result.completion_state === 'PARTIAL', result);
}

// 15: R-4 CLEAN (anticipatory)
{
  const sessionId = `session-r4-${randomUUID()}`;
  tree.register({ session_id: sessionId, mandate_id: `mjwt-${randomUUID()}`, parent_session_id: null, responsive: true });
  const result = revocation.trigger('R-4', sessionId, { haltTiming: 'BEFORE_ACTION' });
  record('R4-EDGE-01 irreversible threshold anticipatory -> CLEAN', result.completion_state === 'CLEAN', result);
}

// 16: R-5 no cascade
{
  const parentId = `session-r5-parent-${randomUUID()}`;
  const childId = `session-r5-child-${randomUUID()}`;
  tree.register({ session_id: parentId, mandate_id: `mjwt-${randomUUID()}`, parent_session_id: null, responsive: true });
  tree.register({ session_id: childId, mandate_id: `mjwt-${randomUUID()}`, parent_session_id: parentId, responsive: true });
  const result = revocation.trigger('R-5', parentId, { haltTiming: 'BEFORE_ACTION' });
  record('R5-EDGE-01 scheduled rotation -> no cascade (Table 2)', result.cascade_scope === 'NONE' && !result.revoked_sessions.includes(childId), result);
}

// 17: R-6 operator-specified THIS_MANDATE_ONLY
{
  const parentId = `session-r6-parent-${randomUUID()}`;
  const childId = `session-r6-child-${randomUUID()}`;
  tree.register({ session_id: parentId, mandate_id: `mjwt-${randomUUID()}`, parent_session_id: null, responsive: true });
  tree.register({ session_id: childId, mandate_id: `mjwt-${randomUUID()}`, parent_session_id: parentId, responsive: true });
  const result = revocation.trigger('R-6', parentId, { haltTiming: 'BEFORE_ACTION', revocationScope: 'THIS_MANDATE_ONLY' });
  record('R6-EDGE-01 operator override scoped THIS_MANDATE_ONLY -> child survives', !result.revoked_sessions.includes(childId), result);
}

// 18-19: R-7 DEADLOCK -> UNKNOWN, then timeout -> R-3 path
{
  const sessionA = `session-r7-a-${randomUUID()}`;
  const sessionB = `session-r7-b-${randomUUID()}`;
  tree.register({ session_id: sessionA, mandate_id: `mjwt-${randomUUID()}`, parent_session_id: null, responsive: true });
  tree.register({ session_id: sessionB, mandate_id: `mjwt-${randomUUID()}`, parent_session_id: null, responsive: true });
  const resultA = revocation.trigger('R-7', sessionA);
  const resultB = revocation.trigger('R-7', sessionB);
  record('R7-HP-01 deadlock -> UNKNOWN for all participants', resultA.completion_state === 'UNKNOWN' && resultB.completion_state === 'UNKNOWN', { resultA, resultB });
  const timeoutResult = revocation.timeoutDeadlock(sessionA);
  record('R7-EDGE-01 deadlock_timeout -> auto-revoke under R-3', timeoutResult.trigger === 'R-3' && timeoutResult.completion_state === 'UNKNOWN', timeoutResult);
}

// 20: ephemeral identity retirement on session close
{
  const parentScope = baseParentScope();
  const req = baseRequest();
  tree.register({ session_id: parentScope.session_id + '-20', mandate_id: req.parent_mandate_id, parent_session_id: null, responsive: true });
  const sacr = gec.spawnSubAgent({ ...req, parent_session_id: parentScope.session_id + '-20' }, { ...parentScope, session_id: parentScope.session_id + '-20' });
  gec.retireEphemeralIdentity(sacr.ephemeral_kia_ref, 'CLEAN');
  const retired = gec.getSacr(sacr.ephemeral_kia_ref) === undefined;
  record('SACR-HP-02 ephemeral identity retirement (ALE-SPAWN-04)', retired, { ephemeral_kia_ref: sacr.ephemeral_kia_ref });
}

mkdirSync('svl', { recursive: true });
writeFileSync('svl/mad-corpus.json', JSON.stringify(log, null, 2));
writeFileSync('svl/mad-gar-log.json', JSON.stringify(gar.all(), null, 2));

const passCount = log.filter((l) => l.ok).length;
console.log(`MAD SVL corpus: ${log.length} scenarios, ${passCount} passed, ${log.length - passCount} failed.`);
console.log(`GAR entries emitted: ${gar.all().length}`);
if (log.length - passCount > 0) {
  console.error('FAILURES:', log.filter((l) => !l.ok));
  process.exitCode = 1;
}
