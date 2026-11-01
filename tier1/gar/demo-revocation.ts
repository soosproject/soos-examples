// demo-revocation.ts — Authority Lifecycle Events (ALE-001..012 + holds) walkthrough
// draft-sato-soos-gar-13 Section 12 (updated 1 Nov 2026: mandate_jti
// vocabulary, revocation_type/cascade_root_jti, authority_type,
// revocation_event_ref, mandate holds)
//
// Companion to demo.ts (which covers the Session Audit Record path:
// SESSION_START/CEDAR_PERMIT/CEDAR_DENY/HEM_ESCALATION/SESSION_END). This
// file covers the separate Authority Lifecycle Event category -- the
// revocation and recovery chain, new to the sample code this pass.
//
// Scenarios (numbers match the section headings printed at run time):
//   1. Single-agent revocation + recovery, non-R-8 (R-2 Scope Boundary),
//      including the mandate_hold gate rejecting MJWT issuance mid-recovery
//   2. CASCADE revocation with PARTIAL completion_state -> disposition ->
//      recovery (revocation_type CASCADE + cascade_root_jti, GAR-13 12.3)
//   3. R-8 (Compromise) revocation -> external KIA-signed ALE-007
//   4. Account-level suspension (ALE-002 chain root, not ALE-001)
//   5. Multi-agent delegation: child revoked -> tree recovery initiated
//   6. Cluster partial revocation, UNACHIEVABLE -> forced HALT_REMAINING
//   7. Sibling revocation notice (no horizontal cascade)
//   8. Causal-ordering violation (gap detection)
//   9. ALE-007 misuse: fired for a non-R-8 revocation -> rejected
//  10. ALE-008 blocked while a PARTIAL disposition is still DEFER
//  11. Mandate hold on an external signal -> converted to revocation
//      (ALE_MANDATE_HELD -> ALE_MANDATE_HOLD_RELEASED -> ALE-001)
//  12. Vocabulary conformance: CAEP_SIGNAL + KERNEL rejected; CASCADE
//      without cascade_root_jti rejected

import { randomUUID } from 'crypto';
import {
  AuthorityLedger,
  AgentInRecoveryError,
  ALECausalOrderingError,
  ExternalSigningRequiredError,
  UnresolvedPartialStateError,
  VocabularyConformanceError,
  buildMandateHeld,
  buildMandateHoldReleased,
  stubSignature,
  buildALE001,
  buildALE002,
  buildALE003,
  buildALE004,
  buildALE005,
  buildALE006,
  buildALE007,
  buildALE008,
  buildALE009,
  buildALE010,
  buildALE011,
  buildALE012,
} from './authority-lifecycle';

function line() { console.log('─'.repeat(70)); }
function section(title: string) { line(); console.log(title); line(); }
function ok(msg: string) { console.log(`  ✓ ${msg}`); }
function expected(msg: string) { console.log(`  ✓ (expected) ${msg}`); }

async function main() {
  const ledger = new AuthorityLedger();

  // =================================================================
  // 1. Single-agent revocation + recovery, non-R-8
  // =================================================================
  section('1. R-2 (Scope Boundary) revocation -> credential rotation -> restored');

  const rev1 = ledger.append(buildALE001({
    prior_event_id: 'aep-event-' + randomUUID().slice(0, 8), // opaque AEP ref, not ledger-validated
    session_id: 'session-alpha',
    agent_id: 'agent-alpha',
    mandate_jti: 'mjwt-alpha-1',
    so_id: 'so://mission/alpha/step-3',
    revocation_class: 'R-2',
    revocation_reason: 'Attempted action outside mandate scope at execution time',
    revocation_source: 'CAP_VIOLATION',
    revocation_type: 'DIRECT',
    authority_type: 'KERNEL',
    revocation_event_ref: 'mjwt-mandate-revoked-' + randomUUID().slice(0, 8), // MJWT-08 7.3 MANDATE_REVOKED
    trigger_event_ref: 'evt-cap-' + randomUUID().slice(0, 8),
    completion_state: 'CLEAN',
    natural_breakpoint_reached: true,
    irreversible_actions_taken: false,
    rollback_available: true,
    so_state_at_revocation: 'in_progress',
    iterations_completed: 4,
    cascade_depth: 0,
    gec_signature: stubSignature('gec-alpha'),
  }));
  console.log(`  ALE-001  revocation_class=${rev1.revocation_class}  completion_state=${rev1.completion_state}`);

  const rec1 = ledger.append(buildALE004({
    prior_event_id: rev1.event_id,
    agent_id: 'agent-alpha',
    recovery_ref: randomUUID(),
    initiated_by: 'OPERATOR',
    initiator_ref: 'operator-1',
    revocation_ref: rev1.event_id,
    recovery_type: 'CREDENTIAL_ROTATION',
    gec_signature: stubSignature('gec-alpha'),
  }));
  console.log(`  ALE-004  mandate_hold=${rec1.mandate_hold}  recovery_type=${rec1.recovery_type}`);
  console.log(`  hasMandateHold('agent-alpha') = ${ledger.hasMandateHold('agent-alpha')}`);

  try {
    ledger.assertCanIssueMandate('agent-alpha');
    console.log('  ✗ unexpected: mandate issuance should have been blocked');
  } catch (err) {
    if (err instanceof AgentInRecoveryError) {
      expected(`MJWT issuance rejected: ${err.message}`);
    } else throw err;
  }

  const cred1 = ledger.append(buildALE006({
    prior_event_id: rec1.event_id,
    recovery_ref: rec1.recovery_ref,
    agent_id: 'agent-alpha',
    credential_type: 'MJWT',
    new_credential_ref: 'mjwt-alpha-2',
    old_credential_ref: 'mjwt-alpha-1',
    rotation_method: 'REISSUANCE',
    pt_score_at_restoration: 0.91,
    gec_signature: stubSignature('gec-alpha'),
  }));
  ok(`ALE-006  new_credential_ref=${cred1.new_credential_ref}`);

  const rest1 = ledger.append(buildALE008({
    prior_event_id: cred1.event_id,
    recovery_ref: rec1.recovery_ref,
    agent_id: 'agent-alpha',
    restored_by: 'OPERATOR',
    restoration_scope: 'FULL',
    prior_revocation_ref: rev1.event_id,
    pt_score_at_restoration: 0.91,
    new_mandate_jti: 'mjwt-alpha-2',
    gec_signature: stubSignature('gec-alpha'),
  }));
  ok(`ALE-008  mandate_hold_lifted=${rest1.mandate_hold_lifted}`);
  console.log(`  hasMandateHold('agent-alpha') = ${ledger.hasMandateHold('agent-alpha')} (gate now clear)`);
  ledger.assertCanIssueMandate('agent-alpha');
  ok(`MJWT issuance now permitted for agent-alpha`);

  // =================================================================
  // 2. PARTIAL completion_state -> disposition -> recovery
  // =================================================================
  section('2. PARTIAL completion_state -> ALE-003 -> disposition -> recovery');

  const rev2 = ledger.append(buildALE001({
    prior_event_id: 'aep-event-' + randomUUID().slice(0, 8),
    session_id: 'session-beta',
    agent_id: 'agent-beta',
    mandate_jti: 'mjwt-beta-1',
    so_id: 'so://mission/beta/step-7',
    revocation_class: 'R-3',
    revocation_reason: 'No response to cascade timeout within required window',
    revocation_source: 'OPERATOR', // mechanism at cascade_root_jti (GAR-13 12.3)
    revocation_type: 'CASCADE',
    cascade_root_jti: 'mjwt-beta-parent',
    authority_type: 'OPERATOR',
    revocation_event_ref: 'mjwt-mandate-revoked-' + randomUUID().slice(0, 8), // MJWT-08 7.3 MANDATE_REVOKED
    trigger_event_ref: 'evt-cascade-' + randomUUID().slice(0, 8),
    completion_state: 'PARTIAL',
    natural_breakpoint_reached: false,
    irreversible_actions_taken: true,
    rollback_available: false,
    so_state_at_revocation: 'mid_write',
    iterations_completed: 12,
    cascade_depth: 1,
    gec_signature: stubSignature('gec-beta'),
  }));
  console.log(`  ALE-001  completion_state=${rev2.completion_state} -- ALE-003 REQUIRED immediately (Section 12.3)`);

  const hemId = randomUUID();
  const partial2 = ledger.append(buildALE003({
    prior_event_id: rev2.event_id,
    session_id: 'session-beta',
    so_id: 'so://mission/beta/step-7',
    so_state_at_suspension: 'mid_write',
    last_committed_action: 'write_batch_3_of_5',
    last_committed_event_id: 'evt-write-3',
    uncommitted_idp_ref: 'idp-uncommitted-beta-1',
    irreversible_actions: [{ action: 'write_batch_3_of_5', event_id: 'evt-write-3', occurred_at: new Date().toISOString() }],
    rollback_path: [],
    hem_escalation_id: hemId,
    disposition_required_by: new Date(Date.now() + 86400_000).toISOString(),
    gec_signature: stubSignature('gec-beta'),
  }));
  ok(`ALE-003  hem_escalation_id=${partial2.hem_escalation_id.slice(0, 8)}...`);

  const rec2 = ledger.append(buildALE004({
    prior_event_id: rev2.event_id, // ALE-004's prior_event_id MUST reference ALE-001 or ALE-002 (not ALE-003)
    agent_id: 'agent-beta',
    recovery_ref: randomUUID(),
    initiated_by: 'HUMAN_PRINCIPAL',
    initiator_ref: 'principal-jane',
    revocation_ref: rev2.event_id,
    recovery_type: 'OPERATOR_REINSTATEMENT',
    gec_signature: stubSignature('gec-beta'),
  }));

  const disp2 = ledger.append(buildALE005({
    prior_event_id: partial2.event_id,
    recovery_ref: rec2.recovery_ref,
    session_id: 'session-beta',
    so_id: 'so://mission/beta/step-7',
    disposition: 'COMPLETE',
    decided_by: 'principal-jane',
    principal_signature: stubSignature('principal-jane'),
    disposition_rationale: 'Batch is safe to complete by a fresh agent instance -- write is idempotent',
    completion_agent_id: 'agent-beta-2',
    completion_mandate_ref: 'mjwt-beta-2',
    gec_signature: stubSignature('gec-beta'),
  }));
  ok(`ALE-005  disposition=${disp2.disposition} -> completion_agent_id=${disp2.completion_agent_id}`);

  const cred2 = ledger.append(buildALE006({
    prior_event_id: rec2.event_id,
    recovery_ref: rec2.recovery_ref,
    agent_id: 'agent-beta',
    credential_type: 'MJWT',
    new_credential_ref: 'mjwt-beta-2',
    old_credential_ref: 'mjwt-beta-1',
    rotation_method: 'REISSUANCE',
    pt_score_at_restoration: 0.77,
    gec_signature: stubSignature('gec-beta'),
  }));

  const rest2 = ledger.append(buildALE008({
    prior_event_id: cred2.event_id,
    recovery_ref: rec2.recovery_ref,
    agent_id: 'agent-beta',
    restored_by: 'OPERATOR',
    restoration_scope: 'CONSTRAINED',
    constraints: ['permit(principal, action == "WriteBatch", resource) when { resource.batch_id == "3" }'],
    prior_revocation_ref: rev2.event_id,
    partial_state_disposition_ref: disp2.event_id,
    pt_score_at_restoration: 0.77,
    gec_signature: stubSignature('gec-beta'),
  }));
  ok(`ALE-008  restoration_scope=${rest2.restoration_scope} (PARTIAL disposition was resolved first -- required)`);

  // =================================================================
  // 3. R-8 (Compromise) -> external KIA-signed ALE-007
  // =================================================================
  section('3. R-8 (Compromise) -- external KIA Verification Service signs ALE-007');

  const rev3 = ledger.append(buildALE001({
    prior_event_id: 'aep-event-' + randomUUID().slice(0, 8),
    session_id: 'session-gamma',
    agent_id: 'agent-gamma',
    mandate_jti: 'mjwt-gamma-1',
    so_id: 'so://mission/gamma/step-2',
    revocation_class: 'R-8',
    revocation_reason: 'KIA reattestation failure -- runtime identity no longer matches attested state',
    revocation_source: 'KIA_ATTESTATION',
    revocation_type: 'DIRECT',
    authority_type: 'KERNEL',
    revocation_event_ref: 'mjwt-mandate-revoked-' + randomUUID().slice(0, 8), // MJWT-08 7.3 MANDATE_REVOKED
    trigger_event_ref: 'evt-kia-fail-' + randomUUID().slice(0, 8),
    completion_state: 'UNKNOWN',
    natural_breakpoint_reached: false,
    irreversible_actions_taken: false,
    rollback_available: false,
    so_state_at_revocation: 'unknown_post_halt',
    iterations_completed: 6,
    cascade_depth: 0,
    gec_signature: stubSignature('gec-gamma'),
  }));
  console.log(`  ALE-001  revocation_class=${rev3.revocation_class} (Compromise)`);

  const partial3 = ledger.append(buildALE003({
    prior_event_id: rev3.event_id,
    session_id: 'session-gamma',
    so_id: 'so://mission/gamma/step-2',
    so_state_at_suspension: 'unknown_post_halt',
    last_committed_action: 'unknown',
    last_committed_event_id: 'evt-last-known-gamma',
    uncommitted_idp_ref: 'idp-uncommitted-gamma-1',
    irreversible_actions: [],
    rollback_path: [],
    hem_escalation_id: randomUUID(),
    disposition_required_by: new Date(Date.now() + 86400_000).toISOString(),
    gec_signature: stubSignature('gec-gamma'),
  }));

  const rec3 = ledger.append(buildALE004({
    prior_event_id: rev3.event_id,
    agent_id: 'agent-gamma',
    recovery_ref: randomUUID(),
    initiated_by: 'OPERATOR',
    initiator_ref: 'operator-2',
    revocation_ref: rev3.event_id,
    recovery_type: 'KIA_REATTESTATION',
    gec_signature: stubSignature('gec-gamma'),
  }));

  const disp3 = ledger.append(buildALE005({
    prior_event_id: partial3.event_id,
    recovery_ref: rec3.recovery_ref,
    session_id: 'session-gamma',
    so_id: 'so://mission/gamma/step-2',
    disposition: 'ABANDON',
    decided_by: 'operator-2',
    principal_signature: stubSignature('operator-2'),
    disposition_rationale: 'Runtime identity mismatch -- state provenance cannot be trusted, abandon in place',
    abandon_compensation: [{ action: 'flag_so_for_manual_review', rationale: 'compromise window overlaps this SO' }],
    gec_signature: stubSignature('gec-gamma'),
  }));
  ok(`ALE-005  disposition=${disp3.disposition}`);

  // ALE-007 is signed by an external KIA Verification Service -- NOT the
  // GEC being re-attested. kia_verifier_signature REPLACES gec_signature
  // on this event type; there's no gec_signature field to fall back to.
  const react3 = ledger.append(buildALE007({
    prior_event_id: rec3.event_id,
    recovery_ref: rec3.recovery_ref,
    gec_instance_id: 'gec-gamma',
    prior_attestation_id: 'attest-gamma-7',
    new_attestation_id: 'attest-gamma-8',
    new_cedar_policy_hash: 'sha256:' + randomUUID().replace(/-/g, ''),
    new_kernel_version: 'kernel-2.4.1',
    attestation_gap_duration: 340,
    sessions_during_gap: ['session-gamma'],
    kia_verifier_signature: stubSignature('external-kia-verifier-svc-1'), // external verifier, not gec-gamma
    kia_verifier_id: 'kia-verifier-svc-1',
  }));
  ok(`ALE-007  kia_verifier_signature.key_id=${react3.kia_verifier_signature.key_id} (external verifier, not the GEC under attestation)`);
  console.log('  ATTESTATION_GAP_WARNING would be flagged on: ' + react3.sessions_during_gap.join(', '));

  const rest3 = ledger.append(buildALE008({
    prior_event_id: react3.event_id,
    recovery_ref: rec3.recovery_ref,
    agent_id: 'agent-gamma',
    restored_by: 'OPERATOR',
    restoration_scope: 'CONSTRAINED',
    constraints: ['permit(principal, action, resource) when { context.post_compromise_review == true }'],
    prior_revocation_ref: rev3.event_id,
    partial_state_disposition_ref: disp3.event_id,
    pt_score_at_restoration: 0.42,
    gec_signature: stubSignature('gec-gamma'),
  }));
  ok(`ALE-008  restoration_scope=${rest3.restoration_scope} (low pt_score after Compromise -- CONSTRAINED, per Section 12.10)`);

  // =================================================================
  // 4. Account-level suspension -- ALE-002 chain root, not ALE-001
  // =================================================================
  section('4. Account-level suspension (ALE-002 chain root)');

  const susp4 = ledger.append(buildALE002({
    prior_event_id: null,
    agent_id: 'agent-delta',
    suspension_reason: 'REGULATORY_HOLD',
    suspension_source: 'REGULATORY_AUTHORITY',
    trigger_event_ref: 'evt-reg-hold-' + randomUUID().slice(0, 8),
    affected_session_ids: ['session-delta-1', 'session-delta-2'],
    affected_so_ids: ['so://mission/delta/1', 'so://mission/delta/2'],
    recovery_permitted: true,
    gec_signature: stubSignature('gec-delta'),
  }));
  ok(`ALE-002  suspension_reason=${susp4.suspension_reason}  affected_sessions=${susp4.affected_session_ids.length}`);

  const rec4 = ledger.append(buildALE004({
    prior_event_id: susp4.event_id, // ALE-004 may chain from ALE-002 too, per Section 12.2
    agent_id: 'agent-delta',
    recovery_ref: randomUUID(),
    initiated_by: 'REGULATORY_AUTHORITY',
    initiator_ref: 'regulator-jp-1',
    revocation_ref: susp4.event_id,
    recovery_type: 'REGULATORY_CLEARANCE',
    gec_signature: stubSignature('gec-delta'),
  }));
  ok(`ALE-004  chained from ALE-002 (account-level root) rather than ALE-001`);

  const cred4 = ledger.append(buildALE006({
    prior_event_id: rec4.event_id,
    recovery_ref: rec4.recovery_ref,
    agent_id: 'agent-delta',
    credential_type: 'ALL',
    new_credential_ref: 'mjwt-delta-2',
    old_credential_ref: 'mjwt-delta-1',
    rotation_method: 'REISSUANCE',
    pt_score_at_restoration: 0.85,
    gec_signature: stubSignature('gec-delta'),
  }));

  ledger.append(buildALE008({
    prior_event_id: cred4.event_id,
    recovery_ref: rec4.recovery_ref,
    agent_id: 'agent-delta',
    restored_by: 'REGULATORY_AUTHORITY',
    restoration_scope: 'FULL',
    prior_revocation_ref: susp4.event_id,
    pt_score_at_restoration: 0.85,
    gec_signature: stubSignature('gec-delta'),
  }));
  ok('ALE-008  account-level authority restored');

  // =================================================================
  // 5. Multi-agent delegation: child revoked -> tree recovery
  // =================================================================
  section('5. Delegation: child mandate revoked -> parent notified -> tree recovery');

  const revChild = ledger.append(buildALE001({
    prior_event_id: 'aep-event-' + randomUUID().slice(0, 8),
    session_id: 'session-child-1',
    agent_id: 'agent-child-1',
    mandate_jti: 'mjwt-child-1',
    so_id: 'so://mission/epsilon/subtask-2',
    revocation_class: 'R-4',
    revocation_reason: 'Approached irreversible action threshold without confirmation',
    revocation_source: 'CAP_VIOLATION',
    revocation_type: 'DIRECT',
    authority_type: 'KERNEL',
    revocation_event_ref: 'mjwt-mandate-revoked-' + randomUUID().slice(0, 8), // MJWT-08 7.3 MANDATE_REVOKED
    trigger_event_ref: 'evt-threshold-' + randomUUID().slice(0, 8),
    completion_state: 'PARTIAL',
    natural_breakpoint_reached: true,
    irreversible_actions_taken: false,
    rollback_available: true,
    so_state_at_revocation: 'awaiting_confirmation',
    iterations_completed: 2,
    cascade_depth: 0,
    gec_signature: stubSignature('gec-child-1'),
  }));

  const childRevoked5 = ledger.append(buildALE009({
    prior_event_id: 'parent-last-event-' + randomUUID().slice(0, 8), // last event in the PARENT session, opaque here
    parent_session_id: 'session-orchestrator-epsilon',
    parent_mandate_jti: 'mjwt-orchestrator-epsilon',
    revoked_child_mandate_jti: 'mjwt-child-1',
    revoked_agent_id: 'agent-child-1',
    revoked_so_id: 'so://mission/epsilon/subtask-2',
    revocation_class: revChild.revocation_class,
    child_completion_state: 'PARTIAL',
    delegation_depth: 1,
    cascade_depth_remaining: 2,
    cluster_id: null,
    parent_goal_impact: 'BLOCKING',
    gec_signature: stubSignature('gec-orchestrator-epsilon'),
  }));
  ok(`ALE-009  parent_goal_impact=${childRevoked5.parent_goal_impact} -- orchestrator MUST re-delegate or escalate before next ACT`);

  const treeRecovery5 = ledger.append(buildALE012({
    prior_event_id: childRevoked5.event_id,
    root_mandate_jti: 'mjwt-orchestrator-epsilon',
    orchestrator_session_id: 'session-orchestrator-epsilon',
    recovery_ref: randomUUID(),
    revoked_subtree_root: 'mjwt-child-1',
    revoked_agents: [{ agent_id: 'agent-child-1', mandate_jti: 'mjwt-child-1', completion_state: 'PARTIAL', so_id: 'so://mission/epsilon/subtask-2' }],
    still_active_agents: [{ agent_id: 'agent-child-2', mandate_jti: 'mjwt-child-2', so_id: 'so://mission/epsilon/subtask-3' }],
    partial_so_ids: ['so://mission/epsilon/subtask-2'],
    tree_recovery_strategy: 'REDELEGATION',
    mandate_hold_scope: 'SUBTREE_ONLY',
    gec_signature: stubSignature('gec-orchestrator-epsilon'),
  }));
  ok(`ALE-012  tree_recovery_strategy=${treeRecovery5.tree_recovery_strategy}  mandate_hold_scope=${treeRecovery5.mandate_hold_scope}`);

  // =================================================================
  // 6. Cluster partial revocation -- UNACHIEVABLE forces HALT_REMAINING
  // =================================================================
  section('6. Cluster partial revocation -- UNACHIEVABLE forces HALT_REMAINING');

  const revClusterMember = ledger.append(buildALE001({
    prior_event_id: 'aep-event-' + randomUUID().slice(0, 8),
    session_id: 'session-cluster-member-3',
    agent_id: 'agent-cluster-member-3',
    mandate_jti: 'mjwt-cluster-3',
    so_id: 'so://mission/zeta/cluster-part-3',
    revocation_class: 'R-6',
    revocation_reason: 'Operator override -- resource contention with higher-priority mission',
    revocation_source: 'OPERATOR',
    revocation_type: 'DIRECT',
    authority_type: 'OPERATOR',
    revocation_event_ref: 'mjwt-mandate-revoked-' + randomUUID().slice(0, 8), // MJWT-08 7.3 MANDATE_REVOKED
    trigger_event_ref: 'evt-override-' + randomUUID().slice(0, 8),
    completion_state: 'UNKNOWN',
    natural_breakpoint_reached: false,
    irreversible_actions_taken: false,
    rollback_available: false,
    so_state_at_revocation: 'in_progress',
    iterations_completed: 3,
    cascade_depth: 0,
    gec_signature: stubSignature('gec-cluster-3'),
  }));

  const clusterRev6 = ledger.append(buildALE010({
    prior_event_id: revClusterMember.event_id,
    cluster_id: 'cluster-zeta',
    orchestrator_session_id: 'session-orchestrator-zeta',
    revoked_member_agent_id: 'agent-cluster-member-3',
    revoked_member_so_id: 'so://mission/zeta/cluster-part-3',
    revoked_completion_state: 'UNKNOWN',
    members_still_active: ['agent-cluster-member-1'],
    members_completed: ['agent-cluster-member-2'],
    members_revoked: ['agent-cluster-member-3'],
    aggregation_rule: 'ALL_COMPLETE',
    cluster_achievability: 'UNACHIEVABLE',
    recommended_disposition: 'HALT_REMAINING',
    gec_signature: stubSignature('gec-orchestrator-zeta'),
  }));
  ok(`ALE-010  aggregation_rule=${clusterRev6.aggregation_rule}, member 3 revoked -> ALL_COMPLETE now UNACHIEVABLE -> ${clusterRev6.recommended_disposition}`);

  try {
    ledger.append(buildALE010({
      prior_event_id: revClusterMember.event_id,
      cluster_id: 'cluster-zeta',
      orchestrator_session_id: 'session-orchestrator-zeta',
      revoked_member_agent_id: 'agent-cluster-member-3',
      revoked_member_so_id: 'so://mission/zeta/cluster-part-3',
      revoked_completion_state: 'UNKNOWN',
      members_still_active: ['agent-cluster-member-1'],
      members_completed: ['agent-cluster-member-2'],
      members_revoked: ['agent-cluster-member-3'],
      aggregation_rule: 'ALL_COMPLETE',
      cluster_achievability: 'UNACHIEVABLE',
      recommended_disposition: 'CONTINUE', // WRONG -- Section 12.12 forbids this combination
      gec_signature: stubSignature('gec-orchestrator-zeta'),
    }));
    console.log('  ✗ unexpected: should have rejected UNACHIEVABLE + CONTINUE');
  } catch (err) {
    if (err instanceof ALECausalOrderingError) {
      expected(`UNACHIEVABLE + CONTINUE rejected: ${err.message}`);
    } else throw err;
  }

  // =================================================================
  // 7. Sibling revocation notice -- no horizontal cascade
  // =================================================================
  section('7. Sibling revocation notice -- INV-4 horizontal non-contamination');

  const sibling7 = ledger.append(buildALE011({
    prior_event_id: 'sibling-last-event-' + randomUUID().slice(0, 8),
    notified_session_id: 'session-cluster-member-1',
    notified_agent_id: 'agent-cluster-member-1',
    shared_so_id: 'so://mission/zeta/shared-context',
    revoked_agent_id: 'agent-cluster-member-3',
    revoked_session_id: 'session-cluster-member-3',
    revoked_jti: 'mjwt-cluster-3',
    revocation_class: revClusterMember.revocation_class,
    last_revoked_event_id: revClusterMember.event_id,
    peer_relationship: 'SIBLING',
    contamination_assessment: 'CLEAN_SEPARATION',
    gec_signature: stubSignature('gec-cluster-1'),
  }));
  ok(`ALE-011  contamination_assessment=${sibling7.contamination_assessment} -- agent-cluster-member-1's work is unaffected, per INV-4`);

  // =================================================================
  // 8. Causal-ordering violation (gap detection)
  // =================================================================
  section('8. Causal-ordering violation -- prior_event_id references nothing');

  try {
    ledger.append(buildALE004({
      prior_event_id: 'does-not-exist-' + randomUUID(),
      agent_id: 'agent-ghost',
      recovery_ref: randomUUID(),
      initiated_by: 'OPERATOR',
      initiator_ref: 'operator-x',
      revocation_ref: 'nonexistent-revocation',
      recovery_type: 'OPERATOR_REINSTATEMENT',
      gec_signature: stubSignature('gec-ghost'),
    }));
    console.log('  ✗ unexpected: should have rejected unreferenceable prior_event_id');
  } catch (err) {
    if (err instanceof ALECausalOrderingError) {
      expected(`gap rejected: ${err.message}`);
    } else throw err;
  }

  // =================================================================
  // 9. ALE-007 misuse -- fired for a non-R-8 revocation
  // =================================================================
  section('9. ALE-007 restricted to R-8 -- misuse against R-2 rejected');

  // rev1 above was R-2. Simulate someone incorrectly routing its
  // recovery through ALE-007 (external KIA reattestation) instead of
  // ALE-006 (ordinary credential restoration) -- this is exactly the
  // bug GAR-07's "R-3"->"R-8" relabel this pass was meant to prevent
  // from being ambiguous.
  const recMisuse = ledger.append(buildALE004({
    prior_event_id: rev1.event_id,
    agent_id: 'agent-alpha',
    recovery_ref: randomUUID(),
    initiated_by: 'OPERATOR',
    initiator_ref: 'operator-1',
    revocation_ref: rev1.event_id,
    recovery_type: 'KIA_REATTESTATION', // wrong choice for an R-2 revocation
    gec_signature: stubSignature('gec-alpha'),
  }));
  try {
    ledger.append(buildALE007({
      prior_event_id: recMisuse.event_id,
      recovery_ref: recMisuse.recovery_ref,
      gec_instance_id: 'gec-alpha',
      prior_attestation_id: 'attest-alpha-1',
      new_attestation_id: 'attest-alpha-2',
      new_cedar_policy_hash: 'sha256:' + randomUUID().replace(/-/g, ''),
      new_kernel_version: 'kernel-2.4.1',
      attestation_gap_duration: 10,
      sessions_during_gap: [],
      kia_verifier_signature: stubSignature('external-kia-verifier-svc-1'),
      kia_verifier_id: 'kia-verifier-svc-1',
    }));
    console.log('  ✗ unexpected: ALE-007 against an R-2 origin should have been rejected');
  } catch (err) {
    if (err instanceof ExternalSigningRequiredError) {
      expected(`ALE-007 misuse rejected: ${err.message}`);
    } else throw err;
  }

  // =================================================================
  // 10. ALE-008 blocked while a PARTIAL disposition is DEFER
  // =================================================================
  section('10. ALE-008 blocked -- unresolved (DEFER) PARTIAL state');

  const rev10 = ledger.append(buildALE001({
    prior_event_id: 'aep-event-' + randomUUID().slice(0, 8),
    session_id: 'session-eta',
    agent_id: 'agent-eta',
    mandate_jti: 'mjwt-eta-1',
    so_id: 'so://mission/eta/step-1',
    revocation_class: 'R-1',
    revocation_reason: 'CAP Tier 0-A prohibition violated',
    revocation_source: 'CAP_VIOLATION',
    revocation_type: 'DIRECT',
    authority_type: 'KERNEL',
    revocation_event_ref: 'mjwt-mandate-revoked-' + randomUUID().slice(0, 8), // MJWT-08 7.3 MANDATE_REVOKED
    trigger_event_ref: 'evt-tier0a-' + randomUUID().slice(0, 8),
    completion_state: 'PARTIAL',
    natural_breakpoint_reached: false,
    irreversible_actions_taken: true,
    rollback_available: false,
    so_state_at_revocation: 'mid_action',
    iterations_completed: 1,
    cascade_depth: 0,
    gec_signature: stubSignature('gec-eta'),
  }));
  const partial10 = ledger.append(buildALE003({
    prior_event_id: rev10.event_id,
    session_id: 'session-eta',
    so_id: 'so://mission/eta/step-1',
    so_state_at_suspension: 'mid_action',
    last_committed_action: 'unknown',
    last_committed_event_id: 'evt-eta-last',
    uncommitted_idp_ref: 'idp-eta-uncommitted',
    irreversible_actions: [],
    rollback_path: [],
    hem_escalation_id: randomUUID(),
    disposition_required_by: new Date(Date.now() + 86400_000).toISOString(),
    gec_signature: stubSignature('gec-eta'),
  }));
  const rec10 = ledger.append(buildALE004({
    prior_event_id: rev10.event_id,
    agent_id: 'agent-eta',
    recovery_ref: randomUUID(),
    initiated_by: 'OPERATOR',
    initiator_ref: 'operator-3',
    revocation_ref: rev10.event_id,
    recovery_type: 'OPERATOR_REINSTATEMENT',
    gec_signature: stubSignature('gec-eta'),
  }));
  const disp10 = ledger.append(buildALE005({
    prior_event_id: partial10.event_id,
    recovery_ref: rec10.recovery_ref,
    session_id: 'session-eta',
    so_id: 'so://mission/eta/step-1',
    disposition: 'DEFER',
    decided_by: 'operator-3',
    principal_signature: stubSignature('operator-3'),
    disposition_rationale: 'Tier 0-A violation under legal review -- disposition pending counsel',
    defer_deadline: new Date(Date.now() + 7 * 86400_000).toISOString(),
    gec_signature: stubSignature('gec-eta'),
  }));
  console.log(`  ALE-005  disposition=${disp10.disposition}, defer_deadline=${disp10.defer_deadline}`);

  const cred10 = ledger.append(buildALE006({
    prior_event_id: rec10.event_id,
    recovery_ref: rec10.recovery_ref,
    agent_id: 'agent-eta',
    credential_type: 'MJWT',
    new_credential_ref: 'mjwt-eta-2',
    old_credential_ref: 'mjwt-eta-1',
    rotation_method: 'REISSUANCE',
    pt_score_at_restoration: 0.6,
    gec_signature: stubSignature('gec-eta'),
  }));

  try {
    ledger.append(buildALE008({
      prior_event_id: cred10.event_id,
      recovery_ref: rec10.recovery_ref,
      agent_id: 'agent-eta',
      restored_by: 'OPERATOR',
      restoration_scope: 'FULL',
      prior_revocation_ref: rev10.event_id,
      partial_state_disposition_ref: disp10.event_id,
      pt_score_at_restoration: 0.6,
      gec_signature: stubSignature('gec-eta'),
    }));
    console.log('  ✗ unexpected: ALE-008 should have been blocked by the DEFER disposition');
  } catch (err) {
    if (err instanceof UnresolvedPartialStateError) {
      expected(`ALE-008 blocked: ${err.message}`);
    } else throw err;
  }
  console.log(`  hasMandateHold('agent-eta') = ${ledger.hasMandateHold('agent-eta')} (still held -- correctly not lifted)`);

  // =================================================================
  // 11. Mandate hold -> converted to revocation (MJWT-08 Section 7.7)
  // =================================================================
  section('11. External signal -> mandate HOLD -> principal converts to revocation');

  const held = ledger.append(buildMandateHeld({
    prior_event_id: null, // causal chain root for hold flows (Section 12.21)
    mandate_jti: 'mjwt-theta-1',
    hold_event_ref: 'mjwt-mandate-held-' + randomUUID().slice(0, 8),
    hold_type: 'DIRECT',
    authority_type: 'KERNEL',
    signal_source: 'CAEP_SIGNAL',
    hold_category: 'REPORTED_COMPROMISE',
    trigger_event_ref: 'caep-session-revoked-' + randomUUID().slice(0, 8),
    paused_session_ids: ['session-theta'],
    affected_descendant_count: 0,
    gec_signature: stubSignature('gec-theta'),
  }));
  console.log(`  ALE_MANDATE_HELD  isMandateHeld('mjwt-theta-1') = ${ledger.isMandateHeld('mjwt-theta-1')} (paused, not revoked)`);

  const released = ledger.append(buildMandateHoldReleased({
    prior_event_id: held.event_id,
    mandate_jti: 'mjwt-theta-1',
    release_event_ref: 'mjwt-hold-released-' + randomUUID().slice(0, 8),
    disposition: 'CONVERTED_TO_REVOCATION',
    authority_type: 'PRINCIPAL',
    releasing_principal: 'principal-theta',
    hold_duration_seconds: 1800,
    gec_signature: stubSignature('gec-theta'),
  }));
  console.log(`  ALE_MANDATE_HOLD_RELEASED  disposition=${released.disposition}`);

  const rev12 = ledger.append(buildALE001({
    prior_event_id: released.event_id, // Section 12.22: conversion links back to the release
    session_id: 'session-theta',
    agent_id: 'agent-theta',
    mandate_jti: 'mjwt-theta-1',
    so_id: 'so://mission/theta/step-2',
    revocation_class: 'R-8',
    authority_type: 'PRINCIPAL',
    revocation_event_ref: 'mjwt-mandate-revoked-' + randomUUID().slice(0, 8),
    revocation_reason: 'Principal confirmed reported credential compromise',
    revocation_type: 'DIRECT',
    revocation_source: 'CAEP_SIGNAL', // valid: held first, converted under PRINCIPAL authority
    trigger_event_ref: held.trigger_event_ref,
    completion_state: 'CLEAN',
    natural_breakpoint_reached: true,
    irreversible_actions_taken: false,
    rollback_available: true,
    so_state_at_revocation: 'paused',
    iterations_completed: 4,
    cascade_depth: 0,
    gec_signature: stubSignature('gec-theta'),
  }));
  ok(`ALE-001  revocation_source=${rev12.revocation_source} authority_type=${rev12.authority_type} (conforming)`);
  console.log(`  isMandateHeld('mjwt-theta-1') = ${ledger.isMandateHeld('mjwt-theta-1')}`);

  // =================================================================
  // 12. Vocabulary conformance (negative paths)
  // =================================================================
  section('12. Vocabulary conformance -- non-conforming ALE-001 entries rejected');

  const badBase = {
    prior_event_id: 'aep-event-' + randomUUID().slice(0, 8),
    session_id: 'session-iota',
    agent_id: 'agent-iota',
    mandate_jti: 'mjwt-iota-1',
    so_id: 'so://mission/iota/step-1',
    revocation_class: 'R-1' as const,
    revocation_event_ref: 'mjwt-mandate-revoked-' + randomUUID().slice(0, 8),
    revocation_reason: 'test',
    trigger_event_ref: 'evt-iota',
    completion_state: 'CLEAN' as const,
    natural_breakpoint_reached: true,
    irreversible_actions_taken: false,
    rollback_available: true,
    so_state_at_revocation: 'idle',
    iterations_completed: 0,
    cascade_depth: 0,
    gec_signature: stubSignature('gec-iota'),
  };
  try {
    ledger.append(buildALE001({ ...badBase, authority_type: 'KERNEL', revocation_type: 'DIRECT', revocation_source: 'CAEP_SIGNAL' }));
    console.log('  ✗ unexpected: CAEP_SIGNAL + KERNEL accepted');
  } catch (err) {
    if (err instanceof VocabularyConformanceError) expected(`CAEP_SIGNAL + KERNEL rejected`);
    else throw err;
  }
  try {
    ledger.append(buildALE001({ ...badBase, authority_type: 'OPERATOR', revocation_type: 'CASCADE', revocation_source: 'OPERATOR' }));
    console.log('  ✗ unexpected: CASCADE without cascade_root_jti accepted');
  } catch (err) {
    if (err instanceof VocabularyConformanceError) expected(`revocation_type CASCADE without cascade_root_jti rejected`);
    else throw err;
  }

  // =================================================================
  // Summary
  // =================================================================
  section('Summary');
  console.log(`  Total ALE entries appended: ${ledger.getAll().length}`);
  const gaps = ledger.verifyNoGaps();
  console.log(`  Gap check: ${gaps.valid ? 'PASS -- no causal gaps' : `FAIL at ${gaps.missingAt}`}`);
  line();
}

main();
