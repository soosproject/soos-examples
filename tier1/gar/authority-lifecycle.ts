// GAR — Authority Lifecycle Events (ALE-001 through ALE-012, plus the
// mandate-hold events ALE_MANDATE_HELD / ALE_MANDATE_HOLD_RELEASED)
// draft-sato-soos-gar-13 Section 12
//
// GAR-13 ALIGNMENT (1 Nov 2026): field names follow the shared vocabulary
// with KIA-09 Section 8.1 and MJWT-08 Section 7 (GAR-13 Section 12.1):
// mandate_jwt_id -> mandate_jti family, revoked_mandate_jwt_id ->
// revoked_jti; ALE-001 gains authority_type, revocation_event_ref,
// revocation_type ("DIRECT" | "CASCADE") and cascade_root_jti;
// revocation_source loses CASCADE and gains PRINCIPAL / FEDERATED_ISSUER;
// revocation_class runs R-1..R-9; hold events added (Sections 12.21-12.22).
//
// NOTE ON NAMING: this module intentionally does NOT reuse the `ALEType`
// enum exported from gar-core.ts. That enum (SESSION_START, CEDAR_PERMIT,
// SESSION_HALTED_CLEAN, etc.) predates GAR-07 Section 12's real Authority
// Lifecycle Event category and uses a different, incompatible numbering in
// its own stale comments (its "// ALE-002/ALE-003/ALE-004" refer to
// SESSION_HALTED_CLEAN/PARTIAL/UNKNOWN — nothing like GAR-07's actual
// ALE-002 (ALE_AUTHORITY_SUSPENDED) / ALE-003 (ALE_PARTIAL_STATE_RECORDED) /
// ALE-004 (ALE_RECOVERY_INITIATED)). Renaming gar-core.ts's `ALEType` is a
// separate cleanup task, out of scope here — flagged, not fixed, since it
// touches the existing Session Audit Record path this module doesn't own.
// This module's own event kinds are distinguished via `event_type` string
// literals matching the draft's own wire values exactly, not a shared enum.

import { randomUUID } from 'crypto';

// ---------------------------------------------------------------------
// Shared enumerations (Section 12 field definitions)
// ---------------------------------------------------------------------

// MAD Section 3.6.4 — Trigger classes R-1 through R-9 (GAR-13 Sections
// 12.3, 12.11). R-7 is DEADLOCK, R-8 is Compromise; R-9 is defined in MAD
// and carried here as an opaque class value.
export type RevocationClass =
  | 'R-1' | 'R-2' | 'R-3' | 'R-4' | 'R-5' | 'R-6' | 'R-7' | 'R-8' | 'R-9';

export type CompletionState = 'CLEAN' | 'PARTIAL' | 'UNKNOWN';

// Triggering mechanism only -- no CASCADE value (GAR-13 Section 12.3).
// Whether an entry is a direct or cascade revocation is revocation_type.
export type RevocationSource =
  | 'CAEP_SIGNAL' | 'OPERATOR' | 'CAP_VIOLATION' | 'PT_THRESHOLD'
  | 'KIA_ATTESTATION' | 'PRINCIPAL' | 'FEDERATED_ISSUER';

// KIA-09 Section 8.1 / MJWT-08 Section 7.2 casing, verbatim.
export type RevocationType = 'DIRECT' | 'CASCADE';

// MJWT-08 Section 7.6: by what right the mandate was revoked.
export type AuthorityType = 'PRINCIPAL' | 'KERNEL' | 'OPERATOR';

// Mandate holds (GAR-13 Sections 12.21-12.22, MJWT-08 Section 7.7)
export type HoldType = 'DIRECT' | 'CASCADE';
export type HoldSignalSource =
  | 'CAEP_SIGNAL' | 'RISC_SIGNAL' | 'WISE_SIGNAL' | 'MLE_SIGNAL'
  | 'THIRD_PARTY_REPORT' | 'KERNEL_FINDING' | 'ISSUER_SUSPENSION';
export type HoldCategory = 'REPORTED_COMPROMISE' | 'REPORTED_VIOLATION' | 'PENDING_REVIEW';
export type HoldReleaseDisposition = 'RESUMED' | 'CONVERTED_TO_REVOCATION';

export type SuspensionReason =
  | 'CREDENTIAL_COMPROMISE' | 'OPERATOR_HOLD' | 'REGULATORY_HOLD'
  | 'KIA_ATTESTATION_FAILURE' | 'PT_SYSTEMIC_FAILURE';

export type SuspensionSource = 'RISC_SIGNAL' | 'OPERATOR' | 'REGULATORY_AUTHORITY';

export type RecoveryInitiator = 'OPERATOR' | 'HUMAN_PRINCIPAL' | 'REGULATORY_AUTHORITY';

export type RecoveryType =
  | 'CREDENTIAL_ROTATION' | 'KIA_REATTESTATION' | 'PT_REHABILITATION'
  | 'OPERATOR_REINSTATEMENT' | 'REGULATORY_CLEARANCE';

export type Disposition = 'ROLLBACK' | 'COMPLETE' | 'ABANDON' | 'DEFER';

export type CredentialType = 'MJWT' | 'KIA_ATTESTATION' | 'WIMSE_SVID' | 'ALL';

export type RotationMethod = 'KEY_ROTATION' | 'REATTESTATION' | 'REISSUANCE';

export type RestoredBy = 'OPERATOR' | 'REGULATORY_AUTHORITY';

export type RestorationScope = 'FULL' | 'CONSTRAINED';

export type ChildCompletionState = 'CLEAN' | 'PARTIAL' | 'UNKNOWN';

export type ParentGoalImpact = 'BLOCKING' | 'NON_BLOCKING' | 'UNKNOWN';

export type AggregationRule = 'QUORUM' | 'ALL_COMPLETE' | 'FIRST_COMPLETE' | 'ANY';

export type ClusterAchievability = 'ACHIEVABLE' | 'DEGRADED' | 'UNACHIEVABLE';

export type RecommendedDisposition = 'CONTINUE' | 'HALT_REMAINING' | 'REASSIGN_REVOKED';

export type PeerRelationship = 'SIBLING' | 'COUSIN' | 'UNRELATED_SAME_SO';

export type ContaminationAssessment = 'CLEAN_SEPARATION' | 'INTERLEAVED' | 'UNKNOWN';

export type TreeRecoveryStrategy =
  | 'REDELEGATION' | 'PARTIAL_COMPLETION' | 'FULL_ABORT' | 'HUMAN_DECISION';

export type MandateHoldScope = 'SUBTREE_ONLY' | 'FULL_TREE';

// Section 8.9's ed25519 signature shape, reused by every ALE entry.
export interface Ed25519Signature {
  algorithm: 'Ed25519';
  key_id: string;
  signature: string;
}

interface ALEBase {
  event_id: string;              // UUID v7 per spec; randomUUID() stands in for v7 here
  prior_event_id: string | null; // null only for ALE-001/ALE-002 chain roots
  occurred_at: string;           // ISO 8601
}

// ---------------------------------------------------------------------
// ALE-001: ALE_SESSION_REVOKED  (Section 12.3)
// Causal chain root for single-session revocations.
// ---------------------------------------------------------------------
export interface ALE001SessionRevoked extends ALEBase {
  event_type: 'ALE_SESSION_REVOKED';
  session_id: string;
  agent_id: string;
  mandate_jti: string;
  so_id: string;
  revocation_class: RevocationClass;
  authority_type: AuthorityType;       // MUST equal the MANDATE_REVOKED entry's (MJWT-08 7.6)
  revocation_event_ref: string;        // event_id of the MANDATE_REVOKED entry (MJWT-08 7.3)
  revocation_reason: string;
  revocation_type: RevocationType;     // MUST equal the MANDATE_REVOKED entry's
  cascade_root_jti?: string;           // present only when revocation_type === 'CASCADE'
  revocation_source: RevocationSource; // for CASCADE: the mechanism at cascade_root_jti
  trigger_event_ref: string;
  completion_state: CompletionState;
  natural_breakpoint_reached: boolean;
  irreversible_actions_taken: boolean;
  rollback_available: boolean;
  so_state_at_revocation: string;
  iterations_completed: number;
  cascade_depth: number;
  gec_signature: Ed25519Signature;
}

// ---------------------------------------------------------------------
// ALE-002: ALE_AUTHORITY_SUSPENDED  (Section 12.4)
// Causal chain root for account-level suspension flows.
// ---------------------------------------------------------------------
export interface ALE002AuthoritySuspended extends ALEBase {
  event_type: 'ALE_AUTHORITY_SUSPENDED';
  agent_id: string;
  suspension_reason: SuspensionReason;
  suspension_source: SuspensionSource;
  trigger_event_ref: string;
  affected_session_ids: string[];
  affected_so_ids: string[];
  recovery_permitted: boolean;
  operator_authority_ref?: string; // REQUIRED when suspension_source is OPERATOR
  gec_signature: Ed25519Signature;
}

// ---------------------------------------------------------------------
// ALE-003: ALE_PARTIAL_STATE_RECORDED  (Section 12.5)
// prior_event_id MUST reference ALE_SESSION_REVOKED.
// ---------------------------------------------------------------------
export interface ALE003PartialStateRecorded extends ALEBase {
  event_type: 'ALE_PARTIAL_STATE_RECORDED';
  session_id: string;
  so_id: string;
  so_state_at_suspension: string;
  last_committed_action: string;
  last_committed_event_id: string;
  uncommitted_idp_ref: string;
  irreversible_actions: { action: string; event_id: string; occurred_at: string }[];
  rollback_path: { action: string; from_state: string; to_state: string }[];
  hem_escalation_id: string;   // UUID v7
  disposition_required_by: string; // ISO 8601
  gec_signature: Ed25519Signature;
}

// ---------------------------------------------------------------------
// ALE-004: ALE_RECOVERY_INITIATED  (Section 12.6)
// Establishes the mandate_hold gate. prior_event_id MUST reference
// ALE-001 or ALE-002.
// ---------------------------------------------------------------------
export interface ALE004RecoveryInitiated extends ALEBase {
  event_type: 'ALE_RECOVERY_INITIATED';
  agent_id: string;
  recovery_ref: string; // UUID v7
  initiated_by: RecoveryInitiator;
  initiator_ref: string;
  revocation_ref: string;
  recovery_type: RecoveryType;
  estimated_completion?: string;
  mandate_hold: true;   // normatively required
  gec_signature: Ed25519Signature;
}

// ---------------------------------------------------------------------
// ALE-005: ALE_PARTIAL_STATE_DISPOSITION  (Section 12.7)
// prior_event_id MUST reference ALE_PARTIAL_STATE_RECORDED.
// ---------------------------------------------------------------------
export interface ALE005PartialStateDisposition extends ALEBase {
  event_type: 'ALE_PARTIAL_STATE_DISPOSITION';
  recovery_ref: string;
  session_id: string;
  so_id: string;
  disposition: Disposition;
  decided_by: string;
  principal_signature: Ed25519Signature;
  disposition_rationale: string;
  rollback_target_state?: string;      // REQUIRED when disposition === ROLLBACK
  completion_agent_id?: string;        // REQUIRED when disposition === COMPLETE
  completion_mandate_ref?: string;     // REQUIRED when disposition === COMPLETE
  abandon_compensation?: { action: string; rationale: string }[];
  defer_deadline?: string;             // REQUIRED when disposition === DEFER (ISO 8601)
  gec_signature: Ed25519Signature;
}

// ---------------------------------------------------------------------
// ALE-006: ALE_CREDENTIAL_RESTORED  (Section 12.8)
// ---------------------------------------------------------------------
export interface ALE006CredentialRestored extends ALEBase {
  event_type: 'ALE_CREDENTIAL_RESTORED';
  recovery_ref: string;
  agent_id: string;
  credential_type: CredentialType;
  new_credential_ref: string;
  old_credential_ref: string;
  rotation_method: RotationMethod;
  pt_score_at_restoration: number; // 0.0–1.0
  gec_signature: Ed25519Signature;
}

// ---------------------------------------------------------------------
// ALE-007: ALE_KIA_REATTESTATION_COMPLETED  (Section 12.9)
// CRITICAL: fires for R-8 (Compromise) revocations only (fixed this pass
// -- GAR-07 previously mislabeled this "R-3", which is MAD's Non-Response
// class, not Attestation Integrity Failure). MUST be signed by an
// external KIA Verification Service, never the GEC being re-attested --
// `kia_verifier_signature` REPLACES `gec_signature` on this event type
// specifically; there is no `gec_signature` field here at all.
// ---------------------------------------------------------------------
export interface ALE007KiaReattestationCompleted extends ALEBase {
  event_type: 'ALE_KIA_REATTESTATION_COMPLETED';
  recovery_ref: string;
  gec_instance_id: string;
  prior_attestation_id: string;
  new_attestation_id: string;
  new_cedar_policy_hash: string;
  new_kernel_version: string;
  attestation_gap_duration: number; // seconds
  sessions_during_gap: string[];
  kia_verifier_signature: Ed25519Signature; // NOT gec_signature -- see above
  kia_verifier_id: string;
}

// ---------------------------------------------------------------------
// ALE-008: ALE_AUTHORITY_RESTORED  (Section 12.10)
// Normative endpoint of the recovery lifecycle; lifts mandate_hold.
// prior_event_id MUST reference ALE-006 or ALE-007.
// ---------------------------------------------------------------------
export interface ALE008AuthorityRestored extends ALEBase {
  event_type: 'ALE_AUTHORITY_RESTORED';
  recovery_ref: string;
  agent_id: string;
  restored_by: RestoredBy;
  restoration_scope: RestorationScope;
  constraints?: string[]; // Cedar fragments; REQUIRED when CONSTRAINED
  prior_revocation_ref: string;
  partial_state_disposition_ref?: string; // REQUIRED if any PARTIAL states existed
  pt_score_at_restoration: number;
  mandate_hold_lifted: true;
  new_mandate_jti?: string;
  gec_signature: Ed25519Signature;
}

// ---------------------------------------------------------------------
// ALE-009: ALE_DELEGATION_CHILD_REVOKED  (Section 12.11)
// Fires on the parent agent's GEC session when a child mandate is
// revoked.
// ---------------------------------------------------------------------
export interface ALE009DelegationChildRevoked extends ALEBase {
  event_type: 'ALE_DELEGATION_CHILD_REVOKED';
  parent_session_id: string;
  parent_mandate_jti: string;
  revoked_child_mandate_jti: string;
  revoked_agent_id: string;
  revoked_so_id: string;
  revocation_class: RevocationClass;
  child_completion_state: ChildCompletionState;
  delegation_depth: number;
  cascade_depth_remaining: number;
  cluster_id: string | null;
  parent_goal_impact: ParentGoalImpact;
  gec_signature: Ed25519Signature;
}

// ---------------------------------------------------------------------
// ALE-010: ALE_CLUSTER_PARTIAL_REVOCATION  (Section 12.12)
// Fires on the SO Cluster coordination record when any cluster member
// is revoked. prior_event_id MUST reference the revoked member's
// ALE_SESSION_REVOKED.
// ---------------------------------------------------------------------
export interface ALE010ClusterPartialRevocation extends ALEBase {
  event_type: 'ALE_CLUSTER_PARTIAL_REVOCATION';
  cluster_id: string;
  orchestrator_session_id: string;
  revoked_member_agent_id: string;
  revoked_member_so_id: string;
  revoked_completion_state: CompletionState;
  members_still_active: string[];
  members_completed: string[];
  members_revoked: string[];
  aggregation_rule: AggregationRule;
  cluster_achievability: ClusterAchievability;
  recommended_disposition: RecommendedDisposition;
  gec_signature: Ed25519Signature;
}

// ---------------------------------------------------------------------
// ALE-011: ALE_SIBLING_REVOCATION_NOTICE  (Section 12.13)
// Receipt does NOT invalidate the notified agent's work (INV-4
// horizontal non-contamination).
// ---------------------------------------------------------------------
export interface ALE011SiblingRevocationNotice extends ALEBase {
  event_type: 'ALE_SIBLING_REVOCATION_NOTICE';
  notified_session_id: string;
  notified_agent_id: string;
  shared_so_id: string;
  revoked_agent_id: string;
  revoked_session_id: string;
  revoked_jti: string;
  revocation_class: RevocationClass;
  last_revoked_event_id: string;
  peer_relationship: PeerRelationship;
  contamination_assessment: ContaminationAssessment;
  gec_signature: Ed25519Signature;
}

// ---------------------------------------------------------------------
// ALE-012: ALE_DELEGATION_TREE_RECOVERY_INITIATED  (Section 12.14)
// Fires on the root orchestrator session when recovery begins for any
// revoked descendant.
// ---------------------------------------------------------------------
export interface ALE012DelegationTreeRecoveryInitiated extends ALEBase {
  event_type: 'ALE_DELEGATION_TREE_RECOVERY_INITIATED';
  root_mandate_jti: string;
  orchestrator_session_id: string;
  recovery_ref: string; // UUID v7, tree-level
  revoked_subtree_root: string;
  revoked_agents: { agent_id: string; mandate_jti: string; completion_state: CompletionState; so_id: string }[];
  still_active_agents: { agent_id: string; mandate_jti: string; so_id: string }[];
  partial_so_ids: string[];
  tree_recovery_strategy: TreeRecoveryStrategy;
  mandate_hold_scope: MandateHoldScope;
  gec_signature: Ed25519Signature;
}

// ---------------------------------------------------------------------
// ALE_MANDATE_HELD  (Section 12.21, NEW in -12; cascade_root_jti NEW in -13)
// Causal chain root for hold flows. Mandate-scoped (covers descendants),
// unlike ALE-002 which is agent-scoped.
// ---------------------------------------------------------------------
export interface ALEMandateHeld extends ALEBase {
  event_type: 'ALE_MANDATE_HELD';
  mandate_jti: string;
  hold_event_ref: string;            // event_id of the MJWT MANDATE_HELD entry
  hold_type: HoldType;
  cascade_root_jti?: string;         // present only when hold_type === 'CASCADE'
  authority_type: AuthorityType;
  signal_source: HoldSignalSource;
  hold_category: HoldCategory;
  trigger_event_ref: string;
  paused_session_ids: string[];
  affected_descendant_count: number;
  gec_signature: Ed25519Signature;
}

// ---------------------------------------------------------------------
// ALE_MANDATE_HOLD_RELEASED  (Section 12.22, NEW in -12)
// prior_event_id MUST reference the corresponding ALE_MANDATE_HELD.
// ---------------------------------------------------------------------
export interface ALEMandateHoldReleased extends ALEBase {
  event_type: 'ALE_MANDATE_HOLD_RELEASED';
  mandate_jti: string;
  release_event_ref: string;         // event_id of the MJWT MANDATE_HOLD_RELEASED entry
  disposition: HoldReleaseDisposition;
  authority_type: 'PRINCIPAL' | 'OPERATOR';
  releasing_principal: string;
  hold_duration_seconds: number;
  gec_signature: Ed25519Signature;
}

export type AuthorityLifecycleEvent =
  | ALE001SessionRevoked
  | ALE002AuthoritySuspended
  | ALE003PartialStateRecorded
  | ALE004RecoveryInitiated
  | ALE005PartialStateDisposition
  | ALE006CredentialRestored
  | ALE007KiaReattestationCompleted
  | ALE008AuthorityRestored
  | ALE009DelegationChildRevoked
  | ALE010ClusterPartialRevocation
  | ALE011SiblingRevocationNotice
  | ALE012DelegationTreeRecoveryInitiated
  | ALEMandateHeld
  | ALEMandateHoldReleased;

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

export class ALECausalOrderingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ALECausalOrderingError';
  }
}

export class AgentInRecoveryError extends Error {
  readonly code = 'AGENT_IN_RECOVERY';
  constructor(agent_id: string) {
    super(`Section 12.6: MJWT issuance rejected -- agent ${agent_id} has an active mandate_hold`);
    this.name = 'AgentInRecoveryError';
  }
}

export class ExternalSigningRequiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ExternalSigningRequiredError';
  }
}

export class VocabularyConformanceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VocabularyConformanceError';
  }
}

export class UnresolvedPartialStateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnresolvedPartialStateError';
  }
}

// ---------------------------------------------------------------------
// AuthorityLedger — append-only store + causal-chain and business-rule
// enforcement for the ALE-001..012 category (Section 12).
// ---------------------------------------------------------------------
export class AuthorityLedger {
  private entries: AuthorityLifecycleEvent[] = [];
  private byId = new Map<string, AuthorityLifecycleEvent>();
  // agent_id -> recovery_ref of the active hold, or undefined if none
  private mandateHold = new Map<string, string>();
  // recovery_ref -> set of {session_id, so_id} keys with unresolved
  // (DEFER, or no disposition committed yet) PARTIAL state
  private unresolvedPartial = new Map<string, Set<string>>();
  // mandate_jti -> event_id of the active ALE_MANDATE_HELD
  private activeHolds = new Map<string, string>();

  // Per Section 12.2/12.3-12.14: which prior ALE event_type(s) each type's
  // prior_event_id is REQUIRED to reference, when the spec pins it to a
  // specific type. Types not listed here either don't require a same-
  // ledger reference at all (ALE-001/002, opaque external AEP/root
  // references) or reference "the last event in a *different* session"
  // (ALE-009's parent session, ALE-011's notified session) -- a GAR
  // Event Log / SAR entry this ledger doesn't own, not another ALE
  // entry, so it's not checked against this store either.
  private static readonly REQUIRED_PRIOR_TYPE: Partial<Record<AuthorityLifecycleEvent['event_type'], AuthorityLifecycleEvent['event_type'][]>> = {
    ALE_PARTIAL_STATE_RECORDED: ['ALE_SESSION_REVOKED'],
    ALE_RECOVERY_INITIATED: ['ALE_SESSION_REVOKED', 'ALE_AUTHORITY_SUSPENDED'],
    ALE_PARTIAL_STATE_DISPOSITION: ['ALE_PARTIAL_STATE_RECORDED'],
    ALE_CREDENTIAL_RESTORED: ['ALE_RECOVERY_INITIATED'],
    ALE_KIA_REATTESTATION_COMPLETED: ['ALE_RECOVERY_INITIATED'],
    ALE_AUTHORITY_RESTORED: ['ALE_CREDENTIAL_RESTORED', 'ALE_KIA_REATTESTATION_COMPLETED'],
    ALE_CLUSTER_PARTIAL_REVOCATION: ['ALE_SESSION_REVOKED'],
    ALE_DELEGATION_TREE_RECOVERY_INITIATED: ['ALE_DELEGATION_CHILD_REVOKED'],
    ALE_MANDATE_HOLD_RELEASED: ['ALE_MANDATE_HELD'],
  };

  // Chain roots that MAY carry prior_event_id === null.
  private static readonly NULLABLE_PRIOR = new Set<AuthorityLifecycleEvent['event_type']>([
    'ALE_AUTHORITY_SUSPENDED', 'ALE_MANDATE_HELD',
  ]);

  // Event types whose prior_event_id is a REQUIRED opaque reference to
  // something outside this ledger (an AEP event, or another session's
  // GAR Event Log entry) -- required to be present, but not checked
  // against this store's own membership.
  private static readonly EXTERNAL_PRIOR_REQUIRED = new Set<AuthorityLifecycleEvent['event_type']>([
    'ALE_SESSION_REVOKED', 'ALE_DELEGATION_CHILD_REVOKED', 'ALE_SIBLING_REVOCATION_NOTICE',
    'ALE_MANDATE_HELD',
  ]);

  /** Section 12.2: causal completeness, enforced per event type:
   *  - ALE-001 and ALE-002 are the only true chain roots. ALE-001 still
   *    REQUIRES a prior_event_id (its own field doc: "causal link to
   *    last AEP event; REQUIRED"), just not one validated against this
   *    ledger. ALE-002 truly has none (account-level suspension has no
   *    single triggering session event) -- null is accepted.
   *  - ALE-009/ALE-011 reference the last event in a *different*
   *    session's own Event Log, not this ledger -- required, opaque,
   *    unchecked here.
   *  - Every other type is checked against REQUIRED_PRIOR_TYPE: the
   *    referenced entry must exist in this ledger AND be one of the
   *    specific types the spec names (Section 12.5-12.14), not merely
   *    "any prior entry" -- e.g. ALE-008 rejects a prior_event_id that
   *    resolves to an ALE-004 instead of the required ALE-006/ALE-007.
   */
  append<T extends AuthorityLifecycleEvent>(event: T): T {
    const requiredTypes = AuthorityLedger.REQUIRED_PRIOR_TYPE[event.event_type];
    const externalOk = AuthorityLedger.EXTERNAL_PRIOR_REQUIRED.has(event.event_type);

    if (!AuthorityLedger.NULLABLE_PRIOR.has(event.event_type) && !event.prior_event_id) {
      throw new ALECausalOrderingError(
        `${event.event_type}: prior_event_id is REQUIRED (only ALE-002 and ALE_MANDATE_HELD may have prior_event_id === null)`
      );
    }

    if (requiredTypes && event.prior_event_id) {
      const prior = this.byId.get(event.prior_event_id);
      if (!prior) {
        throw new ALECausalOrderingError(
          `${event.event_type}: prior_event_id ${event.prior_event_id} does not reference an existing ALE entry -- gap detected (Section 12.2)`
        );
      }
      if (!requiredTypes.includes(prior.event_type)) {
        throw new ALECausalOrderingError(
          `${event.event_type}: prior_event_id ${event.prior_event_id} resolves to ${prior.event_type}, but this event requires one of [${requiredTypes.join(', ')}]`
        );
      }
    } else if (!requiredTypes && !externalOk && !AuthorityLedger.NULLABLE_PRIOR.has(event.event_type) && event.prior_event_id) {
      // Shouldn't happen given the two static sets above cover every
      // event type, but fail loudly rather than silently skip checking
      // a type nobody classified.
      throw new ALECausalOrderingError(
        `${event.event_type}: unclassified for causal-ordering validation -- add it to REQUIRED_PRIOR_TYPE or EXTERNAL_PRIOR_REQUIRED`
      );
    }

    this.enforceBusinessRules(event);

    this.entries.push(event);
    this.byId.set(event.event_id, event);
    return event;
  }

  private enforceBusinessRules(event: AuthorityLifecycleEvent): void {
    switch (event.event_type) {
      case 'ALE_SESSION_REVOKED': {
        // Section 12.3: PARTIAL/UNKNOWN completion_state requires an
        // immediate ALE-003; the caller is responsible for committing it.
        // Shared-vocabulary rules (GAR-13 Section 12.3, RESTORED in -13):
        if ((event.revocation_type === 'CASCADE') !== (event.cascade_root_jti !== undefined)) {
          throw new VocabularyConformanceError(
            'ALE-001: cascade_root_jti MUST be present when revocation_type is "CASCADE" and absent when "DIRECT" (Section 12.3)'
          );
        }
        if ((event.revocation_source as string) === 'CASCADE') {
          throw new VocabularyConformanceError(
            'ALE-001: revocation_source has no CASCADE value in GAR-13 -- use revocation_type "CASCADE" with the root mechanism as revocation_source'
          );
        }
        // Section 12.3: CAEP_SIGNAL + KERNEL is evidence of a non-conforming
        // GEC (an external signal alone only holds, MJWT-08 Section 7.7).
        // Auditors SHOULD flag it; this sample GEC refuses to write it.
        if (event.revocation_source === 'CAEP_SIGNAL' && event.authority_type === 'KERNEL') {
          throw new VocabularyConformanceError(
            'ALE-001: revocation_source CAEP_SIGNAL with authority_type KERNEL -- an external signal alone does not revoke (MJWT-08 Section 7.7); hold first, then convert under PRINCIPAL or OPERATOR authority'
          );
        }
        break;
      }
      case 'ALE_MANDATE_HELD': {
        if ((event.hold_type === 'CASCADE') !== (event.cascade_root_jti !== undefined)) {
          throw new VocabularyConformanceError(
            'ALE_MANDATE_HELD: cascade_root_jti MUST be present when hold_type is CASCADE and absent when DIRECT (Section 12.21, KIA-09 Section 8.1 HoldRecord)'
          );
        }
        this.activeHolds.set(event.mandate_jti, event.event_id);
        break;
      }
      case 'ALE_MANDATE_HOLD_RELEASED': {
        const held = this.byId.get(event.prior_event_id!) as ALEMandateHeld | undefined;
        if (held && held.mandate_jti !== event.mandate_jti) {
          throw new ALECausalOrderingError(
            `ALE_MANDATE_HOLD_RELEASED: mandate_jti ${event.mandate_jti} does not match the referenced ALE_MANDATE_HELD (${held.mandate_jti})`
          );
        }
        this.activeHolds.delete(event.mandate_jti);
        break;
      }
      case 'ALE_RECOVERY_INITIATED': {
        if (event.mandate_hold !== true) {
          throw new ALECausalOrderingError(
            'ALE-004 mandate_hold MUST be true (Section 12.6) -- this is not optional'
          );
        }
        this.mandateHold.set(event.agent_id, event.recovery_ref);
        break;
      }
      case 'ALE_PARTIAL_STATE_DISPOSITION': {
        const key = `${event.recovery_ref}:${event.session_id}:${event.so_id}`;
        const set = this.unresolvedPartial.get(event.recovery_ref) ?? new Set<string>();
        if (event.disposition === 'DEFER') {
          set.add(key);
        } else {
          set.delete(key);
        }
        this.unresolvedPartial.set(event.recovery_ref, set);
        break;
      }
      case 'ALE_KIA_REATTESTATION_COMPLETED': {
        // The fix this pass: this entry corresponds to R-8 (Compromise)
        // revocations specifically (GAR-07 Section 12.1/12.9, corrected
        // from a stale "R-3" mislabel). Verify the originating
        // ALE_SESSION_REVOKED, reachable by walking prior_event_id back
        // through the ALE-004 recovery-initiation link, was actually R-8.
        const originClass = this.findOriginatingRevocationClass(event);
        if (originClass !== null && originClass !== 'R-8') {
          throw new ExternalSigningRequiredError(
            `ALE-007 fired for a ${originClass} revocation -- Section 12.1/12.9 restrict ALE-007 to R-8 (Compromise) only; a non-R-8 recovery should use ALE-006 (Credential Restored) instead`
          );
        }
        // kia_verifier_signature replaces gec_signature entirely on this
        // event type -- there is no gec_signature field to fall back to,
        // so a caller building this event without a real external
        // verifier's signature has nowhere to hide the gap. Nothing
        // further to enforce here at the type level; documented for
        // emphasis since this is the exact bug GAR-07's fix targets
        // (external signing is REQUIRED for R-8, and only for R-8).
        break;
      }
      case 'ALE_AUTHORITY_RESTORED': {
        if (event.mandate_hold_lifted !== true) {
          throw new ALECausalOrderingError(
            'ALE-008 mandate_hold_lifted MUST be true (Section 12.10)'
          );
        }
        const unresolved = this.unresolvedPartial.get(event.recovery_ref);
        if (unresolved && unresolved.size > 0) {
          throw new UnresolvedPartialStateError(
            `ALE-008 MUST NOT be committed while ${unresolved.size} PARTIAL state(s) for recovery_ref ${event.recovery_ref} remain DEFER or unresolved (Section 12.7)`
          );
        }
        // Lift the hold for whichever agent this recovery_ref belongs to.
        for (const [agent_id, ref] of this.mandateHold.entries()) {
          if (ref === event.recovery_ref) {
            this.mandateHold.delete(agent_id);
          }
        }
        break;
      }
      case 'ALE_CLUSTER_PARTIAL_REVOCATION': {
        if (event.cluster_achievability === 'UNACHIEVABLE'
          && event.recommended_disposition !== 'HALT_REMAINING') {
          throw new ALECausalOrderingError(
            'ALE-010: cluster_achievability UNACHIEVABLE MUST set recommended_disposition HALT_REMAINING (Section 12.12)'
          );
        }
        break;
      }
      default:
        break;
    }
  }

  /** Walk prior_event_id back from an ALE-006/ALE-007 through the
   * ALE-004 that established the recovery, then to the ALE-001/ALE-002
   * chain root, to find the revocation_class that started this recovery
   * flow. Returns null if the chain root is ALE-002 (account-level
   * suspension has no revocation_class -- see suspension_reason
   * instead) or if the chain can't be walked (shouldn't happen given
   * append()'s own causal-ordering check, but this is defensive).
   */
  private findOriginatingRevocationClass(
    fromEvent: AuthorityLifecycleEvent
  ): RevocationClass | null {
    let current: AuthorityLifecycleEvent | undefined = fromEvent;
    const seen = new Set<string>();
    while (current) {
      if (seen.has(current.event_id)) return null; // cycle guard, shouldn't happen
      seen.add(current.event_id);
      if (current.event_type === 'ALE_SESSION_REVOKED') {
        return current.revocation_class;
      }
      if (current.event_type === 'ALE_AUTHORITY_SUSPENDED') {
        return null; // account-level suspension has no revocation_class
      }
      if (!current.prior_event_id) return null;
      current = this.byId.get(current.prior_event_id);
    }
    return null;
  }

  /** True if the given agent currently has an active mandate_hold.
   * A GEC MUST reject MJWT issuance while this is true (Section 12.6).
   */
  hasMandateHold(agent_id: string): boolean {
    return this.mandateHold.has(agent_id);
  }

  /** Simulates the GEC-side MJWT issuance gate check. Throws
   * AgentInRecoveryError (error code AGENT_IN_RECOVERY) if the agent has
   * an active mandate_hold; otherwise returns normally.
   */
  assertCanIssueMandate(agent_id: string): void {
    if (this.hasMandateHold(agent_id)) {
      throw new AgentInRecoveryError(agent_id);
    }
  }

  /** True if the mandate currently has an active hold (MJWT-08 Section 7.7):
   * sessions under it are paused, not revoked. */
  isMandateHeld(mandate_jti: string): boolean {
    return this.activeHolds.has(mandate_jti);
  }

  getById(event_id: string): AuthorityLifecycleEvent | undefined {
    return this.byId.get(event_id);
  }

  getAll(): readonly AuthorityLifecycleEvent[] {
    return this.entries;
  }

  /** Section 12.2 gap detection: verifies every entry whose
   * prior_event_id is required to resolve within this ledger
   * (REQUIRED_PRIOR_TYPE entries) actually does. Skips ALE-001/002
   * (opaque external root references) and ALE-009/011 (opaque
   * references into a different session's own Event Log). append()
   * already prevents gaps from being introduced going forward; this is
   * for verifying a ledger reconstructed from storage (e.g. after a
   * restart) where entries might have been read out of order or a
   * suppression attempt might have dropped one.
   */
  verifyNoGaps(): { valid: boolean; missingAt?: string } {
    for (const e of this.entries) {
      const requiredTypes = AuthorityLedger.REQUIRED_PRIOR_TYPE[e.event_type];
      if (!requiredTypes) continue; // opaque-external or true-root type
      if (!e.prior_event_id || !this.byId.has(e.prior_event_id)) {
        return { valid: false, missingAt: e.event_id };
      }
    }
    return { valid: true };
  }
}

// ---------------------------------------------------------------------
// Convenience builders — fill in event_id/occurred_at, leave everything
// else to the caller. Keeps demo/scenario code from repeating
// randomUUID()/new Date().toISOString() boilerplate on every event.
// ---------------------------------------------------------------------

function stamp(): { event_id: string; occurred_at: string } {
  return { event_id: randomUUID(), occurred_at: new Date().toISOString() };
}

export function buildALE001(
  fields: Omit<ALE001SessionRevoked, 'event_id' | 'occurred_at' | 'event_type'>
): ALE001SessionRevoked {
  return { ...stamp(), event_type: 'ALE_SESSION_REVOKED', ...fields };
}

export function buildALE002(
  fields: Omit<ALE002AuthoritySuspended, 'event_id' | 'occurred_at' | 'event_type'>
): ALE002AuthoritySuspended {
  return { ...stamp(), event_type: 'ALE_AUTHORITY_SUSPENDED', ...fields };
}

export function buildALE003(
  fields: Omit<ALE003PartialStateRecorded, 'event_id' | 'occurred_at' | 'event_type'>
): ALE003PartialStateRecorded {
  return { ...stamp(), event_type: 'ALE_PARTIAL_STATE_RECORDED', ...fields };
}

export function buildALE004(
  fields: Omit<ALE004RecoveryInitiated, 'event_id' | 'occurred_at' | 'event_type' | 'mandate_hold'>
): ALE004RecoveryInitiated {
  return { ...stamp(), event_type: 'ALE_RECOVERY_INITIATED', mandate_hold: true, ...fields };
}

export function buildALE005(
  fields: Omit<ALE005PartialStateDisposition, 'event_id' | 'occurred_at' | 'event_type'>
): ALE005PartialStateDisposition {
  return { ...stamp(), event_type: 'ALE_PARTIAL_STATE_DISPOSITION', ...fields };
}

export function buildALE006(
  fields: Omit<ALE006CredentialRestored, 'event_id' | 'occurred_at' | 'event_type'>
): ALE006CredentialRestored {
  return { ...stamp(), event_type: 'ALE_CREDENTIAL_RESTORED', ...fields };
}

export function buildALE007(
  fields: Omit<ALE007KiaReattestationCompleted, 'event_id' | 'occurred_at' | 'event_type'>
): ALE007KiaReattestationCompleted {
  return { ...stamp(), event_type: 'ALE_KIA_REATTESTATION_COMPLETED', ...fields };
}

export function buildALE008(
  fields: Omit<ALE008AuthorityRestored, 'event_id' | 'occurred_at' | 'event_type' | 'mandate_hold_lifted'>
): ALE008AuthorityRestored {
  return { ...stamp(), event_type: 'ALE_AUTHORITY_RESTORED', mandate_hold_lifted: true, ...fields };
}

export function buildALE009(
  fields: Omit<ALE009DelegationChildRevoked, 'event_id' | 'occurred_at' | 'event_type'>
): ALE009DelegationChildRevoked {
  return { ...stamp(), event_type: 'ALE_DELEGATION_CHILD_REVOKED', ...fields };
}

export function buildALE010(
  fields: Omit<ALE010ClusterPartialRevocation, 'event_id' | 'occurred_at' | 'event_type'>
): ALE010ClusterPartialRevocation {
  return { ...stamp(), event_type: 'ALE_CLUSTER_PARTIAL_REVOCATION', ...fields };
}

export function buildALE011(
  fields: Omit<ALE011SiblingRevocationNotice, 'event_id' | 'occurred_at' | 'event_type'>
): ALE011SiblingRevocationNotice {
  return { ...stamp(), event_type: 'ALE_SIBLING_REVOCATION_NOTICE', ...fields };
}

export function buildALE012(
  fields: Omit<ALE012DelegationTreeRecoveryInitiated, 'event_id' | 'occurred_at' | 'event_type'>
): ALE012DelegationTreeRecoveryInitiated {
  return { ...stamp(), event_type: 'ALE_DELEGATION_TREE_RECOVERY_INITIATED', ...fields };
}

export function buildMandateHeld(
  fields: Omit<ALEMandateHeld, 'event_id' | 'occurred_at' | 'event_type'>
): ALEMandateHeld {
  return { ...stamp(), event_type: 'ALE_MANDATE_HELD', ...fields };
}

export function buildMandateHoldReleased(
  fields: Omit<ALEMandateHoldReleased, 'event_id' | 'occurred_at' | 'event_type'>
): ALEMandateHoldReleased {
  return { ...stamp(), event_type: 'ALE_MANDATE_HOLD_RELEASED', ...fields };
}

// Stub Ed25519 signature -- same role as KIAStubSigner in gar-core.ts,
// a local placeholder, not a real signature. See gar-core.ts's own
// KIAStubSigner doc comment; a real deployment substitutes a real KIA
// Governance Identity Keypair (gec_signature) or a real external KIA
// Verification Service (kia_verifier_signature on ALE-007 specifically).
export function stubSignature(key_id: string): Ed25519Signature {
  return { algorithm: 'Ed25519', key_id, signature: randomUUID().replace(/-/g, '') };
}
