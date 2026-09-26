// SOOS Step 11 — MAD (Multi-Agent Delegation)
// Built against draft-sato-soos-mad-03.
//
// Integrates real Step 1 (GAR) and Step 6 (KIA) modules from
// ../deps/gar/gar-core.ts and ../deps/kia/*.ts — not stubs. GAR is
// used for ALE-SPAWN-01..04 + revocation event commitment (§4.4, §11).
// KIA is used for the KIA_XPID_NAMESPACE constant and the uuidv5
// primitive that MAD-03 §6.1 explicitly reuses for sub-agent XPID
// derivation (a DIFFERENT derivation formula than KIA-03 §6.2's own
// root-agent XPID derivation in xpid.ts — MAD-03 §6.1 is explicit
// that it "extends the KIA-03 derivation to the delegation tree case",
// not that it calls KIA-03's deriveXpid() directly. See src/xpid.ts.)

/** SHA-256 hex digest / UUID string re-exports for readability. */
export type Uuid = string;
export type Iso8601 = string;

// ---------------------------------------------------------------------
// §4.2 — SACR Schema
// ---------------------------------------------------------------------

export type ReplanAuthority = 'NONE' | 'BOUNDED' | 'AUTONOMOUS';

export interface ScopeConstraints {
  cedar_action_subset: string[];
  so_type_scope: string[];
  resource_envelope: Record<string, unknown>;
  tool_subset: string[];
  temporal_scope?: { not_before?: Iso8601; not_after?: Iso8601 };
}

export interface SACR {
  sacr_id: Uuid; // REQUIRED. UUID v4. Primary key.
  parent_assignment_id: string; // REQUIRED. Cross-refs DR-PLAN-01 §5.4 (not in this sample's scope).
  parent_session_id: string; // REQUIRED.
  parent_mandate_id: string; // REQUIRED. MJWT jti of spawning agent's mandate.
  parent_xpid: Uuid; // REQUIRED. Spawning agent's XPID.
  ephemeral_kia_ref: Uuid; // REQUIRED. GEC-issued, UUID v4, session-scoped.
  scope_constraints: ScopeConstraints; // REQUIRED.
  can_decompose: boolean; // REQUIRED. Default false. MUST be false when max_spawn_depth is 0.
  max_spawn_depth: number; // REQUIRED. Strictly decrements per recursion level. >= 0.
  hub_only: boolean; // REQUIRED. Default true.
  replan_authority: ReplanAuthority; // REQUIRED. Default NONE.
  composition_timestamp: Iso8601; // REQUIRED.
  sacr_signature: string; // REQUIRED. GEC Ed25519 sig over canonical JSON of all preceding fields.
}

/** The subset of SACR fields the spawning agent proposes; the rest are GEC-derived at issuance. */
export interface SpawnRequest {
  parent_assignment_id: string;
  parent_session_id: string;
  parent_mandate_id: string;
  parent_xpid: Uuid;
  scope_constraints: ScopeConstraints;
  can_decompose: boolean;
  max_spawn_depth: number;
  hub_only?: boolean; // defaults to true unless override conditions (§5.2) are met
  replan_authority?: ReplanAuthority; // defaults to NONE
}

/** The spawning agent's currently-authorized scope, as held by the GEC — NEVER agent-supplied
 *  (CONF-MAD-SACR-05: must come from the Revocation Registry + active mandate JWT, not a claim). */
export interface AuthorizedParentScope {
  session_id: string;
  cedar_action_set: string[];
  tool_access: string[];
  max_spawn_depth: number;
  hub_only: boolean;
  revoked: boolean; // Revocation Registry membership check
}

// ---------------------------------------------------------------------
// §4.4 / §11 — SACR & MAD kernel event payloads
// (GAR's ALEType enum is extended in deps/gar/gar-core.ts-compatible
//  fashion via a parallel MadALEType — see src/gar-ext.ts for why.)
// ---------------------------------------------------------------------

export type MadALEType =
  | 'SUB_AGENT_COMPOSED' // ALE-SPAWN-01
  | 'SPAWN_DEPTH_EXCEEDED' // ALE-SPAWN-02
  | 'TOOL_SUBSET_VIOLATION' // ALE-SPAWN-03
  | 'EPHEMERAL_IDENTITY_EXPIRED' // ALE-SPAWN-04
  | 'HUB_ONLY_VIOLATION'
  | 'DIRECT_COMM_PERMITTED'
  | 'CAN_DECOMPOSE_FALSE_VIOLATION' // CONF-MAD-20
  | 'SPAWN_DEPTH_ZERO_VIOLATION' // CONF-MAD-21
  | 'HUB_OVERRIDE_NOT_PERMITTED' // CONF-MAD-HUB-04
  | 'MANDATE_NARROWING_VIOLATION'
  // R-1..R-7 events (§7)
  | 'CONSTITUTIONAL_VIOLATION' // R-1
  | 'SCOPE_BOUNDARY_VIOLATION' // R-2
  | 'CASCADE_TIMEOUT_REVOCATION' // R-3
  | 'IRREVERSIBLE_THRESHOLD_REACHED' // R-4
  | 'SCHEDULED_ROTATION_INITIATED' // R-5
  | 'SESSION_REVOKED_BY_OPERATOR' // R-6
  | 'DEADLOCK_DETECTED' // R-7
  | 'DEADLOCK_TIMEOUT_REVOCATION' // R-7 on deadlock_timeout expiry (-> R-3)
  | 'DEADLOCK_RESOLVED' // R-7
  | 'CONTINUATION_AWAITING_PRINCIPAL'
  | 'HEM_MULTI_PRINCIPAL_REQUIRED'
  | 'HEM_TIER0_OBSERVED'
  | 'SACR_REGISTRY_REBUILT'
  // R-8 (Compromise) events (NEW, MAD-04/-06, kernel design restart).
  | 'COMPROMISE_REVOCATION'
  | 'CASCADE_SUSPENDED' // ALE-CASCADE-01 — machine-detected sources only, pending confirmation
  | 'CASCADE_CONFIRMED'; // ALE-CASCADE-02 — HEM confirms; full cascade then proceeds

// ---------------------------------------------------------------------
// §7 — Revocation Trigger Classes R-1..R-7
// ---------------------------------------------------------------------

export type RevocationTrigger = 'R-1' | 'R-2' | 'R-3' | 'R-4' | 'R-5' | 'R-6' | 'R-7' | 'R-8';

/**
 * R-8 (Compromise) detection source (NEW). Only OPERATOR_REPORTED is itself
 * an explicit operator act — the other two are machine signals, not immune
 * to spoofing or false-positive triggering by a party other than the
 * mandate holder being flagged. This is exactly why R-8's cascade behavior
 * (below) is conditional on it, per the DR "External Dependency
 * Verification Protocol" precedent of checking primary sources rather than
 * assuming a detection signal's mere presence warrants full-tree action.
 */
export type DetectionSource = 'OPERATOR_REPORTED' | 'KIA_REATTESTATION_FAILURE' | 'CAEP_RISC_SIGNAL';

export type CompletionState = 'CLEAN' | 'PARTIAL' | 'UNKNOWN';

export type CascadeScope =
  | 'FULL_CASCADE_TO_DESCENDANTS'
  | 'SELECTIVE' // R-3 only: responsive descendants continue
  | 'NONE' // R-5 only: session-specific
  | 'OPERATOR_SPECIFIED' // R-6 only
  | 'ALL_PARTICIPATING' // R-7 only: all sessions in the deadlock set
  | 'CONDITIONAL_ON_DETECTION_SOURCE'; // R-8 only — see DetectionSource above

/** Table 1 (§7.8) — Completion State Matrix by Revocation Trigger. */
export const COMPLETION_STATE_MATRIX: Record<
  RevocationTrigger,
  { clean: boolean; partial: boolean; unknown: boolean }
> = {
  'R-1': { clean: false, partial: true, unknown: false }, // PARTIAL always (INV-15: UNKNOWN treated as PARTIAL)
  'R-2': { clean: true, partial: true, unknown: true }, // depends on detection timing
  'R-3': { clean: false, partial: false, unknown: true }, // UNKNOWN always
  'R-4': { clean: true, partial: true, unknown: false },
  'R-5': { clean: true, partial: true, unknown: false },
  'R-6': { clean: true, partial: true, unknown: false },
  'R-7': { clean: false, partial: false, unknown: true }, // UNKNOWN always
  'R-8': { clean: false, partial: true, unknown: true }, // PARTIAL or UNKNOWN — R-8 never produces CLEAN
};

/** Table 2 (§7.9) — Cascade Behavior by Revocation Trigger. */
export const CASCADE_MATRIX: Record<RevocationTrigger, CascadeScope> = {
  'R-1': 'FULL_CASCADE_TO_DESCENDANTS',
  'R-2': 'FULL_CASCADE_TO_DESCENDANTS',
  'R-3': 'SELECTIVE',
  'R-4': 'FULL_CASCADE_TO_DESCENDANTS',
  'R-5': 'NONE',
  'R-6': 'OPERATOR_SPECIFIED',
  'R-7': 'ALL_PARTICIPATING',
  'R-8': 'CONDITIONAL_ON_DETECTION_SOURCE',
};

export type ContinuationAuthority =
  | 'HUMAN_PRINCIPAL_MUST_REAUTHORIZE'
  | 'OPERATOR_MAY_REAUTHORIZE'; // R-3, R-5, R-6 (with principal notification where required)

export const CONTINUATION_AUTHORITY: Record<RevocationTrigger, ContinuationAuthority> = {
  'R-1': 'HUMAN_PRINCIPAL_MUST_REAUTHORIZE',
  'R-2': 'HUMAN_PRINCIPAL_MUST_REAUTHORIZE',
  'R-3': 'OPERATOR_MAY_REAUTHORIZE',
  'R-4': 'HUMAN_PRINCIPAL_MUST_REAUTHORIZE',
  'R-5': 'OPERATOR_MAY_REAUTHORIZE',
  'R-6': 'OPERATOR_MAY_REAUTHORIZE',
  'R-7': 'HUMAN_PRINCIPAL_MUST_REAUTHORIZE',
  'R-8': 'HUMAN_PRINCIPAL_MUST_REAUTHORIZE',
};

export class MadDenyError extends Error {
  constructor(
    public code: string,
    message: string,
  ) {
    super(message);
    this.name = 'MadDenyError';
  }
}
