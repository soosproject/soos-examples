// SOOS Step 11 — MAD GEC core.
// draft-sato-soos-mad-03 §4.3 (SACR Issuance Procedure), §5 (Hub-Only
// Constraint), §5.3/§9 (SACR Registry), §6 (XPID).
//
// Integrates the REAL Step 1 (GAR) and Step 6 (KIA) modules — not
// stubs: GARLog.append() from ../deps/gar/gar-core.ts, RevocationRegistry
// from ../deps/kia/event-log.ts.

import { randomUUID } from 'crypto';
import { GARLog, ALEType, KIAStubSigner, type GAREntry } from '../deps/gar/gar-core.js';
import { RevocationRegistry } from '../deps/kia/event-log.js';
import { deriveSubAgentXpid } from './xpid.js';
import {
  MadDenyError,
  type AuthorizedParentScope,
  type SACR,
  type SpawnRequest,
} from './types.js';

function isSubset(candidate: string[], of: string[]): boolean {
  const parent = new Set(of);
  return candidate.every((item) => parent.has(item));
}

function violatingItems(candidate: string[], of: string[]): string[] {
  const parent = new Set(of);
  return candidate.filter((item) => !parent.has(item));
}

export class MadGec {
  // §5.3(b) / §9 — SACR Registry: kernel-internal lookup of active SACRs
  // by session_id, used to enforce hub-only at direct-communication call
  // time without a Cedar evaluation on every attempt.
  private sacrRegistry = new Map<string, SACR>(); // keyed by ephemeral_kia_ref (the sub-agent's session_id)

  constructor(
    private gar: GARLog,
    private signer: KIAStubSigner,
    private revocationRegistry: RevocationRegistry,
  ) {}

  /**
   * §4.3 — SACR Issuance Procedure. Called by the spawning agent via
   * gec.spawnSubAgent(). Runs Steps 1-6 (Step 7, Assignment linkage, is
   * the spawning agent's own follow-up action per DR-PLAN-01 §5.4 and is
   * out of MAD's scope — see demo.ts for how a caller performs it).
   *
   * CONF-MAD-SACR-01: all validation steps MUST complete before the
   * ephemeral_kia_ref is issued — this function is written so no
   * partial-validation code path can reach ephemeral identity issuance.
   */
  spawnSubAgent(request: SpawnRequest, parentScope: AuthorizedParentScope): SACR {
    const now = new Date().toISOString();

    // --- Step 1: Spawn request validation (structural) ---
    // (TypeScript's structural typing + SpawnRequest's REQUIRED fields
    // enforce presence; MAD-03 doesn't further specify Step 1 beyond
    // "the request MUST include" the listed fields.)

    // CONF-MAD-SACR-05: the parent's authorized scope MUST come from the
    // Revocation Registry + active mandate JWT, not an agent-supplied
    // claim. AuthorizedParentScope is the caller's proof of that lookup;
    // this function additionally re-checks revocation itself so a caller
    // cannot bypass CONF-MAD-SACR-05 by constructing a stale scope object.
    if (this.revocationRegistry.isRevoked(request.parent_mandate_id) || parentScope.revoked) {
      throw new MadDenyError(
        'PARENT_MANDATE_REVOKED',
        `spawn rejected: parent mandate ${request.parent_mandate_id} is revoked`,
      );
    }

    // CONF-MAD-20 / CONF-MAD-21: enforced by the CALLER not being able to
    // reach spawnSubAgent() at all when can_decompose:false or
    // max_spawn_depth:0 — modeled here as a scope check since parentScope
    // carries the parent's own SACR-derived max_spawn_depth.
    if (parentScope.max_spawn_depth <= 0) {
      this.emit(ALEType.SPAWN_DEPTH_EXCEEDED, {
        session_id: request.parent_session_id,
        actor_id: request.parent_session_id,
        timestamp: now,
        causal_parent_id: null,
        requesting_session_id: request.parent_session_id,
        requesting_mandate_id: request.parent_mandate_id,
        requested_depth: request.max_spawn_depth,
        parent_max_depth: parentScope.max_spawn_depth,
        rejection_reason: 'SPAWN_DEPTH_ZERO_VIOLATION: parent max_spawn_depth is 0 (CONF-MAD-21)',
      });
      throw new MadDenyError(
        'SPAWN_DEPTH_ZERO_VIOLATION',
        'spawn rejected: parent max_spawn_depth is 0 (leaf agent, CONF-MAD-21)',
      );
    }

    // --- Step 2: Tool-subset invariant check ---
    if (!isSubset(request.scope_constraints.tool_subset, parentScope.tool_access)) {
      const violating = violatingItems(request.scope_constraints.tool_subset, parentScope.tool_access);
      this.emit(ALEType.TOOL_SUBSET_VIOLATION, {
        session_id: request.parent_session_id,
        actor_id: request.parent_session_id,
        timestamp: now,
        causal_parent_id: null,
        requesting_session_id: request.parent_session_id,
        requesting_mandate_id: request.parent_mandate_id,
        requested_tools: request.scope_constraints.tool_subset,
        parent_tools: parentScope.tool_access,
        violating_tools: violating,
        rejection_reason: 'TOOL_SUBSET_VIOLATION (§4.3 Step 2)',
      });
      throw new MadDenyError(
        'TOOL_SUBSET_VIOLATION',
        `spawn rejected: requested tools not a subset of parent's tool access: ${violating.join(', ')}`,
      );
    }

    // --- Step 3: Spawn-depth invariant check ---
    const maxAllowedDepth = parentScope.max_spawn_depth - 1;
    if (request.max_spawn_depth > maxAllowedDepth || request.max_spawn_depth < 0) {
      this.emit(ALEType.SPAWN_DEPTH_EXCEEDED, {
        session_id: request.parent_session_id,
        actor_id: request.parent_session_id,
        timestamp: now,
        causal_parent_id: null,
        requesting_session_id: request.parent_session_id,
        requesting_mandate_id: request.parent_mandate_id,
        requested_depth: request.max_spawn_depth,
        parent_max_depth: parentScope.max_spawn_depth,
        rejection_reason: 'SPAWN_DEPTH_EXCEEDED (§4.3 Step 3)',
      });
      throw new MadDenyError(
        'SPAWN_DEPTH_EXCEEDED',
        `spawn rejected: requested max_spawn_depth ${request.max_spawn_depth} exceeds ` +
          `parent's own max_spawn_depth (${parentScope.max_spawn_depth}) - 1 = ${maxAllowedDepth}`,
      );
    }

    // can_decompose:false MUST imply max_spawn_depth:0 (§4.2)
    if (request.max_spawn_depth === 0 && request.can_decompose) {
      throw new MadDenyError(
        'CAN_DECOMPOSE_MUST_BE_FALSE_AT_DEPTH_0',
        'spawn rejected: can_decompose MUST be false when max_spawn_depth is 0 (§4.2)',
      );
    }

    // --- Step 4: Cedar action subset check (INV-4 Narrowing Property) ---
    if (!isSubset(request.scope_constraints.cedar_action_subset, parentScope.cedar_action_set)) {
      const violating = violatingItems(
        request.scope_constraints.cedar_action_subset,
        parentScope.cedar_action_set,
      );
      this.emit(ALEType.MANDATE_NARROWING_VIOLATION, {
        session_id: request.parent_session_id,
        actor_id: request.parent_session_id,
        timestamp: now,
        causal_parent_id: null,
        requested_actions: request.scope_constraints.cedar_action_subset,
        parent_actions: parentScope.cedar_action_set,
        violating_actions: violating,
      });
      throw new MadDenyError(
        'MANDATE_NARROWING_VIOLATION',
        `spawn rejected: requested Cedar actions not a subset of parent's (INV-4): ${violating.join(', ')}`,
      );
    }

    // hub_only override (§5.2) — CONF-MAD-HUB-04: a hub_only:true parent
    // MUST NOT issue a SACR with hub_only:false.
    const requestedHubOnly = request.hub_only ?? true;
    if (!requestedHubOnly && parentScope.hub_only) {
      this.emit(ALEType.HUB_OVERRIDE_NOT_PERMITTED, {
        session_id: request.parent_session_id,
        actor_id: request.parent_session_id,
        timestamp: now,
        causal_parent_id: null,
      });
      throw new MadDenyError(
        'HUB_OVERRIDE_NOT_PERMITTED',
        'spawn rejected: hub_only:false requested by a hub_only:true parent (CONF-MAD-HUB-04)',
      );
    }

    // --- Step 5: Ephemeral identity issuance + XPID derivation ---
    const sacr_id = randomUUID();
    const ephemeral_kia_ref = randomUUID();
    const sub_agent_xpid = deriveSubAgentXpid(request.parent_xpid, sacr_id);

    const sacrFields: Omit<SACR, 'sacr_signature'> = {
      sacr_id,
      parent_assignment_id: request.parent_assignment_id,
      parent_session_id: request.parent_session_id,
      parent_mandate_id: request.parent_mandate_id,
      parent_xpid: request.parent_xpid,
      ephemeral_kia_ref,
      scope_constraints: request.scope_constraints,
      can_decompose: request.max_spawn_depth === 0 ? false : request.can_decompose,
      max_spawn_depth: request.max_spawn_depth,
      hub_only: requestedHubOnly,
      replan_authority: request.replan_authority ?? 'NONE',
      composition_timestamp: now,
    };

    // --- Step 6: SACR signing and recording ---
    const sacr_signature = this.signer.sign(JSON.stringify(sacrFields));
    const sacr: SACR = { ...sacrFields, sacr_signature };

    this.sacrRegistry.set(ephemeral_kia_ref, sacr);

    this.emit(ALEType.SUB_AGENT_COMPOSED, {
      session_id: ephemeral_kia_ref, // the NEW sub-agent session
      actor_id: 'GEC',
      timestamp: now,
      causal_parent_id: request.parent_session_id,
      sacr_id,
      parent_assignment_id: request.parent_assignment_id,
      parent_session_id: request.parent_session_id,
      parent_mandate_id: request.parent_mandate_id,
      can_decompose: sacrFields.can_decompose,
      max_spawn_depth: sacrFields.max_spawn_depth,
      hub_only: sacrFields.hub_only,
      replan_authority: sacrFields.replan_authority,
      composition_timestamp: now,
      sacr_xpid: sub_agent_xpid, // §6.3(a)
    });

    return sacr;
  }

  // -------------------------------------------------------------------
  // §5 — Hub-Only Constraint enforcement
  // -------------------------------------------------------------------

  /**
   * CONF-MAD-HUB-03: the GEC MUST NOT accept Action::"DirectSubAgentComm"
   * from a hub_only:true session. Returns normally on PERMIT; throws +
   * logs HUB_ONLY_VIOLATION on DENY.
   */
  checkDirectSubAgentComm(sourceSessionId: string, targetSessionId: string, commContentType: string): void {
    const sourceSacr = this.sacrRegistry.get(sourceSessionId);
    if (!sourceSacr) {
      throw new MadDenyError('UNKNOWN_SESSION', `no SACR registered for session ${sourceSessionId}`);
    }

    if (sourceSacr.hub_only) {
      this.emit(ALEType.HUB_ONLY_VIOLATION, {
        session_id: sourceSessionId,
        actor_id: sourceSessionId,
        timestamp: new Date().toISOString(),
        causal_parent_id: null,
        sacr_id: sourceSacr.sacr_id,
        target_session_id: targetSessionId,
        attempted_action: 'DirectSubAgentComm',
      });
      throw new MadDenyError(
        'HUB_ONLY_VIOLATION',
        `session ${sourceSessionId} is hub_only:true and MUST NOT communicate directly with ${targetSessionId} (CONF-MAD-HUB-01/03)`,
      );
    }

    // §5.2 override conditions (b)-(d) are policy/Cedar-layer concerns not
    // modeled as a live Cedar engine in this sample (OQ-SC-02 still open,
    // per Step 9's note) — recorded here as a precondition comment only:
    // caller is responsible for having verified (b) parent hub_only:false
    // lineage and (c) an explicit Cedar PERMIT before calling this.
    this.emit(ALEType.DIRECT_COMM_PERMITTED, {
      session_id: sourceSessionId,
      actor_id: sourceSessionId,
      timestamp: new Date().toISOString(),
      causal_parent_id: null,
      initiating_session_id: sourceSessionId,
      receiving_session_id: targetSessionId,
      authorized_comm_types: [commContentType],
    });
  }

  /**
   * §5.3 recursive rule: a hub_only:true child MUST NOT spawn hub_only:false
   * grandchildren. Call this before spawnSubAgent() when the spawning
   * agent is itself a SACR-spawned sub-agent.
   */
  assertRecursiveHubOnlyNotWeakened(childSacr: SACR, requestedGrandchildHubOnly: boolean): void {
    if (childSacr.hub_only && !requestedGrandchildHubOnly) {
      throw new MadDenyError(
        'HUB_OVERRIDE_NOT_PERMITTED',
        'recursive spawn rejected: a hub_only:true child MUST NOT spawn hub_only:false grandchildren (§5.3)',
      );
    }
  }

  // -------------------------------------------------------------------
  // §4.4 ALE-SPAWN-04 — ephemeral identity retirement
  // -------------------------------------------------------------------

  retireEphemeralIdentity(ephemeral_kia_ref: string, completion_state: 'CLEAN' | 'PARTIAL' | 'UNKNOWN'): void {
    const sacr = this.sacrRegistry.get(ephemeral_kia_ref);
    if (!sacr) return; // already retired or never existed — idempotent
    this.emit(ALEType.EPHEMERAL_IDENTITY_EXPIRED, {
      session_id: ephemeral_kia_ref,
      actor_id: 'GEC',
      timestamp: new Date().toISOString(),
      causal_parent_id: null,
      sacr_id: sacr.sacr_id,
      ephemeral_kia_ref,
      completion_state,
      expired_at: new Date().toISOString(),
    });
    this.sacrRegistry.delete(ephemeral_kia_ref);
  }

  // -------------------------------------------------------------------
  // §9 / CONF-MAD-22 — SACR Registry rebuild on kernel restart
  // -------------------------------------------------------------------

  rebuildSacrRegistryFromGar(): void {
    this.sacrRegistry.clear();
    let count = 0;
    for (const entry of this.gar.all()) {
      if (entry.ale_type === ALEType.SUB_AGENT_COMPOSED) {
        const payload = entry as unknown as SACR & GAREntry;
        // Reconstructs only the fields needed for hub-only enforcement;
        // a real rebuild would restore the full SACR from the signed event.
        this.sacrRegistry.set(entry.session_id, {
          sacr_id: (payload as any).sacr_id,
          parent_assignment_id: (payload as any).parent_assignment_id,
          parent_session_id: (payload as any).parent_session_id,
          parent_mandate_id: (payload as any).parent_mandate_id,
          parent_xpid: (payload as any).parent_xpid ?? '',
          ephemeral_kia_ref: entry.session_id,
          scope_constraints: (payload as any).scope_constraints ?? {
            cedar_action_subset: [],
            so_type_scope: [],
            resource_envelope: {},
            tool_subset: [],
          },
          can_decompose: (payload as any).can_decompose,
          max_spawn_depth: (payload as any).max_spawn_depth,
          hub_only: (payload as any).hub_only,
          replan_authority: (payload as any).replan_authority,
          composition_timestamp: (payload as any).composition_timestamp,
          sacr_signature: '',
        });
        count++;
      }
    }
    this.emit(ALEType.SACR_REGISTRY_REBUILT, {
      session_id: 'KERNEL',
      actor_id: 'GEC',
      timestamp: new Date().toISOString(),
      causal_parent_id: null,
      sacr_count: count,
      active_sacr_ids: [...this.sacrRegistry.values()].map((s) => s.sacr_id),
      rebuilt_at: new Date().toISOString(),
    });
  }

  getSacr(sessionId: string): SACR | undefined {
    return this.sacrRegistry.get(sessionId);
  }

  // -------------------------------------------------------------------
  // internal
  // -------------------------------------------------------------------

  private emit(
    ale_type: ALEType,
    fields: { session_id: string; actor_id: string; timestamp: string; causal_parent_id: string | null } & Record<string, unknown>,
  ): GAREntry {
    return this.gar.append({ ale_type, ...fields } as unknown as Omit<GAREntry, 'prev_span_hash' | 'own_span_hash'>);
  }
}
