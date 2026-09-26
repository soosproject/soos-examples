// SOOS Step 11 — MAD Revocation Engine.
// draft-sato-soos-mad-03 §7 (R-1 through R-7), §7.8 (Completion State
// Matrix), §7.9 (Cascade Behavior Matrix).
//
// SVL Phase A key question (resolved by reading §7.1-§7.8 directly,
// not the plan's paraphrase — same precedent as Steps 4/8/9/10): the
// R-1..R-7 completion matrix in Table 1 IS exhaustive as CLEAN/PARTIAL/
// UNKNOWN for every trigger; there are no additional fallback states.
// Three triggers are fixed to a single state regardless of circumstance
// (R-1: PARTIAL always, R-3: UNKNOWN always, R-7: UNKNOWN always); the
// other four (R-2, R-4, R-5, R-6) are circumstance-dependent across all
// three states, decided by the halt-timing parameter passed into
// trigger(), not left ambiguous by the draft.

import { GARLog, ALEType, KIAStubSigner, type GAREntry } from '../deps/gar/gar-core.js';
import { RevocationRegistry } from '../deps/kia/event-log.js';
import type { MadGec } from './gec.js';
import {
  COMPLETION_STATE_MATRIX,
  CASCADE_MATRIX,
  CONTINUATION_AUTHORITY,
  type CompletionState,
  type RevocationTrigger,
  type DetectionSource,
} from './types.js';

export interface SessionRecord {
  session_id: string;
  mandate_id: string;
  parent_session_id: string | null;
  responsive: boolean; // for R-3 selective-cascade evaluation
}

/**
 * Minimal in-memory delegation tree used only to resolve cascade scope.
 * Real deployments derive this from the Mandate Issuance Tree (§3.2) /
 * SACR chain, not a flat map — this is the Tier 1 sample-code
 * approximation, same category as SOV's POLICY_EVALUATION_ORDER stub.
 */
export class DelegationTree {
  private sessions = new Map<string, SessionRecord>();

  register(record: SessionRecord): void {
    this.sessions.set(record.session_id, record);
  }

  get(session_id: string): SessionRecord | undefined {
    return this.sessions.get(session_id);
  }

  descendantsOf(session_id: string): SessionRecord[] {
    const out: SessionRecord[] = [];
    const stack = [session_id];
    while (stack.length) {
      const current = stack.pop()!;
      for (const record of this.sessions.values()) {
        if (record.parent_session_id === current) {
          out.push(record);
          stack.push(record.session_id);
        }
      }
    }
    return out;
  }
}

export interface TriggerResult {
  session_id: string;
  trigger: RevocationTrigger;
  completion_state: CompletionState;
  cascade_scope: string;
  revoked_sessions: string[]; // this session + any cascaded descendants
  continuation_authority: string;
}

/** §7.1(a)/etc "detection timing" input, only meaningful for R-2/R-4/R-5/R-6. */
export type HaltTiming =
  | 'BEFORE_ACTION' // -> CLEAN
  | 'AFTER_IRREVERSIBLE_ACTION' // -> PARTIAL
  | 'EXECUTION_STATE_UNKNOWN'; // -> UNKNOWN (R-2 only, per §7.2's completion-state prose)

export class RevocationEngine {
  // R-8 sessions currently CASCADE_SUSPENDED, pending HEM confirmation —
  // session_id -> the descendant session_ids awaiting full revocation.
  private suspendedCascades = new Map<string, string[]>();

  constructor(
    private gar: GARLog,
    private signer: KIAStubSigner,
    private revocationRegistry: RevocationRegistry,
    private tree: DelegationTree,
    private gec: MadGec,
  ) {}

  /**
   * Fires a revocation trigger for `session_id`. Returns the completion
   * state, cascade scope, and the full list of sessions revoked as a
   * result (INV-16: completion_state is REQUIRED in every GAR entry
   * this produces).
   */
  trigger(
    trigger: RevocationTrigger,
    session_id: string,
    opts: {
      haltTiming?: HaltTiming;
      revocationScope?: 'THIS_MANDATE_ONLY' | 'CASCADE_TO_DESCENDANTS';
      detectionSource?: DetectionSource; // REQUIRED for R-8
    } = {},
  ): TriggerResult {
    const record = this.tree.get(session_id);
    if (!record) {
      throw new Error(`RevocationEngine: no session registered for ${session_id}`);
    }
    const now = new Date().toISOString();

    const completion_state = this.resolveCompletionState(trigger, opts.haltTiming);
    const revoked_sessions = [session_id];

    // --- INV-15: UNKNOWN is treated as PARTIAL for downstream decisions
    //     that only distinguish CLEAN vs. not-CLEAN (cascade eligibility,
    //     continuation gating). completion_state itself still records the
    //     literal UNKNOWN value in GAR — INV-15 governs how it's TREATED,
    //     not what's recorded.

    // Register the revocation atomically with halting (R-1 requirement,
    // generalized to all triggers per §7's "atomically with halting" language).
    this.revocationRegistry.revoke({
      jti: record.mandate_id,
      revoked_at: now,
      revocation_scope: opts.revocationScope ?? 'CASCADE_TO_DESCENDANTS',
      originating_kernel: 'GEC-LOCAL',
    });

    // Per-trigger behavior + cascade
    switch (trigger) {
      case 'R-1':
        this.emit(ALEType.CONSTITUTIONAL_VIOLATION, session_id, now, { violation_class: 'TIER_0A', tier: '0-A' });
        this.emit(ALEType.HEM_TIER0_OBSERVED, session_id, now, {});
        this.cascadeFull(session_id, revoked_sessions, 'PARTIAL', now);
        this.emit(ALEType.CONTINUATION_AWAITING_PRINCIPAL, session_id, now, {});
        break;

      case 'R-2':
        this.emit(ALEType.SCOPE_BOUNDARY_VIOLATION, session_id, now, {});
        this.cascadeFull(session_id, revoked_sessions, completion_state, now);
        break;

      case 'R-3': {
        this.emit(ALEType.CASCADE_TIMEOUT_REVOCATION, session_id, now, {});
        // Selective cascade: only NON-responsive descendants are pulled in;
        // responsive ones continue under their own mandate authority chain.
        const descendants = this.tree.descendantsOf(session_id);
        for (const d of descendants) {
          if (!d.responsive) {
            revoked_sessions.push(d.session_id);
            this.gec.retireEphemeralIdentity(d.session_id, 'UNKNOWN');
            this.revocationRegistry.revoke({
              jti: d.mandate_id,
              revoked_at: now,
              revocation_scope: 'THIS_MANDATE_ONLY',
              originating_kernel: 'GEC-LOCAL',
            });
          }
        }
        this.gec.retireEphemeralIdentity(session_id, 'UNKNOWN');
        break;
      }

      case 'R-4':
        this.emit(ALEType.IRREVERSIBLE_THRESHOLD_REACHED, session_id, now, {
          anticipatory: opts.haltTiming === 'BEFORE_ACTION',
        });
        this.cascadeFull(session_id, revoked_sessions, completion_state, now);
        break;

      case 'R-5':
        this.emit(ALEType.SCHEDULED_ROTATION_INITIATED, session_id, now, {});
        this.gec.retireEphemeralIdentity(session_id, completion_state);
        // No cascade — session-specific only (Table 2).
        break;

      case 'R-6':
        this.emit(ALEType.SESSION_REVOKED_BY_OPERATOR, session_id, now, {
          revocation_scope: opts.revocationScope ?? 'CASCADE_TO_DESCENDANTS',
        });
        if ((opts.revocationScope ?? 'CASCADE_TO_DESCENDANTS') === 'CASCADE_TO_DESCENDANTS') {
          this.cascadeFull(session_id, revoked_sessions, completion_state, now);
        } else {
          this.gec.retireEphemeralIdentity(session_id, completion_state);
        }
        break;

      case 'R-7': {
        // All participating sessions suspended simultaneously — caller is
        // expected to fire trigger('R-7', ...) once per participating
        // session_id; this handles ONE participant per call, matching how
        // a real cluster coordinator would emit per-session DEADLOCK_DETECTED
        // records while sharing a single arbitration event.
        this.emit(ALEType.DEADLOCK_DETECTED, session_id, now, {});
        this.emit(ALEType.HEM_MULTI_PRINCIPAL_REQUIRED, session_id, now, {});
        // Ephemeral refs are RETAINED pending resolution (Table 2), not
        // retired here — retirement happens on timeout (-> R-3 path) or
        // DEADLOCK_RESOLVED (see resolveDeadlock()/timeoutDeadlock() below).
        break;
      }

      case 'R-8': {
        if (!opts.detectionSource) {
          throw new Error("RevocationEngine: trigger('R-8', ...) requires opts.detectionSource");
        }
        this.emit(ALEType.COMPROMISE_REVOCATION, session_id, now, { detection_source: opts.detectionSource });
        this.emit(ALEType.HEM_TIER0_OBSERVED, session_id, now, {});
        if (opts.detectionSource === 'OPERATOR_REPORTED') {
          // Already an explicit operator act — cascade immediately, same as R-1/R-2/R-4.
          this.cascadeFull(session_id, revoked_sessions, completion_state, now);
          this.emit(ALEType.CONTINUATION_AWAITING_PRINCIPAL, session_id, now, {});
        } else {
          // KIA_REATTESTATION_FAILURE / CAEP_RISC_SIGNAL: neither is an operator act,
          // neither is immune to spoofing or false-positive triggering by a party
          // other than the mandate holder being flagged. Halt descendants
          // immediately (fully contains a genuine compromise) but do NOT revoke
          // them yet — that waits for the HEM_TIER0_OBSERVED escalation above to
          // resolve. See confirmCascade()/timeoutCascade() below.
          this.cascadeSuspend(session_id, now);
        }
        break;
      }
    }

    return {
      session_id,
      trigger,
      completion_state,
      cascade_scope: CASCADE_MATRIX[trigger],
      revoked_sessions,
      continuation_authority: CONTINUATION_AUTHORITY[trigger],
    };
  }

  /** §7.7(e) — on deadlock_timeout expiry, DEADLOCK-suspended sessions auto-revoke under R-3. */
  timeoutDeadlock(session_id: string): TriggerResult {
    const result = this.trigger('R-3', session_id);
    this.emit(ALEType.DEADLOCK_TIMEOUT_REVOCATION, session_id, new Date().toISOString(), {});
    return result;
  }

  /** §7.7 — successful human arbitration. */
  resolveDeadlock(session_id: string): void {
    this.emit(ALEType.DEADLOCK_RESOLVED, session_id, new Date().toISOString(), {});
  }

  // -------------------------------------------------------------------

  private resolveCompletionState(trigger: RevocationTrigger, haltTiming?: HaltTiming): CompletionState {
    const matrix = COMPLETION_STATE_MATRIX[trigger];
    // Fixed-state triggers (only one flag true in the matrix): ignore haltTiming.
    if (matrix.partial && !matrix.clean && !matrix.unknown) return 'PARTIAL'; // R-1
    if (matrix.unknown && !matrix.clean && !matrix.partial) return 'UNKNOWN'; // R-3, R-7

    // Circumstance-dependent triggers: derive from haltTiming.
    switch (haltTiming) {
      case 'BEFORE_ACTION':
        return 'CLEAN';
      case 'AFTER_IRREVERSIBLE_ACTION':
        return 'PARTIAL';
      case 'EXECUTION_STATE_UNKNOWN':
        return matrix.unknown ? 'UNKNOWN' : 'PARTIAL'; // INV-15 fallback if a trigger has no UNKNOWN cell (R-4/5/6)
      default:
        // No timing supplied for a circumstance-dependent trigger — INV-15:
        // treat as PARTIAL rather than assume CLEAN.
        return 'PARTIAL';
    }
  }

  private cascadeFull(session_id: string, revoked: string[], completion_state: CompletionState, now: string): void {
    const descendants = this.tree.descendantsOf(session_id);
    for (const d of descendants) {
      revoked.push(d.session_id);
      this.revocationRegistry.revoke({
        jti: d.mandate_id,
        revoked_at: now,
        revocation_scope: 'CASCADE_TO_DESCENDANTS',
        originating_kernel: 'GEC-LOCAL',
      });
      // R-1/R-2/R-4 SACR implication: all SACRs of revoked descendants are
      // voided and their ephemeral refs retired immediately, same
      // completion_state as the triggering session (§7.1 "SACR implications for R-1").
      this.gec.retireEphemeralIdentity(d.session_id, completion_state);
    }
    this.gec.retireEphemeralIdentity(session_id, completion_state);
  }

  /**
   * R-8, machine-detected sources only (NEW). Halts descendants immediately
   * (ALE-CASCADE-01) but holds their SACRs and ephemeral KIA references —
   * they are suspended alongside their sessions, not voided, pending
   * confirmCascade() or timeoutCascade().
   */
  private cascadeSuspend(session_id: string, now: string): void {
    const descendants = this.tree.descendantsOf(session_id).map((d) => d.session_id);
    for (const descendantId of descendants) {
      this.emit(ALEType.CASCADE_SUSPENDED, descendantId, now, { triggering_session_id: session_id });
    }
    this.suspendedCascades.set(session_id, descendants);
  }

  /**
   * HEM_TIER0_OBSERVED resolves to CONFIRM the R-8 compromise (NEW). Completes
   * the full cascade that cascadeSuspend() held back: revokes every suspended
   * descendant and retires their ephemeral identities, then emits
   * ALE-CASCADE-02.
   */
  confirmCascade(session_id: string, completion_state: CompletionState = 'PARTIAL'): string[] {
    const descendants = this.suspendedCascades.get(session_id);
    if (!descendants) {
      throw new Error(`RevocationEngine.confirmCascade: no CASCADE_SUSPENDED entry for session ${session_id}`);
    }
    const now = new Date().toISOString();
    for (const descendantId of descendants) {
      const record = this.tree.get(descendantId);
      if (record) {
        this.revocationRegistry.revoke({
          jti: record.mandate_id,
          revoked_at: now,
          revocation_scope: 'CASCADE_TO_DESCENDANTS',
          originating_kernel: 'GEC-LOCAL',
        });
      }
      this.gec.retireEphemeralIdentity(descendantId, completion_state);
    }
    this.emit(ALEType.CASCADE_CONFIRMED, session_id, now, { revoked_session_ids: descendants });
    this.suspendedCascades.delete(session_id);
    return descendants;
  }

  /**
   * HEM_TIER0_OBSERVED times out without resolution (NEW). Per this
   * document's Timeout Disposition (TIMEOUT_DENY, no implicit approval):
   * the suspended descendants are NOT automatically revoked, and are NOT
   * automatically resumed either — CASCADE_SUSPENDED persists until an
   * explicit operator act resolves it either way. This method exists so
   * callers have somewhere to record that a timeout occurred; it
   * deliberately changes nothing about suspendedCascades' contents.
   */
  timeoutCascade(session_id: string): void {
    if (!this.suspendedCascades.has(session_id)) {
      throw new Error(`RevocationEngine.timeoutCascade: no CASCADE_SUSPENDED entry for session ${session_id}`);
    }
    this.emit(ALEType.CASCADE_TIMEOUT_REVOCATION, session_id, new Date().toISOString(), {
      note: 'R-8 HEM timeout — TIMEOUT_DENY: cascade neither confirmed nor cleared automatically',
    });
  }

  private emit(ale_type: ALEType, session_id: string, timestamp: string, extra: Record<string, unknown>): GAREntry {
    return this.gar.append({
      ale_type,
      session_id,
      actor_id: 'GEC',
      timestamp,
      causal_parent_id: null,
      ...extra,
    } as unknown as Omit<GAREntry, 'prev_span_hash' | 'own_span_hash'>);
  }
}
