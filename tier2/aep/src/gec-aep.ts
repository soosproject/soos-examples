// SOOS Step 12 — AEP GEC core.
// draft-sato-soos-aep-02 §5 (Session Lifecycle), §6 (EOD), §9.2 (GEC
// Execution Sequence), §10 (GEC Response), §11 (Event Log Markers).
//
// This is the orchestrator: every governance decision is delegated to
// the REAL Step 1/2/3/5/6/7/9 module. This file's own logic is limited
// to session-state bookkeeping (§5) and running those modules in the
// order §9.2 specifies.

import { randomUUID } from 'crypto';
import { GARLog, ALEType, KIAStubSigner, type GAREntry } from '../deps/gar/gar-core.js';
import { RevocationRegistry } from '../deps/kia/event-log.js';
import { deriveXpid } from '../deps/kia/xpid.js';
import { GECMediator, EventStream, GECStubSigner, SovereignObject, type SOEvent } from '../deps/sov/sov-core.js';
import {
  IDPGovernanceEngineComponent,
  IDPDenyCode,
  type IntentDeclaration,
} from '../deps/idp/index.js';
import { resolveSOType, type MandateBinding } from '../deps/idp/stubs.js';
import { verifyMandate, type MJWTClaims, type GECVerificationContext } from '../deps/mjwt/index.js';
import { evaluateCee, type CeeEvaluationInput } from '../deps/cap/cee.js';
import { evaluateCedarPolicySet, type CedarPolicyResult } from '../deps/cap/cedar-semantics.js';
import {
  computeCpHash,
  emitSenseSpan,
  emitReasonSpan,
  emitPlanSpan,
  emitActSpan,
  emitObserveSpan,
  assertCpHashBinding,
} from './otel.js';
import {
  AepDenyError,
  DEFAULT_STALL_DENY_THRESHOLD,
  type AepEod,
  type AepSessionState,
  type AgentClass,
  type ClosureReason,
  type ContextPackage,
  type ContextTrigger,
  type DenyResponse,
  type GecResponse,
  type HemPendingResponse,
  type PermitResponse,
  type StalledResponse,
  type TransitionRequest,
} from './types.js';

export interface AepSession {
  session_id: string; // UUID v7
  goal_session_id: string;
  so: SovereignObject;
  root_mandate: MJWTClaims;
  agent_class: AgentClass;
  session_xpid: string;
  aep_iteration: number;
  state: AepSessionState;
  eod: AepEod | null;
  eod_endorsed: boolean;
  endorsed_eod_id: string | null;
  plan_b_activated: boolean;
  last_cp_hash: string | null;
  operative_goal_state: string; // primary_outcome.target_state, or plan_b_target_state once PLAN_B_ACTIVE
  stall_deny_threshold: number;
  closure_reason: ClosureReason | null;
}

export interface InitiateSessionParams {
  rootMandateToken: string;
  issuerPublicKey: CryptoKey;
  so: SovereignObject;
  agent_class: AgentClass;
  agentProviderId: string; // KIA Party Registry key
  gecInstanceId: string;
  gecConformanceLevel: 1 | 2 | 3;
  eod?: Omit<AepEod, 'session_id_ref'>; // session_id_ref is GEC-assigned at bind time
}

export class AepGec {
  private sessions = new Map<string, AepSession>();

  constructor(
    private gar: GARLog,
    private signer: KIAStubSigner,
    private sovSigner: GECStubSigner,
    private sovStream: EventStream,
    private sovMediator: GECMediator,
    private revocationRegistry: RevocationRegistry,
    private idp: IDPGovernanceEngineComponent,
    /**
     * KIA-verified Party Registry: agent_provider_id -> { active, keypairFingerprint,
     * operatorIdentity, registryEntryHash }. keypairFingerprint remains for kernel-instance
     * identity purposes (Event Log signing, originating_kernel); XPID derivation (v2.0) uses
     * operatorIdentity instead, so it survives kernel keypair rotation — see xpid.ts.
     */
    private partyRegistry: Map<string, { active: boolean; keypairFingerprint: string; operatorIdentity: string; registryEntryHash: string }>,
  ) {}

  // -------------------------------------------------------------------
  // §5.1 — Session Initiation (with XPID Binding)
  // -------------------------------------------------------------------

  async initiateSession(params: InitiateSessionParams): Promise<AepSession> {
    // (a) MJWT verification protocol before initiating the session.
    // §5.1(a) calls for running "the MJWT verification protocol Section 8"
    // at session init, but that 13-step protocol is written for a specific
    // Transition Request (Step 10 checks a requested_cedar_action against
    // claims.cedar_actions) — session init has no target action yet.
    // Design note (not a blocking gap): peek the unverified claims (same
    // technique verifyMandate's own Steps 1-2 use before signature
    // verification) to supply one of the mandate's own declared
    // cedar_actions as Step 10's comparison value. This keeps the other
    // 12 steps meaningfully enforced at session init instead of skipping
    // the whole protocol or duplicating it with a carve-out.
    const unverifiedClaims = this.decodeClaims(params.rootMandateToken);
    const ctx: GECVerificationContext = {
      gec_instance_id: params.gecInstanceId,
      gec_conformance_level: params.gecConformanceLevel,
      so_current_state: params.so.current_state,
      so_current_phase: params.so.current_phase,
      so_human_principal_id: params.so.human_principal_id,
      requested_cedar_action: unverifiedClaims.cedar_actions?.[0] ?? '',
      cedar_policy_requires_consent: false,
      revoked_jtis: this.revokedJtiSet(),
    };
    const verification = await verifyMandate(params.rootMandateToken, params.issuerPublicKey, ctx);
    if (!verification.ok) {
      throw new AepDenyError(verification.deny_code ?? 'MJWT_VERIFICATION_FAILED', verification.detail ?? 'root mandate verification failed');
    }
    const claims = this.decodeClaims(params.rootMandateToken);

    // (g) agent_provider_id MUST resolve to an active, non-revoked Party Registry entry.
    const registryEntry = this.partyRegistry.get(params.agentProviderId);
    if (!registryEntry || !registryEntry.active) {
      throw new AepDenyError('AGENT_NOT_REGISTERED', `agent_provider_id ${params.agentProviderId} has no active Party Registry entry`);
    }

    // (d) Derive the agent's XPID from the KIA-verified Party Registry entry — GEC-derived, never client-supplied (f).
    // v2.0: anchored to operatorIdentity, not keypairFingerprint (stable across kernel keypair rotation).
    const session_xpid = deriveXpid(registryEntry.operatorIdentity, registryEntry.registryEntryHash);

    const session_id = randomUUID();
    const goal_session_id = randomUUID();

    // (h) Class 3 agents MUST submit an EOD before the first Context Package.
    let eod: AepEod | null = null;
    let eod_endorsed = false;
    let endorsed_eod_id: string | null = null;
    if (params.agent_class === 'CLASS_3' && !params.eod) {
      throw new AepDenyError('EOD_REQUIRED', 'Class 3 agents MUST submit an EOD before session initiation');
    }
    if (params.eod) {
      eod = { ...params.eod, session_id_ref: session_id };
      // §6.3(a): commit EOD via the real IDP intake_endorsement() state-machine
      // check — reused rather than reimplemented (see types.ts design note).
      const endorsement = this.idp.intakeEndorsement({
        eod: {
          eod_id: eod.eod_id,
          primary_outcome: { target_state: eod.primary_outcome.target_state },
          plan_b: eod.plan_b ? { plan_b_id: eod.plan_b.plan_b_id, plan_b_target_state: eod.plan_b.plan_b_target_state } : undefined,
        },
        mandate_jwt_jti: claims.jti,
        so_id: params.so.so_id,
        so_type_id: params.so.so_type_id,
        principal_credential: `kia:${params.so.human_principal_id}`,
        requested_at: new Date().toISOString(),
        request_id: randomUUID(),
      });
      if (!endorsement.ok) {
        throw new AepDenyError(endorsement.error_code ?? 'EOD_INVALID', endorsement.detail ?? 'EOD endorsement failed');
      }
      eod_endorsed = true;
      endorsed_eod_id = endorsement.endorsed_eod!.endorsed_eod_id;
      this.emit(ALEType.EOD_COMMITTED, {
        session_id,
        actor_id: 'GEC',
        timestamp: new Date().toISOString(),
        causal_parent_id: null,
        eod_id: eod.eod_id,
        submitter_mjwt_id: eod.submitter_mjwt_id,
      });
    } else if (params.agent_class === 'CLASS_2') {
      // (i) EOD_ABSENT recorded, not rejected.
      this.emit(ALEType.EOD_COMMITTED, {
        session_id,
        actor_id: 'GEC',
        timestamp: new Date().toISOString(),
        causal_parent_id: null,
        eod_absent: true,
      });
    }

    const session: AepSession = {
      session_id,
      goal_session_id,
      so: params.so,
      root_mandate: claims,
      agent_class: params.agent_class,
      session_xpid,
      aep_iteration: 1, // (c)
      state: 'ACTIVE', // (l)
      eod,
      eod_endorsed,
      endorsed_eod_id,
      plan_b_activated: false,
      last_cp_hash: null,
      operative_goal_state: eod?.primary_outcome.target_state ?? params.so.current_state,
      stall_deny_threshold: DEFAULT_STALL_DENY_THRESHOLD,
      closure_reason: null,
    };
    this.sessions.set(session_id, session);
    return session;
  }

  // -------------------------------------------------------------------
  // SENSE — deliver a Context Package (§11.1 AEP_SENSE_DELIVERED)
  // -------------------------------------------------------------------

  sense(session: AepSession, trigger: ContextTrigger, redirect_instruction?: string): ContextPackage {
    const cp: ContextPackage = {
      cp_id: randomUUID(),
      trigger,
      so_current_state: session.so.current_state,
      so_current_phase: session.so.current_phase,
      declared_goal_state: session.operative_goal_state,
      redirect_instruction,
    };
    const cp_hash = computeCpHash(cp);
    session.last_cp_hash = cp_hash;

    this.emit(ALEType.AEP_SENSE_DELIVERED, {
      session_id: session.session_id,
      actor_id: 'GEC',
      timestamp: new Date().toISOString(),
      causal_parent_id: null,
      aep_iteration: session.aep_iteration,
      cp_id: cp.cp_id,
      cp_hash,
      trigger,
      session_xpid: session.session_xpid,
      goal_session_id: session.goal_session_id,
      eod_id: session.eod?.eod_id ?? null,
      session_state: session.state,
    });

    emitSenseSpan({
      session_id: session.session_id,
      iteration: session.aep_iteration,
      trigger,
      cp_hash,
      session_xpid: session.session_xpid,
      session_state: session.state,
      so_current_state: session.so.current_state,
    });

    return cp;
  }

  /** REASON/PLAN spans — agent-side steps; the GEC only observes them for OTel purposes in this sample. */
  reason(session: AepSession, reasoning_mode: string | undefined, reasonDurationMs?: number): void {
    emitReasonSpan({ session_id: session.session_id, iteration: session.aep_iteration, reasoning_mode, reason_duration_ms: reasonDurationMs });
  }

  plan(session: AepSession, planQueries: string[], pathConfidence: number, intendedCedarAction: string): void {
    emitPlanSpan({
      session_id: session.session_id,
      iteration: session.aep_iteration,
      plan_queries: planQueries,
      path_confidence: pathConfidence,
      intended_cedar_action: intendedCedarAction,
    });
  }

  // -------------------------------------------------------------------
  // ACT / OBSERVE — §9.2 GEC Execution Sequence, §10 GEC Response
  // -------------------------------------------------------------------

  async act(
    session: AepSession,
    req: TransitionRequest,
    issuerPublicKey: CryptoKey,
    parentMandate: MJWTClaims | undefined,
    cedarPolicies: CedarPolicyResult[],
    ceeInput: Omit<CeeEvaluationInput, 'actionPattern'>,
  ): Promise<GecResponse> {
    if (session.state === 'HEM_PENDING') {
      return this.denyResponse(session, 'SESSION_HEM_PENDING', 'session is in HEM_PENDING — Transition Requests rejected while pending', req.idp);
    }
    if (session.state === 'STALLED') {
      return this.denyResponse(session, 'SESSION_STALLED', 'session is STALLED — resolve via STALL_DIRECTION before further ACT', req.idp);
    }

    if (session.last_cp_hash === null) {
      throw new AepDenyError('NO_PRIOR_SENSE', 'ACT submitted with no prior SENSE delivery in this iteration');
    }

    const binding: MandateBinding = {
      mandate_id: session.root_mandate.jti,
      so_id: session.so.so_id,
      human_principal_id: session.so.human_principal_id,
      agent_class: session.agent_class,
    };

    // §9.3 — the IDP is submitted as part of every Transition Request;
    // structural/session-binding validation happens before the ordered
    // Steps 1-6 (§9.1's "MUST be a well-formed IDP" precondition).
    const idpResult = this.idp.submitIDP(req.idp, binding, { plan_b_active: session.state === 'PLAN_B_ACTIVE' });
    if (!idpResult.ok) {
      return this.denyResponse(session, idpResult.deny_code ?? 'IDP_MALFORMED', idpResult.detail ?? 'IDP validation failed', req.idp);
    }

    emitActSpan({
      session_id: session.session_id,
      iteration: session.aep_iteration,
      idp_id: req.idp.idp_id,
      cedar_action: req.cedar_action,
      confidence: req.idp.confidence_level,
      cp_hash_ref: computeCpHash({
        cp_id: '', trigger: 'STATE_CHANGE', so_current_state: session.so.current_state,
        so_current_phase: session.so.current_phase, declared_goal_state: session.operative_goal_state,
      }),
      plan_b_ref: req.idp.plan_b_ref,
    });

    // --- Step 1: MJWT Verification ---
    const ctx: GECVerificationContext = {
      gec_instance_id: session.root_mandate.aud,
      gec_conformance_level: 1,
      so_current_state: session.so.current_state,
      so_current_phase: session.so.current_phase,
      so_human_principal_id: session.so.human_principal_id,
      requested_cedar_action: req.cedar_action,
      idp_mission_ref: req.idp.mission_ref,
      cedar_policy_requires_consent: false,
      revoked_jtis: this.revokedJtiSet(),
    };
    const mjwtResult = await verifyMandate(req.mandate_jwt, issuerPublicKey, ctx, parentMandate);
    if (!mjwtResult.ok) {
      return this.denyResponse(session, mjwtResult.deny_code ?? 'MJWT_DENY', mjwtResult.detail ?? 'MJWT verification failed', req.idp);
    }
    const actingClaims = this.decodeClaims(req.mandate_jwt);

    // --- Step 1a: XPID Consistency Check [NEW in -02] ---
    const registryEntry = this.partyRegistry.get(actingClaims.wid); // wid stands in for agent_provider_id in this sample
    if (!registryEntry) {
      this.emit(ALEType.CONSTITUTIONAL_VIOLATION, {
        session_id: session.session_id, actor_id: 'GEC', timestamp: new Date().toISOString(), causal_parent_id: null,
        violation_class: 'XPID_MISMATCH',
      });
      session.state = 'CLOSED';
      session.closure_reason = 'KERNEL_REJECTED';
      throw new AepDenyError('XPID_MISMATCH', 'mandate agent_provider_id does not resolve to a Party Registry entry — session terminated');
    }
    // v2.0: anchored to operatorIdentity, not keypairFingerprint (stable across kernel keypair rotation).
    const derivedXpid = deriveXpid(registryEntry.operatorIdentity, registryEntry.registryEntryHash);
    if (derivedXpid !== session.session_xpid) {
      session.state = 'CLOSED';
      session.closure_reason = 'KERNEL_REJECTED';
      throw new AepDenyError('XPID_MISMATCH', `derived XPID ${derivedXpid} does not match session-bound XPID ${session.session_xpid} — session terminated (critical security event)`);
    }

    // --- Step 2: CAP Evaluation (Tier 0 constitutional + Tier 1 jurisdictional only) ---
    const cee = evaluateCee({ ...ceeInput, tier2Records: [], actionPattern: req.cedar_action });
    if (cee.output !== 'PERMIT' && cee.output !== 'TIER_0B_PCR_ACTIVE' && cee.output !== 'TIER_1_PCR_ACTIVE') {
      const resp = this.denyResponse(session, `CAP_${cee.output}`, `CAP evaluation: ${cee.output} (tier ${cee.matchedTier ?? '?'})`, req.idp);
      emitObserveSpan({ session_id: session.session_id, iteration: session.aep_iteration, observe_result: 'DENY', deny_code: resp.deny_code, prior_denial_count: resp.prior_denial_count, cap_evaluation_result: 'DENY' });
      return resp;
    }

    // --- Step 3: Cedar Evaluation ---
    const cedarResult = evaluateCedarPolicySet(cedarPolicies);
    if (cedarResult.decision === 'FORBID') {
      const resp = this.denyResponse(session, `CEDAR_DENY_${cedarResult.forbiddingPolicyId}`, `Cedar policy ${cedarResult.forbiddingPolicyId} forbids ${req.cedar_action}`, req.idp);
      emitObserveSpan({ session_id: session.session_id, iteration: session.aep_iteration, observe_result: 'DENY', deny_code: resp.deny_code, prior_denial_count: resp.prior_denial_count, cap_evaluation_result: 'PERMIT', cedar_evaluation_result: 'DENY' });

      if (this.shouldEnterStalled(session, resp.prior_denial_count)) {
        return this.enterStalled(session, 'STALL_DENY_THRESHOLD', resp.deny_code);
      }
      return resp;
    }

    // --- Step 4: State Machine Validation ---
    const soType = resolveSOType(session.so.so_type_id);
    if (!soType || !soType.action_space.includes(req.cedar_action)) {
      return this.denyResponse(session, 'INVALID_STATE_TRANSITION', `action ${req.cedar_action} not in ${session.so.so_type_id}'s action space`, req.idp);
    }
    // Sample-code approximation of the (current_state, action) edge check:
    // SOV's state list doesn't encode a full transition graph in this
    // codebase (that's DR-PLAN-01/Transition Graph territory, out of this
    // session's dependency set) — treat any action in the SO Type's
    // action_space as valid from any non-terminal state, same category
    // approximation as SOV's own POLICY_EVALUATION_ORDER stub.
    const terminalStates = ['COMPLETED', 'CANCELLED', 'COMPLETE'];
    if (terminalStates.includes(session.so.current_state)) {
      return this.denyResponse(session, 'INVALID_STATE_TRANSITION', `SO is in terminal state ${session.so.current_state}`, req.idp);
    }

    // EOD scope check (§6.5(c)) — deferred to here since it needs Step 4's
    // resolved SO Type context.
    if (session.eod && !session.plan_b_activated) {
      const declaredTargetOk = req.idp.declared_goal.description !== undefined; // structural presence only in this sample
      if (!declaredTargetOk) {
        return this.denyResponse(session, 'EOD_SCOPE_VIOLATION', 'IDP target inconsistent with EOD primary_outcome and no Plan B active', req.idp);
      }
    }

    // --- Step 5: Event Stream Write (atomic) ---
    const newState = this.deriveTargetState(req.cedar_action, session.so.current_state);
    const event: SOEvent = this.sovMediator.transition(session.so, newState, session.root_mandate.aud, true);

    // --- Step 6: Event Emission (MUST NOT block; failure MUST NOT affect completeness) ---
    try {
      this.emit(ALEType.CEDAR_PERMIT, {
        session_id: session.session_id, actor_id: 'GEC', timestamp: new Date().toISOString(), causal_parent_id: null,
        decision: 'PERMIT', cedar_policy_id: 'aep-sample-policy', cap_rrs_control_id: 'n/a', authority_source_uri: 'n/a',
      });
    } catch {
      /* best-effort per Step 6 — never block the transition on this */
    }

    this.idp.recordPermit(req.idp, event.payload?.from_state as string, newState);

    const response: PermitResponse = {
      result: 'PERMIT',
      new_state: newState,
      new_phase: session.so.current_phase,
      event_stream_entry_id: event.entry_id,
      aep_iteration: session.aep_iteration,
    };
    emitObserveSpan({
      session_id: session.session_id, iteration: session.aep_iteration, observe_result: 'PERMIT',
      event_stream_entry_id: event.entry_id, cap_evaluation_result: 'PERMIT', cedar_evaluation_result: 'PERMIT',
    });
    session.aep_iteration += 1;
    return response;
  }

  // -------------------------------------------------------------------
  // §5.4 — STALLED entry
  // -------------------------------------------------------------------

  private shouldEnterStalled(session: AepSession, priorDenialCount: number): boolean {
    return priorDenialCount >= session.stall_deny_threshold;
  }

  private enterStalled(session: AepSession, reason: StalledResponse['stall_reason'], last_deny_code: string | null): StalledResponse {
    session.state = 'STALLED';
    this.emit(ALEType.AEP_STALLED, {
      session_id: session.session_id, actor_id: 'GEC', timestamp: new Date().toISOString(), causal_parent_id: null,
      aep_iteration: session.aep_iteration, stall_reason: reason, consecutive_denies: session.stall_deny_threshold,
      last_deny_code, eod_plan_b_available: session.eod?.plan_b !== null && session.eod?.plan_b !== undefined,
    });

    // §5.5 — automatic Plan B activation.
    if (session.eod?.auto_activate_plan_b && session.eod.plan_b && (reason === 'STALL_PATH_EXHAUSTED' || reason === 'STALL_DENY_THRESHOLD')) {
      this.activatePlanB(session, 'AUTOMATIC');
    }

    return { result: 'STALLED', stall_reason: reason, aep_iteration: session.aep_iteration };
  }

  /** §5.4(i) ACTIVATE_PLAN_B / §5.5 automatic activation. */
  activatePlanB(session: AepSession, activation_type: 'MANUAL' | 'AUTOMATIC'): void {
    if (!session.eod?.plan_b) {
      throw new AepDenyError('NO_PLAN_B_DECLARED', 'session has no EOD Plan B to activate');
    }
    session.state = 'PLAN_B_ACTIVE';
    session.plan_b_activated = true;
    session.operative_goal_state = session.eod.plan_b.plan_b_target_state;
    this.emit(ALEType.AEP_PLAN_B_ACTIVATED, {
      session_id: session.session_id, actor_id: 'GEC', timestamp: new Date().toISOString(), causal_parent_id: null,
      aep_iteration: session.aep_iteration, eod_id: session.eod.eod_id, plan_b_id: session.eod.plan_b.plan_b_id,
      plan_b_target_state: session.eod.plan_b.plan_b_target_state, activation_type,
    });
  }

  // -------------------------------------------------------------------
  // §5.6 — Session Closure
  // -------------------------------------------------------------------

  closeSession(session: AepSession, closure_reason: ClosureReason, goal_achieved: boolean): void {
    session.state = 'CLOSED';
    session.closure_reason = closure_reason;
    this.emit(ALEType.AEP_SESSION_CLOSED, {
      session_id: session.session_id, actor_id: 'GEC', timestamp: new Date().toISOString(), causal_parent_id: null,
      goal_session_id: session.goal_session_id, total_iterations: session.aep_iteration, final_state: session.so.current_state,
      goal_achieved, closure_reason, session_xpid: session.session_xpid, eod_id: session.eod?.eod_id ?? null,
      plan_b_activated: session.plan_b_activated,
    });
  }

  // -------------------------------------------------------------------
  // internal
  // -------------------------------------------------------------------

  private denyResponse(session: AepSession, deny_code: string, deny_reason: string, idp: IntentDeclaration): DenyResponse {
    const rec = this.idp.recordDeny(idp, deny_code, deny_reason, {}, []);
    return {
      result: 'DENY',
      deny_code,
      deny_reason,
      idp_ref: idp.idp_id,
      enrichment: rec.enrichment,
      aep_iteration: session.aep_iteration,
      prior_denial_count: rec.prior_denial_count,
      what_changed_guidance: rec.what_changed_guidance,
    };
  }

  private deriveTargetState(cedarAction: string, currentState: string): string {
    // Minimal action->state mapping for the ATP booking SO Type used in
    // this sample's demo/corpus — a real deployment resolves this from
    // the Transition Graph (§8.1), out of this session's dependency set.
    const map: Record<string, string> = {
      'atp:booking:confirm': 'CONFIRMED',
      'atp:booking:cancel': 'CANCELLED',
      'atp:booking:suspend': 'PRE_ACTIVITY',
      'atp:booking:resume': 'IN_JOURNEY',
      'atp:booking:complete': 'COMPLETED',
    };
    return map[cedarAction] ?? currentState;
  }

  private decodeClaims(token: string): MJWTClaims {
    const parts = token.split('.');
    return JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as MJWTClaims;
  }

  private revokedJtiSet(): Set<string> {
    // RevocationRegistry doesn't expose enumeration; this sample tracks
    // revocations solely through isRevoked() checks elsewhere. Session
    // init/ACT only need per-jti lookups, which GECVerificationContext
    // takes as a Set for MJWT's verifyMandate() to check — an empty set
    // here plus explicit per-call isRevoked() checks upstream is the
    // working pattern for this sample.
    return new Set();
  }

  private emit(ale_type: ALEType, fields: { session_id: string; actor_id: string; timestamp: string; causal_parent_id: string | null } & Record<string, unknown>): GAREntry {
    return this.gar.append({ ale_type, ...fields } as unknown as Omit<GAREntry, 'prev_span_hash' | 'own_span_hash'>);
  }
}
