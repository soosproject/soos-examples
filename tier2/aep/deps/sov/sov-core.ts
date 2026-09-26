// SOV (Sovereign Object) — core implementation
// draft-sato-soos-sov-02
// SDB-01 — see svl/issue-log.md: draft does not name SUSPENDED as a
// current_phase value. Confirmed current_phase enum below is drawn
// directly from the SOV-01/-02 schema table (ACTIVE ->
// OPERATIONALLY_COMPLETE -> ADMINISTRATIVELY_CLOSED -> ARCHIVED ->
// CRYPTOGRAPHICALLY_ERASED). No SUSPENDED phase exists. Note: the
// draft's own Cedar example uses `resource.current_state == "HEM_PENDING"`
// — i.e. an escalation pause is modeled as a current_state value, not a
// current_phase value, in at least one place in the draft. That's a
// plausible resolution pattern but is not stated as a general rule, so
// SDB-01 remains open. TODO: SDB-01.

import { createHash, randomBytes } from 'crypto';
import { generateKeyPairSync, sign as edSign } from 'crypto';

// ---------------------------------------------------------------------
// UUID v7 — time-ordered, per RFC 9562. Node's built-in randomUUID()
// only produces v4; SOV-02 requires v7 for so_id/entry_id, so a small
// compliant generator is implemented here rather than substituting v4
// (Type I mapping decision — draft is explicit about v7, silently using
// v4 would misrepresent time-ordering that downstream code may rely on).
// ---------------------------------------------------------------------
export function uuidv7(): string {
  const unixMs = BigInt(Date.now());
  const rand = randomBytes(10);

  const bytes = Buffer.alloc(16);
  bytes.writeUIntBE(Number(unixMs & 0xffffffffffffn), 0, 6);
  bytes[6] = 0x70 | (rand[0] & 0x0f); // version 7
  bytes[7] = rand[1];
  bytes[8] = 0x80 | (rand[2] & 0x3f); // variant 10
  rand.copy(bytes, 9, 3, 10);

  const hex = bytes.toString('hex');
  return [
    hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16),
    hex.slice(16, 20), hex.slice(20, 32),
  ].join('-');
}

// ---------------------------------------------------------------------
// Lifecycle phase (State layer) — SOV-01/-02 schema table
// TODO: SDB-01 — no SUSPENDED phase defined. See svl/issue-log.md
// ISSUE-006. HEM_PENDING precedent in the draft's Cedar example suggests
// pause conditions may belong at current_state rather than current_phase,
// but this is not confirmed as a general rule.
// ---------------------------------------------------------------------
export type SOPhase =
  | 'ACTIVE'
  | 'OPERATIONALLY_COMPLETE'
  | 'ADMINISTRATIVELY_CLOSED'
  | 'ARCHIVED'
  | 'CRYPTOGRAPHICALLY_ERASED';

export type SOEventType =
  | 'SO_CREATED'
  | 'STATE_TRANSITION'
  | 'SPO_ACTIVATED'
  | 'MISSION_STEP_COMPLETE'
  | 'ZONE_A_WRITE_REJECTED'
  | 'MISSION_STATUS_WRITE_REJECTED'
  // NEW, kernel design restart (SOV-05 §4.2.6 / MJWT mandate issuance):
  // MANDATE_BOUND records a mandate's issuance, once. MANDATE_SESSION_BOUND
  // is repeatable — one per GAR session opened under that mandate, since a
  // mandate MAY govern multiple sessions over its validity window and the
  // (once-written, immutable) MANDATE_BOUND entry cannot itself carry a
  // single fixed back-reference to every session that follows.
  | 'MANDATE_BOUND'
  | 'MANDATE_SESSION_BOUND';

// ---------------------------------------------------------------------
// Zone A — operational fields only. INV-ZA-1: MUST NOT contain personal
// data. Enforced here as a denylist of common personal-data field names;
// a production implementation would likely use a schema/type-level
// guarantee rather than runtime denylist scanning (Type I: reasonable
// sample-code approximation of a MUST that SOV-02 doesn't specify an
// enforcement mechanism for).
// ---------------------------------------------------------------------
const PERSONAL_DATA_FIELD_DENYLIST = [
  'email', 'phone', 'ssn', 'address', 'name', 'dob', 'date_of_birth',
  'passport', 'credit_card', 'full_name', 'birthdate',
];

export function assertNoPersonalData(zoneA: Record<string, unknown>, path = ''): void {
  for (const [key, value] of Object.entries(zoneA)) {
    const normalized = key.toLowerCase();
    const fullPath = path ? `${path}.${key}` : key;
    if (PERSONAL_DATA_FIELD_DENYLIST.some((banned) => normalized.includes(banned))) {
      throw new Error(
        `Zone A write rejected: field '${fullPath}' resembles personal data (INV-ZA-1, SOV §Zone A)`
      );
    }
    // Recurse into nested plain objects — a denylisted key nested inside an
    // otherwise-innocuous-looking field (e.g. { contact: { email: '...' } })
    // must still be caught. SOV-EDGE-004 confirmed this was previously
    // top-level-only and silently missed nested personal data.
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      assertNoPersonalData(value as Record<string, unknown>, fullPath);
    }
  }
}

// ---------------------------------------------------------------------
// Event Stream entry — append-only, GEC-signed, causal chain via
// prior_event_id, mandatory soos.governance.kernel_id on every entry
// ---------------------------------------------------------------------
export interface SOEvent {
  entry_id: string;             // UUID v7
  so_id: string;
  event_type: SOEventType;
  actor_id: string;             // 'GEC' or an agent id
  timestamp: string;            // ISO 8601
  prior_event_id: string | null; // null ONLY for SO_CREATED
  kernel_id: string;            // soos.governance.kernel_id — mandatory every entry
  gec_signature: string;        // stub Ed25519 signature over entry content
  payload?: Record<string, unknown>;

  // MANDATE_BOUND / MANDATE_SESSION_BOUND fields (NEW, kernel design restart).
  // prior_event_id above still applies but, for these two types only, chains
  // within the mandate's own sub-chain (MANDATE_BOUND, then successive
  // MANDATE_SESSION_BOUND entries for the same mandate_id) rather than the
  // SO's general chain — see EventStream.bindMandate()/bindSession().
  mandate_id?: string;
  gar_session_id?: string;            // MANDATE_SESSION_BOUND only
  gar_sequence_record_id?: string;    // MANDATE_SESSION_BOUND only — GAR's Type 6 record id
}

// KIA/GEC stub signer — same pattern as gar-core.ts KIAStubSigner.
// Replace with real GEC-issued signature when GEC integration lands.
export class GECStubSigner {
  private privateKey: any;
  public keyId: string;

  constructor() {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    this.privateKey = privateKey;
    this.keyId = createHash('sha256')
      .update(publicKey.export({ type: 'spki', format: 'der' }))
      .digest('hex')
      .slice(0, 16);
  }

  sign(data: string): string {
    return edSign(null, Buffer.from(data), this.privateKey).toString('hex');
  }
}

export class EventStream {
  private events: SOEvent[] = [];
  private lastEventIdBySO: Map<string, string> = new Map();
  // Per-mandate sub-chain (NEW): keyed by mandate_id, not so_id. Distinct
  // from, but interleaved with, the SO's own general chain above — see
  // bindMandate()/bindSession().
  private lastEventIdByMandate: Map<string, string> = new Map();

  /**
   * MANDATE_BOUND (NEW) — records a mandate's issuance, once. Does not
   * touch lastEventIdBySO: this event starts its own per-mandate sub-chain,
   * it isn't a link in the SO's general one.
   */
  bindMandate(
    so_id: string,
    mandate_id: string,
    actor_id: string,
    timestamp: string,
    kernel_id: string,
    signer: GECStubSigner,
  ): SOEvent {
    if (this.lastEventIdByMandate.has(mandate_id)) {
      throw new Error(
        `EventStream bindMandate rejected: mandate_id '${mandate_id}' already has a MANDATE_BOUND entry — ` +
          `issuance is once-only, use bindSession() for subsequent sessions under this mandate`
      );
    }
    const entry_id = uuidv7();
    const canonical = [so_id, 'MANDATE_BOUND', actor_id, timestamp, kernel_id, 'GENESIS', mandate_id].join('|');
    const gec_signature = signer.sign(canonical);
    const full: SOEvent = {
      entry_id, so_id, event_type: 'MANDATE_BOUND', actor_id, timestamp, kernel_id, gec_signature,
      prior_event_id: null, mandate_id,
    };
    this.events.push(full);
    this.lastEventIdByMandate.set(mandate_id, entry_id);
    return full;
  }

  /**
   * MANDATE_SESSION_BOUND (NEW, SOV-05 §4.2.6) — repeatable, one per GAR
   * session opened under `mandate_id`. prior_event_id chains to the
   * mandate's MANDATE_BOUND entry (first session) or the immediately
   * preceding MANDATE_SESSION_BOUND for the same mandate_id (subsequent
   * sessions) — never the SO's general chain.
   */
  bindSession(
    so_id: string,
    mandate_id: string,
    gar_session_id: string,
    gar_sequence_record_id: string,
    actor_id: string,
    timestamp: string,
    kernel_id: string,
    signer: GECStubSigner,
  ): SOEvent {
    const priorMandateEventId = this.lastEventIdByMandate.get(mandate_id);
    if (!priorMandateEventId) {
      throw new Error(
        `EventStream bindSession rejected: mandate_id '${mandate_id}' has no MANDATE_BOUND entry — ` +
          `call bindMandate() first (this is the SOV side of GAR's CONF-GAR-SEQ-02 resolution failing)`
      );
    }
    const entry_id = uuidv7();
    const canonical = [
      so_id, 'MANDATE_SESSION_BOUND', actor_id, timestamp, kernel_id, priorMandateEventId, mandate_id, gar_session_id,
    ].join('|');
    const gec_signature = signer.sign(canonical);
    const full: SOEvent = {
      entry_id, so_id, event_type: 'MANDATE_SESSION_BOUND', actor_id, timestamp, kernel_id, gec_signature,
      prior_event_id: priorMandateEventId, mandate_id, gar_session_id, gar_sequence_record_id,
    };
    this.events.push(full);
    this.lastEventIdByMandate.set(mandate_id, entry_id);
    return full;
  }

  /**
   * The SOV side of GAR's CONF-GAR-SEQ-02 lookup ("SO Instance Typed Graph,
   * MUST expose currently bound Mandate JWTs"). Returns the mandate's most
   * recent chain entry_id (MANDATE_BOUND if no session yet, else the latest
   * MANDATE_SESSION_BOUND) if bound, else null — pass this as GARLog's
   * resolveMandateBinding callback.
   */
  resolveMandateBinding(mandate_id: string): string | null {
    return this.lastEventIdByMandate.get(mandate_id) ?? null;
  }

  append(
    entry: Omit<SOEvent, 'entry_id' | 'prior_event_id' | 'gec_signature'>,
    signer: GECStubSigner
  ): SOEvent {
    const priorId = this.lastEventIdBySO.get(entry.so_id) ?? null;

    if (priorId === null && entry.event_type !== 'SO_CREATED') {
      throw new Error(
        `EventStream append rejected: first entry for so_id '${entry.so_id}' must be ` +
          `SO_CREATED (got '${entry.event_type}')`
      );
    }
    if (priorId !== null && entry.event_type === 'SO_CREATED') {
      throw new Error(
        `EventStream append rejected: SO_CREATED must be the first entry for so_id ` +
          `'${entry.so_id}', but ${this.getForSO(entry.so_id).length} entries already exist`
      );
    }

    const entry_id = uuidv7();
    const canonical = [
      entry.so_id, entry.event_type, entry.actor_id, entry.timestamp,
      entry.kernel_id, priorId ?? 'GENESIS', JSON.stringify(entry.payload ?? {}),
    ].join('|');
    const gec_signature = signer.sign(canonical);

    const full: SOEvent = { ...entry, entry_id, prior_event_id: priorId, gec_signature };
    this.events.push(full);
    this.lastEventIdBySO.set(entry.so_id, entry_id);
    return full;
  }

  getForSO(so_id: string): SOEvent[] {
    return this.events.filter((e) => e.so_id === so_id);
  }

  all(): SOEvent[] {
    return [...this.events];
  }
}

// ---------------------------------------------------------------------
// SovereignObject — Identity + State layers. Typed Graph and Attachment
// Index are represented as lightweight stubs (materialized view / content
// refs) rather than full implementations, per the plan's Tier 1 scope.
// ---------------------------------------------------------------------
export interface AttachmentRef {
  content_hash: string; // SHA-256, Zone B integrity check
  uri: string;
}

export class SovereignObject {
  public readonly so_id: string;
  public readonly so_type_id: string;
  public readonly human_principal_id: string;
  public gec_id: string;
  public current_state: string;
  public current_phase: SOPhase;
  public state_entered_at: string;
  public zoneA: Record<string, unknown>;
  public readonly attachments: AttachmentRef[] = []; // Zone B index (content refs only)
  public readonly parent_so_id: string | null;

  constructor(opts: {
    so_type_id: string;
    human_principal_id: string;
    gec_id: string;
    current_state: string;
    zoneA?: Record<string, unknown>;
    parent_so_id?: string | null;
  }) {
    this.so_id = uuidv7();
    this.so_type_id = opts.so_type_id;
    this.human_principal_id = opts.human_principal_id;
    this.gec_id = opts.gec_id;
    this.current_state = opts.current_state;
    this.current_phase = 'ACTIVE';
    this.state_entered_at = new Date().toISOString();
    this.zoneA = opts.zoneA ?? {};
    this.parent_so_id = opts.parent_so_id ?? null;

    assertNoPersonalData(this.zoneA); // INV-ZA-1 enforced at construction
  }

  addAttachment(ref: AttachmentRef): void {
    this.attachments.push(ref);
  }
}

// ---------------------------------------------------------------------
// GECMediator — the only path for state transitions. "All transitions
// are GEC-mediated — no agent writes Zone A directly" is enforced here:
// transition() requires isGEC === true or throws.
// ---------------------------------------------------------------------
export class GECMediator {
  constructor(private stream: EventStream, private signer: GECStubSigner) {}

  create(so: SovereignObject, kernel_id: string): SOEvent {
    return this.stream.append(
      {
        so_id: so.so_id, event_type: 'SO_CREATED', actor_id: 'GEC',
        timestamp: new Date().toISOString(), kernel_id,
        payload: {
          so_type_id: so.so_type_id, current_state: so.current_state,
          current_phase: so.current_phase, parent_so_id: so.parent_so_id,
        },
      },
      this.signer
    );
  }

  transition(
    so: SovereignObject,
    newState: string,
    kernel_id: string,
    isGEC: boolean,
    newPhase?: SOPhase
  ): SOEvent {
    if (!isGEC) {
      throw new Error(
        `Transition rejected: SO '${so.so_id}' Zone A may only be written by the GEC — ` +
          `agent-authored direct transitions are forbidden (SOV §GEC mediation)`
      );
    }
    const oldState = so.current_state;
    so.current_state = newState;
    if (newPhase) so.current_phase = newPhase;
    so.state_entered_at = new Date().toISOString();

    return this.stream.append(
      {
        so_id: so.so_id, event_type: 'STATE_TRANSITION', actor_id: 'GEC',
        timestamp: so.state_entered_at, kernel_id,
        payload: { from_state: oldState, to_state: newState, current_phase: so.current_phase },
      },
      this.signer
    );
  }
}

// ---------------------------------------------------------------------
// StandingPlanObject (soos/standing-plan-object/1.0) — SOV-02 subtype
// ---------------------------------------------------------------------
export interface ScopeConstraints {
  geographic?: string[];
  so_type?: string[];
  agent_role?: string[];
  temporal?: { not_before?: string; not_after?: string };
  delegation_depth?: number;
}

export class StandingPlanObject extends SovereignObject {
  public scope_constraints: ScopeConstraints;
  public cedar_bundle_ref: string;
  public cap_rrs_catalog_ref: string;
  public idp_validation_ref: string;
  public active: boolean = false;

  constructor(opts: {
    human_principal_id: string;
    gec_id: string;
    scope_constraints: ScopeConstraints;
    cedar_bundle_ref: string;
    cap_rrs_catalog_ref: string;
    idp_validation_ref: string;
  }) {
    super({
      so_type_id: 'soos/standing-plan-object/1.0',
      human_principal_id: opts.human_principal_id,
      gec_id: opts.gec_id,
      current_state: 'DRAFT',
    });
    this.scope_constraints = opts.scope_constraints;
    this.cedar_bundle_ref = opts.cedar_bundle_ref;
    this.cap_rrs_catalog_ref = opts.cap_rrs_catalog_ref;
    this.idp_validation_ref = opts.idp_validation_ref;
  }

  activate(mediator: GECMediator, kernel_id: string): SOEvent {
    this.active = true;
    return mediator.transition(this, 'ACTIVE_STANDING', kernel_id, true);
  }
}

// ---------------------------------------------------------------------
// MissionPlanSO (soos/mission-plan/1.0) — DAG-structured sub-goals
// ---------------------------------------------------------------------
export type EdgeType = 'SEQUENTIAL' | 'PARALLEL';

export interface MissionEdge {
  from_step_id: string;
  to_step_id: string;
  edge_type: EdgeType;
}

export interface MissionStep {
  step_id: string;
  description: string;
}

export class MissionPlanSO extends SovereignObject {
  public steps: MissionStep[] = [];
  public edges: MissionEdge[] = [];

  constructor(opts: { human_principal_id: string; gec_id: string }) {
    super({
      so_type_id: 'soos/mission-plan/1.0',
      human_principal_id: opts.human_principal_id,
      gec_id: opts.gec_id,
      current_state: 'PLANNING',
    });
  }

  addStep(step: MissionStep): void {
    this.steps.push(step);
  }

  addEdge(edge: MissionEdge): void {
    const stepIds = new Set(this.steps.map((s) => s.step_id));
    if (!stepIds.has(edge.from_step_id) || !stepIds.has(edge.to_step_id)) {
      throw new Error(
        `MissionPlanSO edge rejected: from_step_id/to_step_id must reference existing steps ` +
          `(${edge.from_step_id} -> ${edge.to_step_id})`
      );
    }

    // DAG cycle detection — SOV-EDGE-005 confirmed this was previously
    // unenforced: edges were accepted silently even when they closed a
    // cycle, contradicting the "DAG-structured sub-goals" claim in the
    // plan and the draft. Check whether adding this edge would create a
    // path back from to_step_id to from_step_id via a DFS over the
    // proposed edge set before committing it.
    const proposed = [...this.edges, edge];
    if (this.hasCycle(proposed)) {
      throw new Error(
        `MissionPlanSO edge rejected: would create a cycle (${edge.from_step_id} -> ` +
          `${edge.to_step_id}) — Mission Plan sub-goals must form a DAG`
      );
    }

    this.edges.push(edge);
  }

  private hasCycle(edges: MissionEdge[]): boolean {
    const adjacency = new Map<string, string[]>();
    for (const e of edges) {
      if (!adjacency.has(e.from_step_id)) adjacency.set(e.from_step_id, []);
      adjacency.get(e.from_step_id)!.push(e.to_step_id);
    }
    const visiting = new Set<string>();
    const visited = new Set<string>();

    const dfs = (node: string): boolean => {
      if (visiting.has(node)) return true; // back-edge found -> cycle
      if (visited.has(node)) return false;
      visiting.add(node);
      for (const next of adjacency.get(node) ?? []) {
        if (dfs(next)) return true;
      }
      visiting.delete(node);
      visited.add(node);
      return false;
    };

    for (const step of this.steps) {
      if (dfs(step.step_id)) return true;
    }
    return false;
  }
}

// ---------------------------------------------------------------------
// MissionStatusSO (soos/mission-status/1.0) — live execution mirror,
// GEC-EXCLUSIVE write. An agent attempting to write directly must reject.
// ---------------------------------------------------------------------
export class MissionStatusSO extends SovereignObject {
  public step_states: Record<string, string> = {};

  constructor(opts: { human_principal_id: string; gec_id: string; mission_plan_so_id: string }) {
    super({
      so_type_id: 'soos/mission-status/1.0',
      human_principal_id: opts.human_principal_id,
      gec_id: opts.gec_id,
      current_state: 'MIRRORING',
      parent_so_id: opts.mission_plan_so_id,
    });
  }

  writeStepState(step_id: string, state: string, isGEC: boolean): void {
    if (!isGEC) {
      throw new Error(
        `MissionStatusSO write rejected: '${this.so_id}' is GEC-exclusive — agent-authored ` +
          `direct writes are forbidden (SOV §Mission Status SO)`
      );
    }
    this.step_states[step_id] = state;
  }
}

// ---------------------------------------------------------------------
// Policy evaluation order stub (documented, not enforced end-to-end in
// Tier 1 sample code — no live Cedar/CAP-RRS/MJWT engines are wired up).
// (1) CAP Tier 0, (2) CAP Tier 1, (3) SPO scope constraints,
// (4) SO Type Cedar (parent then subtype), (5) MJWT scope.
// ---------------------------------------------------------------------
export const POLICY_EVALUATION_ORDER = [
  'CAP_TIER_0',
  'CAP_TIER_1',
  'SPO_SCOPE_CONSTRAINTS',
  'SO_TYPE_CEDAR_PARENT',
  'SO_TYPE_CEDAR_SUBTYPE',
  'MJWT_SCOPE',
] as const;
