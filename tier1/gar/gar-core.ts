// GAR (Governance Audit Record) — core implementation
// draft-sato-soos-gar-03
// SDB-GAR-01 resolution applied — see svl/issue-log.md ISSUE-001

import { createHash, randomBytes } from 'crypto';
import { generateKeyPairSync, sign as edSign } from 'crypto';

// ---------------------------------------------------------------------
// ALE event types (GAR-03 §6 / §3 Terminology)
// ---------------------------------------------------------------------
export enum ALEType {
  // Type 6 (NEW, kernel design restart, GAR-09/-10): committed BEFORE any
  // governed action in a session may execute — see GARLog.openSession().
  SESSION_OPEN_RECORD = 'SESSION_OPEN_RECORD',
  SESSION_START = 'SESSION_START',
  SESSION_END = 'SESSION_END',
  SESSION_COMPLETE = 'SESSION_COMPLETE',       // ALE-005
  SESSION_HALTED_CLEAN = 'SESSION_HALTED_CLEAN',       // ALE-002
  SESSION_HALTED_PARTIAL = 'SESSION_HALTED_PARTIAL',   // ALE-003
  SESSION_HALTED_UNKNOWN = 'SESSION_HALTED_UNKNOWN',   // ALE-004
  CEDAR_PERMIT = 'CEDAR_PERMIT',
  CEDAR_DENY = 'CEDAR_DENY',
  HEM_ESCALATION = 'HEM_ESCALATION',
  GOVERNANCE_SUSPENDED = 'GOVERNANCE_SUSPENDED',
}

export type Decision = 'PERMIT' | 'DENY' | 'SUSPENDED' | 'ESCALATE';

// ---------------------------------------------------------------------
// GAREntry — GAR-03 §3 entry schema, with -03 mandatory provenance
// fields on CEDAR_PERMIT / CEDAR_DENY
// ---------------------------------------------------------------------
export interface GAREntry {
  entry_id: string;
  ale_type: ALEType;
  session_id: string;
  actor_id: string;
  timestamp: string;                 // ISO 8601 — descriptive metadata only;
                                      // NOT an ordering key. Chain integrity comes
                                      // from append() call order + prev_span_hash /
                                      // own_span_hash, not from timestamp comparison.
                                      // GAR-EDGE-005 confirmed identical timestamps
                                      // across entries are harmless (Type I, no gap).
  causal_parent_id: string | null;    // GAR-03 §3 causal ordering

  // soos.governance.* core (GAR-03 §13.2) — present on every governance span
  decision?: Decision;
  kernel_id?: string;
  cap_profile_id?: string;
  cap_profile_hash?: string;

  // soos.cap.* (GAR-03 §13.3) — REQUIRED on CEDAR_PERMIT / CEDAR_DENY
  cedar_policy_id?: string;
  cap_rrs_control_id?: string;
  authority_source_uri?: string;
  tier?: string;
  conflict_detected?: boolean;
  // soos.cap.cedar_action (NEW, GAR-11): the plain Cedar action string, on both
  // PERMIT and DENY spans. subject_digest-equivalent fields elsewhere in this
  // suite are hashes, provable but not matchable against a trajectory
  // condition without the pre-image; this is what CAP-RRS's
  // condition_temporal_hint actually needs. Additive only in this sample —
  // not yet added to MANDATORY_PROVENANCE, to avoid breaking every existing
  // caller in one pass; real enforcement is a follow-up.
  cedar_action?: string;

  // Type 6 fields (NEW, GAR-09/-10) — present only on SESSION_OPEN_RECORD entries.
  session_sequence_number?: number;
  sov_binding_event_id?: string;   // resolved MANDATE_BOUND / MANDATE_SESSION_BOUND entry
  mandate_id?: string;             // the jti this session opens under

  // HEM escalation fields
  escalation_class?: string;
  so_reference?: string;

  // soos.gar.* integrity (GAR-03 §13.7)
  prev_span_hash: string;            // 'GENESIS' for first entry in session — SDB-GAR-01
  own_span_hash: string;             // this entry's own content hash — verifyChain() failure
                                      // index fix (Step 1b finding #1): without this field,
                                      // verifyChain() can only detect tampering to entry N by
                                      // checking entry N+1's prev_span_hash, so a modified entry N
                                      // reports failedAt: N+1. Storing the entry's own derived
                                      // hash lets verification localize the failure to N itself.
  block_id?: string;                 // = OTel trace_id, set at session close
}

const MANDATORY_PROVENANCE: (keyof GAREntry)[] = [
  'cedar_policy_id',
  'cap_rrs_control_id',
  'authority_source_uri',
];

// ---------------------------------------------------------------------
// computePrevSpanHash — SDB-GAR-01 resolution (svl/issue-log.md ISSUE-001)
// ---------------------------------------------------------------------
export function computePrevSpanHash(span: {
  session_id: string;
  decision?: string;
  kernel_id?: string;
  cap_profile_hash?: string;
  timestamp: string;
  prev_span_hash: string;
}): string {
  const canonical = [
    span.session_id,
    span.decision ?? '',
    span.kernel_id ?? '',
    span.cap_profile_hash ?? '',
    span.timestamp,
    span.prev_span_hash,
  ].join('|');
  return createHash('sha256').update(canonical).digest('hex');
}

// ---------------------------------------------------------------------
// KIA stub signer — Ed25519 local keypair
// // KIA stub — replace with real KIA Governance Identity Keypair when Step 6 completes
// ---------------------------------------------------------------------
export class KIAStubSigner {
  private privateKey: any;
  public publicKeyId: string;

  constructor() {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    this.privateKey = privateKey;
    this.publicKeyId = createHash('sha256')
      .update(publicKey.export({ type: 'spki', format: 'der' }))
      .digest('hex')
      .slice(0, 16);
  }

  sign(data: string): string {
    return edSign(null, Buffer.from(data), this.privateKey).toString('hex');
  }
}

// ---------------------------------------------------------------------
// GARLog — append-only log. No delete() method (GAR-03 §5, append-only).
// ---------------------------------------------------------------------
export class GARLog {
  private entries: GAREntry[] = [];
  private lastHashBySession: Map<string, string> = new Map();
  private nextSequenceNumber = 0; // CONF-GAR-SEQ-01 — monotonic per GEC instance, never reused

  /**
   * Type 6 — Session-Open Record (NEW, GAR-09/-10).
   *
   * CONF-GAR-SEQ-01: commits session_sequence_number BEFORE any governed
   * action in the session may execute — closing the suppression window that
   * existed when the number lived only in the SAR, generated solely at
   * session close (a session's whole action history could execute and take
   * effect, then be suppressed, with nothing but an eventual, inferential
   * numbering gap for a verifier to notice).
   *
   * CONF-GAR-SEQ-02: resolveMandateBinding is the caller's SOV Typed Graph
   * lookup (mandate_id -> bound entry). Resolution failure MUST prevent the
   * session from opening at all — this throws rather than appending
   * anything, so no Session-Open Record, no session, no governed action.
   */
  openSession(params: {
    session_id: string;
    actor_id: string;
    mandate_id: string;
    timestamp: string;
    resolveMandateBinding: (mandate_id: string) => string | null;
  }): GAREntry {
    const sov_binding_event_id = params.resolveMandateBinding(params.mandate_id);
    if (sov_binding_event_id === null) {
      throw new Error(
        `GAR session open rejected: mandate_id ${params.mandate_id} did not resolve against SOV's Typed Graph ` +
          `(CONF-GAR-SEQ-02) — session MUST NOT open; caller MUST additionally emit KERNEL_AUDIT_ANOMALY`
      );
    }
    const session_sequence_number = this.nextSequenceNumber++;
    return this.append({
      entry_id: `sor-${params.session_id}`,
      ale_type: ALEType.SESSION_OPEN_RECORD,
      session_id: params.session_id,
      actor_id: params.actor_id,
      timestamp: params.timestamp,
      causal_parent_id: null,
      session_sequence_number,
      sov_binding_event_id,
      mandate_id: params.mandate_id,
    });
  }

  // TODO: SDB-GAR-03 — append() does not validate that causal_parent_id
  // references an entry that actually exists in the log, nor that
  // timestamps are monotonically non-decreasing within a session.
  // GAR-EDGE-003 confirmed both are currently accepted silently. Needs a
  // Decision Record: enforce here, or leave to a higher layer (e.g. SOV
  // Event Stream)? Non-blocking for Step 1 Done Criteria.
  append(entry: Omit<GAREntry, 'prev_span_hash' | 'own_span_hash'>): GAREntry {
    const prev = this.lastHashBySession.get(entry.session_id) ?? 'GENESIS';

    // Mandatory provenance enforcement on CEDAR_PERMIT / CEDAR_DENY (GAR-03 §13.3)
    // TODO: SDB-GAR-05 — GOVERNANCE_SUSPENDED has no enforced field set at all.
    // GAR-EDGE-009 confirmed a SUSPENDED entry is accepted with zero identifying
    // or escalation fields. GAR-03 is silent on what SUSPENDED requires (plausibly
    // escalation_class + so_reference, mirroring HEM_ESCALATION) — not enforcing
    // yet since the correct field set isn't normatively defined.
    if (entry.ale_type === ALEType.CEDAR_PERMIT || entry.ale_type === ALEType.CEDAR_DENY) {
      for (const field of MANDATORY_PROVENANCE) {
        if (!(entry as any)[field]) {
          throw new Error(
            `GAR append rejected: ${entry.ale_type} missing mandatory provenance field '${field}' (GAR-03 §13.3)`
          );
        }
      }
    }

    const ownHash = computePrevSpanHash({
      session_id: entry.session_id,
      decision: entry.decision,
      kernel_id: entry.kernel_id,
      cap_profile_hash: entry.cap_profile_hash,
      timestamp: entry.timestamp,
      prev_span_hash: prev,
    });

    const full: GAREntry = { ...entry, prev_span_hash: prev, own_span_hash: ownHash };

    this.lastHashBySession.set(entry.session_id, ownHash);
    this.entries.push(full);
    return full;
  }

  getSession(session_id: string): GAREntry[] {
    return this.entries.filter((e) => e.session_id === session_id);
  }

  all(): GAREntry[] {
    return [...this.entries];
  }

  // verifyChain — walk entries, recompute each hash, compare (Layer 1, GAR-03 §14.4)
  // Step 1b fix: compares the recomputed hash against entry i's OWN own_span_hash,
  // not entry i+1's prev_span_hash. This localizes a tampered entry to its own index
  // instead of reporting the failure one entry late (GAR-EDGE-006 requirement).
  verifyChain(session_id: string): { valid: boolean; failedAt: number | null } {
    const entries = this.getSession(session_id);
    let prev = 'GENESIS';

    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];
      if (e.prev_span_hash !== prev) {
        return { valid: false, failedAt: i };
      }
      const recomputed = computePrevSpanHash({
        session_id: e.session_id,
        decision: e.decision,
        kernel_id: e.kernel_id,
        cap_profile_hash: e.cap_profile_hash,
        timestamp: e.timestamp,
        prev_span_hash: prev,
      });
      if (recomputed !== e.own_span_hash) {
        return { valid: false, failedAt: i };
      }
      prev = recomputed;
    }
    return { valid: true, failedAt: null };
  }
}

// ---------------------------------------------------------------------
// GARProcessor stub — soos.governance.* attributes -> console
// (real impl would emit to @opentelemetry/api; this is the sample stub)
// ---------------------------------------------------------------------
export class GARProcessor {
  emit(entry: GAREntry): void {
    // soos.governance.* — mandatory on every Cedar evaluation (GAR-03 §13.2)
    const governance =
      `[soos.governance] decision=${entry.decision ?? '-'} ` +
      `kernel_id=${entry.kernel_id ?? '-'} session_id=${entry.session_id} ` +
      `cap_profile_id=${entry.cap_profile_id ?? '-'} ` +
      `cap_profile_hash=${(entry.cap_profile_hash ?? '-').slice(0, 12)}`;
    console.log(governance);

    // soos.cap.* — mandatory on CEDAR_PERMIT / CEDAR_DENY (GAR-03 §13.3)
    if (entry.ale_type === ALEType.CEDAR_PERMIT || entry.ale_type === ALEType.CEDAR_DENY) {
      console.log(
        `[soos.cap] cedar_policy_id=${entry.cedar_policy_id ?? '-'} ` +
          `cap_rrs_control_id=${entry.cap_rrs_control_id ?? '-'} ` +
          `authority_source_uri=${entry.authority_source_uri ?? '-'} ` +
          `tier=${entry.tier ?? '-'} conflict_detected=${entry.conflict_detected ?? false} ` +
          `cedar_action=${entry.cedar_action ?? '-'}` // NEW, GAR-11
      );
    }

    // Type 6 Session-Open Record fields (NEW, GAR-09/-10)
    if (entry.ale_type === ALEType.SESSION_OPEN_RECORD) {
      console.log(
        `[soos.gar.session-open] session_sequence_number=${entry.session_sequence_number ?? '-'} ` +
          `mandate_id=${entry.mandate_id ?? '-'} sov_binding_event_id=${entry.sov_binding_event_id ?? '-'}`
      );
    }
  }
}

// ---------------------------------------------------------------------
// SessionBlock — Merkle root (Layer 2) + KIA signature (GAR-03 §14.3)
// ---------------------------------------------------------------------
export interface SessionBlock {
  block_id: string;
  session_id: string;
  events: GAREntry[];
  merkle_root: string;
  block_signature: {
    algorithm: 'Ed25519';
    key_id: string;
    signature: string;
  };
}

function merkleRoot(leaves: string[]): string {
  if (leaves.length === 0) return createHash('sha256').update('').digest('hex');
  let level = leaves.map((l) => createHash('sha256').update(l).digest('hex'));
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : level[i];
      next.push(createHash('sha256').update(left + right).digest('hex'));
    }
    level = next;
  }
  return level[0];
}

export function closeSessionBlock(
  session_id: string,
  entries: GAREntry[],
  signer: KIAStubSigner
): SessionBlock {
  const block_id = randomBytes(16).toString('hex'); // stand-in for OTel trace_id
  const leaves = entries.map((e) => JSON.stringify(e));
  const root = merkleRoot(leaves);
  const signature = signer.sign(root);

  return {
    block_id,
    session_id,
    events: entries.map((e) => ({ ...e, block_id })),
    merkle_root: root,
    block_signature: {
      algorithm: 'Ed25519',
      key_id: signer.publicKeyId,
      signature,
    },
  };
}

// tamperDetect — modify byte in entry N, verify fails at N (GAR-03 §14.4)
export function tamperDetect(log: GARLog, session_id: string, entryIndex: number): void {
  const entries = log.getSession(session_id);
  if (entries[entryIndex]) {
    (entries[entryIndex] as any).decision = 'TAMPERED';
  }
}
