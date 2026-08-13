// GAR (Governance Audit Record) — core implementation
// draft-sato-soos-gar-04 (proposed)
// SDB-GAR-01 resolution applied — see svl/issue-log.md ISSUE-001
// SDB-GAR-06 resolution applied — see notes below (Merkle canonicalization)

import { createHash, randomBytes } from 'crypto';
import { generateKeyPairSync, sign as edSign } from 'crypto';

// ---------------------------------------------------------------------
// ALE event types (GAR-03 §6 / §3 Terminology)
// ---------------------------------------------------------------------
export enum ALEType {
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

  // HEM escalation fields
  escalation_class?: string;
  so_reference?: string;

  // soos.gar.* integrity (GAR-03 §13.7)
  // NOTE (open question, see chat / SDB-GAR-07 candidate): prev_span_hash
  // below covers only session_id/decision/kernel_id/cap_profile_hash/
  // timestamp/prev_span_hash. It does NOT cover entry_id, causal_parent_id,
  // or any §13.3 provenance field (cedar_policy_id, cap_rrs_control_id,
  // authority_source_uri, tier, conflict_detected, escalation_class,
  // so_reference). Only the Merkle layer (leafHash(), below) currently
  // covers those fields, and Layer 1's own_span_hash chain does not by
  // itself detect their tampering. Left unresolved intentionally --
  // widening the Layer 1 field set is a spec-level decision, not a bug fix.
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
// canonicalize — deterministic JSON serialization (RFC 8785 JCS subset:
// recursive key sort). Sufficient for GAREntry's field set (strings,
// booleans, null, undefined-as-omitted). A full JCS library (e.g. the
// `canonicalize` npm package) should replace this before production use,
// for RFC 8785's numeric-formatting rules -- GAREntry has no numeric
// fields today, so this subset is exact for the current schema.
// ---------------------------------------------------------------------
function canonicalize(value: unknown): string {
  if (value === undefined) return 'null'; // JSON has no undefined; normalize
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return (
    '{' +
    keys.map((k) => JSON.stringify(k) + ':' + canonicalize(obj[k])).join(',') +
    '}'
  );
}

// ---------------------------------------------------------------------
// leafHash — SHA-256 over the UTF-8 bytes of the JCS canonicalization of
// the event delta record. SDB-GAR-06 fix: previously JSON.stringify(e),
// which is not canonical across implementations (field-order dependent).
// Returns the raw digest (Buffer), not a hex string -- see merkleRoot().
// ---------------------------------------------------------------------
function leafHash(entry: GAREntry): Buffer {
  return createHash('sha256').update(canonicalize(entry), 'utf8').digest();
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
          `tier=${entry.tier ?? '-'} conflict_detected=${entry.conflict_detected ?? false}`
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

// ---------------------------------------------------------------------
// merkleRoot — SDB-GAR-06 fix. Takes raw leaf digests (Buffer[], from
// leafHash()) and combines parent nodes by concatenating RAW DIGEST
// BYTES, not hex-string text. Previously:
//
//   createHash('sha256').update(left + right).digest('hex')
//
// where left/right were hex strings -- this hashes the UTF-8 text of
// two 64-char hex strings, not the 64 raw bytes they represent. That
// mismatch was the IETF 126 interop divergence: "leaf = SHA-256(BYTES),
// not hex — found the hard way." Fixed by operating on Buffers
// throughout and hex-encoding only at the point of storage/display
// (closeSessionBlock, below).
// ---------------------------------------------------------------------
function merkleRoot(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) return createHash('sha256').update('').digest();
  let level = leaves;
  while (level.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : level[i];
      next.push(createHash('sha256').update(Buffer.concat([left, right])).digest());
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
  // SDB-GAR-08 fix: attach block_id BEFORE hashing, not after. Previously
  // the Merkle root was computed over `entries` (no block_id) while the
  // stored `events` had block_id added afterward -- the anchored events
  // never actually matched the root that claimed to cover them, so even
  // an untampered block would fail recomputation. block_id is now part
  // of the leaf content on both sides.
  const events = entries.map((e) => ({ ...e, block_id }));
  const leaves = events.map(leafHash);
  const root = merkleRoot(leaves);
  const rootHex = root.toString('hex');
  const signature = signer.sign(rootHex);

  return {
    block_id,
    session_id,
    events,
    merkle_root: rootHex,
    block_signature: {
      algorithm: 'Ed25519',
      key_id: signer.publicKeyId,
      signature,
    },
  };
}

// ---------------------------------------------------------------------
// verifySessionBlock — SDB-GAR-04 resolution. Recomputes the Merkle root
// from the block's own events (via leafHash()/merkleRoot(), the same
// canonicalization as closeSessionBlock) and compares against the
// claimed merkle_root. Does NOT verify the Ed25519 signature itself --
// that requires the signer's public key, which this Tier-1 stub does
// not distribute; signature verification is left for the Step 6 (KIA)
// integration.
// ---------------------------------------------------------------------
export function verifySessionBlock(block: SessionBlock): { valid: boolean; expectedRoot: string } {
  const recomputed = merkleRoot(block.events.map(leafHash)).toString('hex');
  return { valid: recomputed === block.merkle_root, expectedRoot: recomputed };
}

// tamperDetect — modify byte in entry N, verify fails at N (GAR-03 §14.4)
export function tamperDetect(log: GARLog, session_id: string, entryIndex: number): void {
  const entries = log.getSession(session_id);
  if (entries[entryIndex]) {
    (entries[entryIndex] as any).decision = 'TAMPERED';
  }
}
