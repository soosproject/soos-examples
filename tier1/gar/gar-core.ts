// GAR (Governance Audit Record) — core implementation
// draft-sato-soos-gar-04 (proposed)
// SDB-GAR-01 resolution applied — see svl/issue-log.md ISSUE-001
// SDB-GAR-06 resolution applied — see notes below (Merkle canonicalization)
// SDB-GAR-09 resolution applied — see notes below (RFC 6962 MTH construction,
//   replaces duplicate-last-node padding; adds leaf/internal domain separation)

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
  // SDB-GAR-10 fix: GAR-06 §14.3's "Signer failure at close" requires a
  // KERNEL_AUDIT_ANOMALY Audit Alert when the KIA signer can't sign
  // (FROST quorum failure), satisfying KIA-05's own CONF-KIA-19. This
  // member exists so a caller catching GarSignerFailureError (below) has
  // something to append. GAR-core does not emit this automatically --
  // see closeSessionBlock()'s doc comment for the expected caller pattern.
  KERNEL_AUDIT_ANOMALY = 'KERNEL_AUDIT_ANOMALY',
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
// SDB-GAR-09 fix: now prefixes the canonicalized bytes with 0x00 before
// hashing, per RFC 6962 §2.1's leaf-hash domain separation
// (MTH({d0}) = SHA-256(0x00 || d0)). This is what actually prevents an
// internal node's raw bytes from being replayable as leaf content -- see
// merkleRoot() below for why this matters together with the tree-shape
// change. Returns the raw digest (Buffer), not a hex string.
// ---------------------------------------------------------------------
function leafHash(entry: GAREntry): Buffer {
  const data = Buffer.from(canonicalize(entry), 'utf8');
  return createHash('sha256').update(Buffer.concat([Buffer.from([0x00]), data])).digest();
}

// ---------------------------------------------------------------------
// KIA stub signer — Ed25519 local keypair
// // KIA stub — replace with real KIA Governance Identity Keypair when Step 6 completes
// ---------------------------------------------------------------------
export class KIAStubSigner implements GarBlockSigner {
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

  // SDB-GAR-03 fix (GAR-06 §6.2 / §12.1): causal_parent_id, when present,
  // MUST reference an entry that actually exists in the log at append
  // time. Previously accepted silently (GAR-EDGE-003 confirmed a
  // nonexistent causal_parent_id passes through untouched) -- the hash
  // chain itself doesn't depend on causal_parent_id, so a dangling
  // reference was purely decorative and undetectable. GAR-06 now
  // requires this check explicitly and treats a dangling reference as
  // a KERNEL_AUDIT_ANOMALY finding, not a silent accept -- see the
  // KERNEL_AUDIT_ANOMALY ALEType member and the SDB-GAR-10 fix note
  // below for the emission pattern this mirrors. Timestamp monotonicity
  // is NOT enforced here -- GAR-06 doesn't require it, and GAR-EDGE-005
  // already confirmed identical/out-of-order timestamps are harmless to
  // chain integrity (which is append-order-keyed, not timestamp-keyed).
  append(entry: Omit<GAREntry, 'prev_span_hash' | 'own_span_hash'>): GAREntry {
    const prev = this.lastHashBySession.get(entry.session_id) ?? 'GENESIS';

    if (entry.causal_parent_id !== null && entry.causal_parent_id !== undefined) {
      const parentExists = this.entries.some((e) => e.entry_id === entry.causal_parent_id);
      if (!parentExists) {
        throw new Error(
          `GAR append rejected: causal_parent_id '${entry.causal_parent_id}' does not ` +
            `reference an existing entry_id in the log (GAR-06 §6.2, SDB-GAR-03). A dangling ` +
            `causal reference MUST be treated as a KERNEL_AUDIT_ANOMALY, not silently accepted.`
        );
      }
    }

    // Mandatory provenance enforcement on CEDAR_PERMIT / CEDAR_DENY (GAR-03 §13.3)
    // TODO: SDB-GAR-05 — GOVERNANCE_SUSPENDED has no enforced field set at all.
    // GAR-EDGE-009 confirmed a SUSPENDED entry is accepted with zero identifying
    // or escalation fields. GAR-03 is silent on what SUSPENDED requires (plausibly
    // escalation_class + so_reference, mirroring HEM_ESCALATION) — not enforcing
    // yet since the correct field set isn't normatively defined. OPEN QUESTION
    // (flagged, not resolved this pass): GAR-06's own ALE registry no longer lists
    // GOVERNANCE_SUSPENDED at all -- worth confirming with Tom whether this ALEType
    // member is stale (superseded by CAP-04's own CAP_POLICY_SUSPENDED event, which
    // already has a full required field set) before investing in field enforcement
    // for a type GAR itself may no longer own.
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
// merkleRoot — SDB-GAR-09 fix. Was: pairwise combine with duplicate-last-
// node padding for odd counts, no domain separation. That's the same
// shape as the Bitcoin Merkle malleability bug (CVE-2012-2459): an
// odd-count tree could be crafted so a duplicated-leaf variant collides
// on the same root as a differently-shaped tree, and nothing stopped an
// internal node's raw bytes from being replayable as leaf content.
//
// Now: RFC 6962 §2.1's Merkle Tree Hash (MTH) construction, verbatim.
//   MTH({})      = SHA-256()                          -- empty tree
//   MTH({d0})    = leafHash(d0)                        -- already 0x00-prefixed
//   MTH(D[n])    = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])), n > 1
//                  where k = largest power of two < n
// No duplication, ever -- an odd node at any level is carried down into
// a smaller right subtree instead of paired with a copy of itself. This
// also makes sibling-array length and direction bits fully derivable
// from (index, leaf count) alone, per Joel Hillier's ARP-03 §7 pins 1/2.
//
// Bonus: RFC 6962's empty-tree definition, SHA-256(''), is EXACTLY what
// this implementation already produced by accident before this fix --
// so the existing empty-tree behavior turns out to already match the
// IETF-precedented convention. It's the 32-zero-octet assumption in
// ARP-03's vectors that's out of step here, not GAR. See SDB-GAR-11.
//
// SDB-GAR-06's fix (raw digest bytes, not hex text, at every combine
// step) is preserved -- this only changes tree SHAPE and adds the
// domain-separation prefix, not the byte-vs-hex behavior Joel's
// typed-ref-cpb01-04 vector already confirmed. That vector's exact hash
// output DOES shift with this change, though (leaf hashes are now
// 0x00-prefixed) -- needs re-confirming with Joel, not just re-framing.
// ---------------------------------------------------------------------
function largestPowerOfTwoLessThan(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function merkleRoot(leaves: Buffer[]): Buffer {
  const n = leaves.length;
  if (n === 0) return createHash('sha256').update('').digest(); // RFC 6962 MTH({})
  if (n === 1) return leaves[0]; // already leafHash()'s 0x00-prefixed digest
  const k = largestPowerOfTwoLessThan(n);
  const left = merkleRoot(leaves.slice(0, k));
  const right = merkleRoot(leaves.slice(k, n));
  return createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x01]), left, right]))
    .digest();
}

// GarBlockSigner — narrowed interface satisfied by KIAStubSigner (below,
// still exported for demo/sample-log scripts that don't care about real
// keys) and, once available, by KiaManifestSigner / KiaFrostSigner in
// kia-signer.ts. closeSessionBlock() only needs sign()/publicKeyId; it does
// not need to know how the signer got its key material.
export interface GarBlockSigner {
  sign(merkleRootHex: string): string;
  readonly publicKeyId: string;
}

// ---------------------------------------------------------------------
// GarSignerFailureError — SDB-GAR-10 fix. Wraps whatever a GarBlockSigner
// throws (e.g. a real KIA signer's KiaError('KIA_QUORUM_FAILURE', ...))
// so callers can distinguish "the signer itself failed" from other
// closeSessionBlock() failures (a malformed entry, etc.) without needing
// to know the signer implementation's own error shape.
//
// GAR-06 §14.3's "Signer failure at close" requirement: the GEC MUST NOT
// close a session with an unsigned or partially-signed Session Block on
// signer failure. This function does NOT swallow or retry the failure --
// it lets it propagate as GarSignerFailureError. The CALLER is expected
// to catch it, append a KERNEL_AUDIT_ANOMALY entry (satisfying KIA-05's
// CONF-KIA-19), and retry closeSessionBlock() once signer quorum is
// restored. Sample usage:
//
//   try {
//     const block = closeSessionBlock(session_id, entries, signer);
//   } catch (err) {
//     if (err instanceof GarSignerFailureError) {
//       log.append({ ale_type: ALEType.KERNEL_AUDIT_ANOMALY, ... });
//       // retry once quorum is restored -- session remains open meanwhile
//     } else {
//       throw err;
//     }
//   }
//
// This orchestration lives in the caller, not here, because only the
// caller knows the retry/backoff policy and how "quorum restored" is
// detected for its deployment -- that's deployment-specific, not
// something GAR-core's Tier-1 sample code should hardcode.
// ---------------------------------------------------------------------
export class GarSignerFailureError extends Error {
  public readonly cause: unknown;
  constructor(message: string, cause: unknown) {
    super(message);
    this.name = 'GarSignerFailureError';
    this.cause = cause;
  }
}

export function closeSessionBlock(
  session_id: string,
  entries: GAREntry[],
  signer: GarBlockSigner
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

  let signature: string;
  try {
    signature = signer.sign(rootHex);
  } catch (err) {
    // SDB-GAR-10 fix: previously this call had no try/catch, so a real
    // signer's failure (e.g. FROST quorum failure) propagated as
    // whatever error shape the signer happened to throw, with no
    // GAR-level marker a caller could reliably catch. Wrapped here so
    // the CONF-GAR-BLOCK-01 "no unsigned Session Block" invariant is
    // never silently violated -- see GarSignerFailureError's doc comment
    // above for the expected caller-side retry pattern.
    throw new GarSignerFailureError(
      `GAR Session Block signing failed for session '${session_id}' (block_id ` +
        `'${block_id}') -- session close MUST NOT proceed with an unsigned or ` +
        `partially-signed block (GAR-06 CONF-GAR-BLOCK-01). Caller MUST emit ` +
        `KERNEL_AUDIT_ANOMALY and retry once signer quorum is restored.`,
      err
    );
  }

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
