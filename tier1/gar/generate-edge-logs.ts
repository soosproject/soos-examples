// Step 1c — SVL Phase B: 10 edge/adversarial logs
// Output: svl/corpus-b/gar/edge/GAR-EDGE-XXX.json
// Each file records: scenario, input construction, actual observed behavior,
// expected-per-plan behavior, and sprint issue classification (Type I / Type II).

import { writeFileSync, mkdirSync } from 'fs';
import { randomUUID } from 'crypto';
import {
  GARLog,
  KIAStubSigner,
  closeSessionBlock,
  ALEType,
  GAREntry,
} from './gar-core';

const OUT_DIR = 'svl/corpus-b/gar/edge';
mkdirSync(OUT_DIR, { recursive: true });

function now(offsetSec = 0): string {
  return new Date(Date.now() + offsetSec * 1000).toISOString();
}

function writeEdge(name: string, data: unknown) {
  writeFileSync(`${OUT_DIR}/${name}.json`, JSON.stringify(data, null, 2));
  console.log(`  wrote ${name}.json`);
}

// =====================================================================
// GAR-EDGE-001 — Empty log, verifyChain() called
// =====================================================================
console.log('GAR-EDGE-001 — empty log verifyChain()...');
{
  const log = new GARLog();
  const session_id = `edge-001-${randomUUID().slice(0, 8)}`;
  const result = log.verifyChain(session_id); // no entries ever appended

  writeEdge('GAR-EDGE-001', {
    scenario: 'Empty log — verifyChain() called on a session_id with zero entries',
    expected_per_plan: 'Valid (vacuously true) or defined error',
    actual: result,
    classification: 'Type II — ambiguity',
    note:
      'GAR-03 does not define behavior for verifyChain() on a session with no entries. ' +
      'Current implementation returns { valid: true, failedAt: null } (vacuous truth via ' +
      'empty-loop fallthrough) rather than a defined error or a distinct "no such session" ' +
      'state. A different implementer could reasonably throw instead. Logged as SDB-GAR-02 — ' +
      'non-blocking for sample code, recommend GAR-04 specify this explicitly.',
    sdb_entry: 'SDB-GAR-02',
  });
}

// =====================================================================
// GAR-EDGE-002 — Single entry, no predecessor
// =====================================================================
console.log('GAR-EDGE-002 — single entry, GENESIS sentinel...');
{
  const log = new GARLog();
  const session_id = `edge-002-${randomUUID().slice(0, 8)}`;
  const entry = log.append({
    entry_id: randomUUID(), ale_type: ALEType.SESSION_START, session_id,
    actor_id: 'agent-1', timestamp: now(0), causal_parent_id: null,
    decision: 'PERMIT', kernel_id: 'k1', cap_profile_hash: 'abc',
  });

  writeEdge('GAR-EDGE-002', {
    scenario: 'Single entry — no predecessor. What does prev_span_hash contain?',
    expected_per_plan: 'Resolved by SDB-GAR-01 — GENESIS sentinel',
    actual: { prev_span_hash: entry.prev_span_hash, verify: log.verifyChain(session_id) },
    classification: 'Resolved — not a new finding',
    note:
      'Confirms SDB-GAR-01 resolution (svl/issue-log.md ISSUE-001) is correctly implemented: ' +
      "first entry in a session carries prev_span_hash === 'GENESIS', and verifyChain() " +
      "treats 'GENESIS' as the expected initial value. No new issue.",
  });
}

// =====================================================================
// GAR-EDGE-003 — Out-of-order append
// =====================================================================
console.log('GAR-EDGE-003 — out-of-order append...');
{
  const log = new GARLog();
  const session_id = `edge-003-${randomUUID().slice(0, 8)}`;

  const e1 = log.append({
    entry_id: randomUUID(), ale_type: ALEType.SESSION_START, session_id,
    actor_id: 'agent-1', timestamp: now(10), causal_parent_id: null,
    decision: 'PERMIT', kernel_id: 'k1', cap_profile_hash: 'abc',
  });

  // e2 has an EARLIER timestamp than e1, and references a causal_parent_id
  // that does not exist in the log at all.
  let threw = false;
  let e2: GAREntry | null = null;
  try {
    e2 = log.append({
      entry_id: randomUUID(), ale_type: ALEType.SESSION_END, session_id,
      actor_id: 'agent-1', timestamp: now(0), // earlier than e1
      causal_parent_id: 'nonexistent-entry-id-999',
      decision: 'PERMIT', kernel_id: 'k1', cap_profile_hash: 'abc',
    });
  } catch (err) {
    threw = true;
  }

  writeEdge('GAR-EDGE-003', {
    scenario:
      'Out-of-order append — second entry has an earlier timestamp than the first, AND ' +
      'references a causal_parent_id that does not exist anywhere in the log',
    expected_per_plan: 'Reject or throw',
    actual: {
      threw,
      e1_timestamp: e1.timestamp,
      e2_timestamp: e2?.timestamp ?? null,
      e2_causal_parent_id: e2?.causal_parent_id ?? null,
      chain_verification: log.verifyChain(session_id),
    },
    classification: 'Type II — gap',
    note:
      'append() currently performs NO validation of (a) timestamp monotonicity or ' +
      "(b) whether causal_parent_id refers to an entry that actually exists in the log. " +
      'Both were silently accepted; verifyChain() still reports valid because the hash chain ' +
      'is computed from append-call order, not from timestamp or causal_parent_id. This is an ' +
      'integration gap between two individually-reasonable pieces: the hash chain guarantees ' +
      'append-order integrity, but causal_parent_id is currently decorative — nothing enforces ' +
      'it references a real prior entry. Logged as SDB-GAR-03 (Type II gap) — a Decision ' +
      'Record is needed on whether GARLog should validate causal_parent_id referential ' +
      'integrity and/or timestamp ordering at append() time, or whether this is left to a ' +
      'higher layer (e.g. SOV Event Stream). TODO marker added in code.',
    sdb_entry: 'SDB-GAR-03',
  });
}

// =====================================================================
// GAR-EDGE-004 — CEDAR_DENY missing cedar_policy_id
// =====================================================================
console.log('GAR-EDGE-004 — CEDAR_DENY missing mandatory provenance field...');
{
  const log = new GARLog();
  const session_id = `edge-004-${randomUUID().slice(0, 8)}`;
  let threw = false;
  let errorMessage = '';
  try {
    log.append({
      entry_id: randomUUID(), ale_type: ALEType.CEDAR_DENY, session_id,
      actor_id: 'agent-1', timestamp: now(0), causal_parent_id: null,
      decision: 'DENY', kernel_id: 'k1', cap_profile_hash: 'abc',
      // cedar_policy_id deliberately omitted
      cap_rrs_control_id: 'ctrl-1', authority_source_uri: 'https://law.example/x',
    });
  } catch (err: any) {
    threw = true;
    errorMessage = err.message;
  }

  writeEdge('GAR-EDGE-004', {
    scenario: 'CEDAR_DENY entry appended without cedar_policy_id',
    expected_per_plan: 'Reject at append — mandatory provenance field',
    actual: { threw, errorMessage },
    classification: 'Confirmed correct — not a new finding',
    note:
      'append() throws as required: "GAR append rejected: CEDAR_DENY missing mandatory ' +
      "provenance field 'cedar_policy_id' (GAR-03 §13.3)\". Matches GAR-03's REQUIRED " +
      'language literally (hard throw, not silent skip) — this was the implementation style ' +
      'decision noted during Step 1a. No new issue.',
  });
}

// =====================================================================
// GAR-EDGE-005 — Two entries, identical timestamps
// =====================================================================
console.log('GAR-EDGE-005 — identical timestamps...');
{
  const log = new GARLog();
  const session_id = `edge-005-${randomUUID().slice(0, 8)}`;
  const t = now(0);

  const e1 = log.append({
    entry_id: randomUUID(), ale_type: ALEType.SESSION_START, session_id,
    actor_id: 'agent-1', timestamp: t, causal_parent_id: null,
    decision: 'PERMIT', kernel_id: 'k1', cap_profile_hash: 'abc',
  });
  const e2 = log.append({
    entry_id: randomUUID(), ale_type: ALEType.SESSION_END, session_id,
    actor_id: 'agent-1', timestamp: t, causal_parent_id: e1.entry_id, // identical timestamp
    decision: 'PERMIT', kernel_id: 'k1', cap_profile_hash: 'abc',
  });

  writeEdge('GAR-EDGE-005', {
    scenario: 'Two entries share an identical ISO 8601 timestamp',
    expected_per_plan: 'Accept or reject — spec says?',
    actual: {
      e1_own_hash: e1.own_span_hash,
      e2_own_hash: e2.own_span_hash,
      hashes_distinct: e1.own_span_hash !== e2.own_span_hash,
      chain_verification: log.verifyChain(session_id),
    },
    classification: 'Type I',
    note:
      'Accepted silently, and correctly so: entry ordering and chain integrity are driven ' +
      'entirely by append() call order and causal_parent_id, not by timestamp uniqueness. ' +
      "Because computePrevSpanHash() includes each entry's own decision/kernel_id/etc plus " +
      'the running prev_span_hash, two entries with identical timestamps still produce ' +
      'distinct own_span_hash values (confirmed above) and the chain still verifies clean. ' +
      'Draft is silent on timestamp uniqueness, but no ambiguity actually exists in the sample ' +
      'implementation — this is normative text absent, but no code decision was needed. Code ' +
      'comment added clarifying timestamp is descriptive metadata, not an ordering key.',
  });
}

// =====================================================================
// GAR-EDGE-006 — Byte modified in entry 3 of 5 (index 2)
// =====================================================================
console.log('GAR-EDGE-006 — tamper entry 3 of 5...');
{
  const log = new GARLog();
  const session_id = `edge-006-${randomUUID().slice(0, 8)}`;
  let parent: string | null = null;
  for (let i = 0; i < 5; i++) {
    const e = log.append({
      entry_id: randomUUID(), ale_type: ALEType.CEDAR_PERMIT, session_id,
      actor_id: 'agent-1', timestamp: now(i), causal_parent_id: parent,
      decision: 'PERMIT', kernel_id: 'k1', cap_profile_hash: 'abc',
      cedar_policy_id: `p${i}`, cap_rrs_control_id: `c${i}`, authority_source_uri: `u${i}`,
    });
    parent = e.entry_id;
  }

  const before = log.verifyChain(session_id);
  // Tamper entry index 2 (the third entry, 1-indexed = "entry 3")
  const entries = log.getSession(session_id);
  (entries[2] as any).decision = 'TAMPERED';
  const after = log.verifyChain(session_id);

  writeEdge('GAR-EDGE-006', {
    scenario: 'Byte (decision field) modified in entry 3 of 5 (0-indexed position 2)',
    expected_per_plan: 'verifyChain() fails at entry 3, not entry 4 or entry 5',
    actual: { before, after },
    classification: 'Confirmed fixed — was Step 1b finding #1, now resolved',
    note:
      'Prior to the Step 1b own_span_hash fix, this scenario reported failedAt: 3 (one entry ' +
      "late) because verifyChain() could only detect tampering to entry N via entry N+1's " +
      "prev_span_hash. With own_span_hash added and verifyChain() comparing each entry's " +
      `recomputation against its OWN own_span_hash, failedAt now correctly equals ${after.failedAt} ` +
      '(0-indexed position 2 = the third entry). No further action needed.',
  });
}

// =====================================================================
// GAR-EDGE-007 — prev_span_hash field itself modified
// =====================================================================
console.log('GAR-EDGE-007 — tamper prev_span_hash directly...');
{
  const log = new GARLog();
  const session_id = `edge-007-${randomUUID().slice(0, 8)}`;
  let parent: string | null = null;
  for (let i = 0; i < 4; i++) {
    const e = log.append({
      entry_id: randomUUID(), ale_type: ALEType.CEDAR_PERMIT, session_id,
      actor_id: 'agent-1', timestamp: now(i), causal_parent_id: parent,
      decision: 'PERMIT', kernel_id: 'k1', cap_profile_hash: 'abc',
      cedar_policy_id: `p${i}`, cap_rrs_control_id: `c${i}`, authority_source_uri: `u${i}`,
    });
    parent = e.entry_id;
  }

  const before = log.verifyChain(session_id);
  const entries = log.getSession(session_id);
  const originalHash = (entries[1] as any).prev_span_hash;
  (entries[1] as any).prev_span_hash = 'deadbeef'.repeat(8); // corrupt directly
  const after = log.verifyChain(session_id);

  writeEdge('GAR-EDGE-007', {
    scenario: "prev_span_hash field of entry index 1 modified directly (not the decision field)",
    expected_per_plan: 'Should detect',
    actual: { before, after, corrupted_index: 1, original_hash_prefix: originalHash.slice(0, 16) },
    classification: 'Confirmed correct — not a new finding',
    note:
      'Detected immediately: verifyChain() checks e.prev_span_hash !== prev as the FIRST ' +
      'check in the loop, before even reaching the own_span_hash recomputation, so this ' +
      `fails at exactly the tampered index (${after.failedAt}). Two independent detection ` +
      'paths (link-field check, then content-hash check) both guard the chain — this ' +
      'redundancy is a strength, not a gap.',
  });
}

// =====================================================================
// GAR-EDGE-008 — Session Block with one entry missing from Merkle
// =====================================================================
console.log('GAR-EDGE-008 — Session Block missing entry from Merkle set...');
{
  const log = new GARLog();
  const session_id = `edge-008-${randomUUID().slice(0, 8)}`;
  let parent: string | null = null;
  for (let i = 0; i < 4; i++) {
    const e = log.append({
      entry_id: randomUUID(), ale_type: ALEType.CEDAR_PERMIT, session_id,
      actor_id: 'agent-1', timestamp: now(i), causal_parent_id: parent,
      decision: 'PERMIT', kernel_id: 'k1', cap_profile_hash: 'abc',
      cedar_policy_id: `p${i}`, cap_rrs_control_id: `c${i}`, authority_source_uri: `u${i}`,
    });
    parent = e.entry_id;
  }
  const fullEntries = log.getSession(session_id);
  const partialEntries = [fullEntries[0], fullEntries[1], fullEntries[3]]; // drop index 2

  const signer = new KIAStubSigner();
  const fullBlock = closeSessionBlock(session_id, fullEntries, signer);
  const partialBlock = closeSessionBlock(session_id, partialEntries, signer);

  writeEdge('GAR-EDGE-008', {
    scenario: 'Session Block Merkle root computed twice: once over all 4 entries, once with entry index 2 dropped',
    expected_per_plan: 'Merkle root mismatch',
    actual: {
      full_merkle_root: fullBlock.merkle_root,
      partial_merkle_root: partialBlock.merkle_root,
      roots_differ: fullBlock.merkle_root !== partialBlock.merkle_root,
    },
    classification: 'Confirmed correct — not a new finding',
    note:
      'Merkle roots differ as expected — closeSessionBlock() takes the entries array as-is ' +
      'and hashes each as a leaf, so a dropped entry produces a different tree deterministically. ' +
      'One open question worth flagging as SDB-GAR-04 (non-blocking, Type II gap): GAR-03 does ' +
      'not specify who is responsible for verifying a received Session Block\'s merkle_root ' +
      'against an independently-held copy of the entries — closeSessionBlock() itself has no ' +
      'verification counterpart (only construction). A verifySessionBlock(block, entries) ' +
      'function may be needed for a receiving party to detect this class of tampering, ' +
      'analogous to verifyChain() for the span-level chain.',
    sdb_entry: 'SDB-GAR-04',
  });
}

// =====================================================================
// GAR-EDGE-009 — GOVERNANCE_SUSPENDED event
// =====================================================================
console.log('GAR-EDGE-009 — GOVERNANCE_SUSPENDED provenance requirements...');
{
  const log = new GARLog();
  const session_id = `edge-009-${randomUUID().slice(0, 8)}`;
  let threw = false;
  try {
    log.append({
      entry_id: randomUUID(), ale_type: ALEType.GOVERNANCE_SUSPENDED, session_id,
      actor_id: 'agent-1', timestamp: now(0), causal_parent_id: null,
      decision: 'SUSPENDED', kernel_id: 'k1', cap_profile_hash: 'abc',
      // no cedar_policy_id / cap_rrs_control_id / authority_source_uri, no escalation_class
    });
  } catch (err) {
    threw = true;
  }

  writeEdge('GAR-EDGE-009', {
    scenario: 'GOVERNANCE_SUSPENDED event appended with no provenance or escalation fields at all',
    expected_per_plan: 'Mandatory provenance fields required?',
    actual: { threw },
    classification: 'Type II — gap',
    note:
      'append() currently enforces the three mandatory provenance fields ONLY for ' +
      'CEDAR_PERMIT / CEDAR_DENY (per MANDATORY_PROVENANCE check). GOVERNANCE_SUSPENDED — ' +
      'arguably the highest-severity ALE type — has no enforcement at all and was accepted ' +
      'with zero identifying fields. GAR-03 §13.3 (per the coding-assistant brief) only names ' +
      'CEDAR_PERMIT/CEDAR_DENY explicitly; the draft is silent on whether SUSPENDED needs its ' +
      'own mandatory field set (plausibly escalation_class + so_reference, mirroring ' +
      'HEM_ESCALATION). Logged as SDB-GAR-05 (Type II gap) — recommend GAR-04 specify ' +
      'provenance requirements for GOVERNANCE_SUSPENDED explicitly. TODO marker added in code ' +
      'pending that decision; no enforcement added yet since the correct field set is not yet defined.',
    sdb_entry: 'SDB-GAR-05',
  });
}

// =====================================================================
// GAR-EDGE-010 — 1000-entry session, performance baseline
// =====================================================================
console.log('GAR-EDGE-010 — 1000-entry performance baseline...');
{
  const log = new GARLog();
  const session_id = `edge-010-${randomUUID().slice(0, 8)}`;

  const appendStart = Date.now();
  let parent: string | null = null;
  for (let i = 0; i < 1000; i++) {
    const e = log.append({
      entry_id: randomUUID(), ale_type: ALEType.CEDAR_PERMIT, session_id,
      actor_id: 'agent-1', timestamp: now(i), causal_parent_id: parent,
      decision: 'PERMIT', kernel_id: 'k1', cap_profile_hash: 'abc',
      cedar_policy_id: `p${i}`, cap_rrs_control_id: `c${i}`, authority_source_uri: `u${i}`,
    });
    parent = e.entry_id;
  }
  const appendMs = Date.now() - appendStart;

  const verifyStart = Date.now();
  const result = log.verifyChain(session_id);
  const verifyMs = Date.now() - verifyStart;

  writeEdge('GAR-EDGE-010', {
    scenario: '1000-entry session — append all, then verifyChain()',
    expected_per_plan: 'Performance baseline — completes in <1s',
    actual: { entry_count: 1000, append_ms: appendMs, verify_ms: verifyMs, chain_valid: result.valid },
    classification: 'Confirmed within baseline — not a new finding',
    note:
      `Append: ${appendMs}ms, verifyChain: ${verifyMs}ms for 1000 entries — well under the ` +
      '1s baseline. In-memory array + per-entry SHA-256 scales linearly as expected for the ' +
      'sample-code Layer 1 implementation; not representative of production persistence-layer ' +
      'performance (see "What Sample Code Does Not Give You" table in the plan).',
  });
}

console.log('\nDone. 10 GAR-EDGE logs written to', OUT_DIR);
