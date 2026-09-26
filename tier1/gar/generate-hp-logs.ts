// Step 1a — SVL Phase A: 20 happy-path GAR logs
// Rebuilt against corrected gar-core.ts (own_span_hash fix, full GARProcessor emit)
// Output: svl/corpus-b/gar/hp/GAR-HP-XXX.json

import { writeFileSync, mkdirSync } from 'fs';
import { randomUUID } from 'crypto';
import {
  GARLog,
  GARProcessor,
  KIAStubSigner,
  closeSessionBlock,
  ALEType,
  GAREntry,
} from './gar-core';

const OUT_DIR = 'svl/corpus-b/gar/hp';
mkdirSync(OUT_DIR, { recursive: true });

function now(offsetSec = 0): string {
  return new Date(Date.now() + offsetSec * 1000).toISOString();
}

function writeLog(name: string, data: unknown) {
  writeFileSync(`${OUT_DIR}/${name}.json`, JSON.stringify(data, null, 2));
  console.log(`  wrote ${name}.json  -> valid=${(data as any).chain_verification?.valid}`);
}

const processor = new GARProcessor();

// -----------------------------------------------------------------
// GAR-HP-001 to 005 — SESSION_START -> 3 events -> SESSION_END
// Baseline fields, clean prev_span_hash chain
// -----------------------------------------------------------------
console.log('Generating GAR-HP-001 to 005 (baseline session lifecycle)...');
for (let n = 1; n <= 5; n++) {
  const log = new GARLog();
  const session_id = `hp-baseline-${n}-${randomUUID().slice(0, 8)}`;
  const kernel_id = `kernel-${n}`;
  const cap_profile_hash = `caphash-${n}`;
  let parent: string | null = null;

  const start = log.append({
    entry_id: randomUUID(), ale_type: ALEType.SESSION_START, session_id,
    actor_id: 'agent-1', timestamp: now(0), causal_parent_id: parent,
    decision: 'PERMIT', kernel_id, cap_profile_hash,
  });
  processor.emit(start);
  parent = start.entry_id;

  for (let i = 0; i < 3; i++) {
    const e = log.append({
      entry_id: randomUUID(), ale_type: ALEType.CEDAR_PERMIT, session_id,
      actor_id: 'agent-1', timestamp: now(i + 1), causal_parent_id: parent,
      decision: 'PERMIT', kernel_id, cap_profile_hash,
      cedar_policy_id: `policy-${n}-${i}`, cap_rrs_control_id: `ctrl-${n}-${i}`,
      authority_source_uri: `https://law.example/art-${n}-${i}`, tier: 'Tier1', conflict_detected: false,
    });
    processor.emit(e);
    parent = e.entry_id;
  }

  const end = log.append({
    entry_id: randomUUID(), ale_type: ALEType.SESSION_END, session_id,
    actor_id: 'agent-1', timestamp: now(4), causal_parent_id: parent,
    decision: 'PERMIT', kernel_id, cap_profile_hash,
  });
  processor.emit(end);

  writeLog(`GAR-HP-${String(n).padStart(3, '0')}`, {
    session_id,
    entries: log.getSession(session_id),
    chain_verification: log.verifyChain(session_id),
  });
}

// -----------------------------------------------------------------
// GAR-HP-006 to 010 — CEDAR_DENY mid-session
// Exercises all three mandatory provenance fields
// -----------------------------------------------------------------
console.log('Generating GAR-HP-006 to 010 (CEDAR_DENY mid-session)...');
for (let n = 1; n <= 5; n++) {
  const log = new GARLog();
  const session_id = `hp-deny-${n}-${randomUUID().slice(0, 8)}`;
  const kernel_id = `kernel-deny-${n}`;
  const cap_profile_hash = `caphash-deny-${n}`;
  let parent: string | null = null;

  const start = log.append({
    entry_id: randomUUID(), ale_type: ALEType.SESSION_START, session_id,
    actor_id: 'agent-2', timestamp: now(0), causal_parent_id: parent,
    decision: 'PERMIT', kernel_id, cap_profile_hash,
  });
  processor.emit(start);
  parent = start.entry_id;

  const permit = log.append({
    entry_id: randomUUID(), ale_type: ALEType.CEDAR_PERMIT, session_id,
    actor_id: 'agent-2', timestamp: now(1), causal_parent_id: parent,
    decision: 'PERMIT', kernel_id, cap_profile_hash,
    cedar_policy_id: `policy-deny-${n}-a`, cap_rrs_control_id: `ctrl-deny-${n}-a`,
    authority_source_uri: `https://law.example/deny-${n}-a`, tier: 'Tier1', conflict_detected: false,
  });
  processor.emit(permit);
  parent = permit.entry_id;

  const deny = log.append({
    entry_id: randomUUID(), ale_type: ALEType.CEDAR_DENY, session_id,
    actor_id: 'agent-2', timestamp: now(2), causal_parent_id: parent,
    decision: 'DENY', kernel_id, cap_profile_hash,
    cedar_policy_id: `policy-deny-${n}-b`, cap_rrs_control_id: `ctrl-deny-${n}-b`,
    authority_source_uri: `https://law.example/deny-${n}-b`, tier: 'Tier0', conflict_detected: n === 3,
  });
  processor.emit(deny);
  parent = deny.entry_id;

  const end = log.append({
    entry_id: randomUUID(), ale_type: ALEType.SESSION_END, session_id,
    actor_id: 'agent-2', timestamp: now(3), causal_parent_id: parent,
    decision: 'DENY', kernel_id, cap_profile_hash,
  });
  processor.emit(end);

  writeLog(`GAR-HP-${String(5 + n).padStart(3, '0')}`, {
    session_id,
    entries: log.getSession(session_id),
    chain_verification: log.verifyChain(session_id),
  });
}

// -----------------------------------------------------------------
// GAR-HP-011 to 015 — HEM escalation event
// escalation_class, SO reference, causal_parent_id
// -----------------------------------------------------------------
console.log('Generating GAR-HP-011 to 015 (HEM escalation)...');
for (let n = 1; n <= 5; n++) {
  const log = new GARLog();
  const session_id = `hp-escalation-${n}-${randomUUID().slice(0, 8)}`;
  const kernel_id = `kernel-esc-${n}`;
  const cap_profile_hash = `caphash-esc-${n}`;
  let parent: string | null = null;

  const start = log.append({
    entry_id: randomUUID(), ale_type: ALEType.SESSION_START, session_id,
    actor_id: 'agent-3', timestamp: now(0), causal_parent_id: parent,
    decision: 'PERMIT', kernel_id, cap_profile_hash,
  });
  processor.emit(start);
  parent = start.entry_id;

  const permit = log.append({
    entry_id: randomUUID(), ale_type: ALEType.CEDAR_PERMIT, session_id,
    actor_id: 'agent-3', timestamp: now(1), causal_parent_id: parent,
    decision: 'PERMIT', kernel_id, cap_profile_hash,
    cedar_policy_id: `policy-esc-${n}`, cap_rrs_control_id: `ctrl-esc-${n}`,
    authority_source_uri: `https://law.example/esc-${n}`, tier: 'Tier1', conflict_detected: false,
  });
  processor.emit(permit);
  parent = permit.entry_id;

  const escalation = log.append({
    entry_id: randomUUID(), ale_type: ALEType.HEM_ESCALATION, session_id,
    actor_id: 'agent-3', timestamp: now(2), causal_parent_id: parent,
    decision: 'ESCALATE', kernel_id, cap_profile_hash,
    escalation_class: n % 2 === 0 ? 'HUMAN_REVIEW_REQUIRED' : 'POLICY_AMBIGUITY',
    so_reference: `so://mission-plan/${session_id}/step-${n}`,
  });
  processor.emit(escalation);
  parent = escalation.entry_id;

  const end = log.append({
    entry_id: randomUUID(), ale_type: ALEType.SESSION_END, session_id,
    actor_id: 'agent-3', timestamp: now(3), causal_parent_id: parent,
    decision: 'ESCALATE', kernel_id, cap_profile_hash,
  });
  processor.emit(end);

  writeLog(`GAR-HP-${String(10 + n).padStart(3, '0')}`, {
    session_id,
    entries: log.getSession(session_id),
    chain_verification: log.verifyChain(session_id),
  });
}

// -----------------------------------------------------------------
// GAR-HP-016 to 018 — Multi-actor session
// Two actors, interleaved, chain integrity (single shared session_id / chain)
// -----------------------------------------------------------------
console.log('Generating GAR-HP-016 to 018 (multi-actor interleaved)...');
for (let n = 1; n <= 3; n++) {
  const log = new GARLog();
  const session_id = `hp-multiactor-${n}-${randomUUID().slice(0, 8)}`;
  const kernel_id = `kernel-multi-${n}`;
  const cap_profile_hash = `caphash-multi-${n}`;
  let parent: string | null = null;

  const start = log.append({
    entry_id: randomUUID(), ale_type: ALEType.SESSION_START, session_id,
    actor_id: 'agent-A', timestamp: now(0), causal_parent_id: parent,
    decision: 'PERMIT', kernel_id, cap_profile_hash,
  });
  processor.emit(start);
  parent = start.entry_id;

  const actors = ['agent-A', 'agent-B', 'agent-A', 'agent-B'];
  for (let i = 0; i < actors.length; i++) {
    const e = log.append({
      entry_id: randomUUID(), ale_type: ALEType.CEDAR_PERMIT, session_id,
      actor_id: actors[i], timestamp: now(i + 1), causal_parent_id: parent,
      decision: 'PERMIT', kernel_id, cap_profile_hash,
      cedar_policy_id: `policy-multi-${n}-${i}`, cap_rrs_control_id: `ctrl-multi-${n}-${i}`,
      authority_source_uri: `https://law.example/multi-${n}-${i}`, tier: 'Tier1', conflict_detected: false,
    });
    processor.emit(e);
    parent = e.entry_id;
  }

  const end = log.append({
    entry_id: randomUUID(), ale_type: ALEType.SESSION_END, session_id,
    actor_id: 'agent-A', timestamp: now(5), causal_parent_id: parent,
    decision: 'PERMIT', kernel_id, cap_profile_hash,
  });
  processor.emit(end);

  writeLog(`GAR-HP-${String(15 + n).padStart(3, '0')}`, {
    session_id,
    entries: log.getSession(session_id),
    chain_verification: log.verifyChain(session_id),
  });
}

// -----------------------------------------------------------------
// GAR-HP-019 to 020 — Session Block close
// Merkle root, KIA stub signature, block_id = OTel trace_id
// -----------------------------------------------------------------
console.log('Generating GAR-HP-019 to 020 (Session Block close)...');
for (let n = 1; n <= 2; n++) {
  const log = new GARLog();
  const session_id = `hp-blockclose-${n}-${randomUUID().slice(0, 8)}`;
  const kernel_id = `kernel-block-${n}`;
  const cap_profile_hash = `caphash-block-${n}`;
  let parent: string | null = null;

  const start = log.append({
    entry_id: randomUUID(), ale_type: ALEType.SESSION_START, session_id,
    actor_id: 'agent-4', timestamp: now(0), causal_parent_id: parent,
    decision: 'PERMIT', kernel_id, cap_profile_hash,
  });
  processor.emit(start);
  parent = start.entry_id;

  const permit = log.append({
    entry_id: randomUUID(), ale_type: ALEType.CEDAR_PERMIT, session_id,
    actor_id: 'agent-4', timestamp: now(1), causal_parent_id: parent,
    decision: 'PERMIT', kernel_id, cap_profile_hash,
    cedar_policy_id: `policy-block-${n}`, cap_rrs_control_id: `ctrl-block-${n}`,
    authority_source_uri: `https://law.example/block-${n}`, tier: 'Tier1', conflict_detected: false,
  });
  processor.emit(permit);
  parent = permit.entry_id;

  const end = log.append({
    entry_id: randomUUID(), ale_type: ALEType.SESSION_END, session_id,
    actor_id: 'agent-4', timestamp: now(2), causal_parent_id: parent,
    decision: 'PERMIT', kernel_id, cap_profile_hash,
  });
  processor.emit(end);

  const entries = log.getSession(session_id);
  const signer = new KIAStubSigner();
  const block = closeSessionBlock(session_id, entries, signer);

  writeLog(`GAR-HP-${String(18 + n).padStart(3, '0')}`, {
    session_id,
    entries,
    chain_verification: log.verifyChain(session_id),
    session_block: block,
  });
}

console.log('\nDone. 20 GAR-HP logs written to', OUT_DIR);
