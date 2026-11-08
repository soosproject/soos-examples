// Step 1d — demo.ts  (updated for draft-sato-soos-gar-14, 4 Nov 2026)
// Readable end-to-end walkthrough of GAR (Governance Audit Record):
// mandate-binding check (CONF-GAR-SEQ-02) -> Session-Open Record
// (CONF-GAR-SEQ-01) -> session start -> Cedar DENY -> HEM escalation -> session close ->
// Session Block (Merkle root + KIA signature) -> chain verification ->
// tamper -> chain verification fails at the tampered entry.
//
// Current against gar-core.ts (SDB-GAR-01/-03/-04/-06/-08/-09/-10 fixes
// applied) -- every causal_parent_id below references a real prior
// entry_id, so this walkthrough's happy path is unaffected by the
// SDB-GAR-03 referential-integrity check. See generate-edge-logs.ts
// GAR-EDGE-003/GAR-EDGE-011 for what a rejected append / signer failure
// actually looks like.
//
// Event shape and field values are drawn from GAR-HP-006
// (svl/corpus-b/gar/hp/GAR-HP-006.json — the CEDAR_DENY mid-session
// happy-path log), with an HEM_ESCALATION entry added per the Step 1d demo
// script so the full ALE surface (PERMIT context, DENY, ESCALATION, END)
// is visible in one run.

import { randomUUID } from 'crypto';
import {
  GARLog,
  GARProcessor,
  KIAStubSigner,
  InMemorySov,
  GarSessionOpenRejectedError,
  closeSessionBlock,
  verifySessionBlock,
  computePrevSpanHash,
  GarBlockHeadMismatchError,
  ALEType,
} from './gar-core';

function short(hash: string): string {
  return hash.slice(0, 16);
}

function line() {
  console.log('─'.repeat(70));
}

function section(title: string) {
  line();
  console.log(title);
  line();
}

async function main() {
  const log = new GARLog();
  const processor = new GARProcessor();
  const session_id = 'demo-session-' + randomUUID().slice(0, 8);
  const kernel_id = 'kernel-demo';
  const cap_profile_hash = 'caphash-demo';

  const sov = new InMemorySov();
  const mandate_id = 'mjwt-demo-1';
  const mandateBound = sov.bindMandate(mandate_id);

  // -------------------------------------------------------------
  // 0. CONF-GAR-SEQ-02 negative path: unbound mandate -> no session
  // -------------------------------------------------------------
  section('0. Session open under an UNBOUND mandate -- rejected (CONF-GAR-SEQ-02)');
  try {
    log.openSession({
      session_id: 'demo-rejected-' + randomUUID().slice(0, 8),
      actor_id: 'agent-2',
      mandate_id: 'mjwt-never-issued',
      timestamp: new Date().toISOString(),
      kernel_id,
      sov,
    });
    console.log('  ✗ unexpected: session opened without a MANDATE_BOUND entry');
  } catch (err) {
    if (!(err instanceof GarSessionOpenRejectedError)) throw err;
    console.log(`  ✓ rejected; ${err.anomaly.ale_type} recorded (anomaly_reason=${err.anomaly.anomaly_reason})`);
  }

  // -------------------------------------------------------------
  // 1. Session-Open Record (Type 6) + SESSION_START
  // -------------------------------------------------------------
  section('1. SESSION_OPEN_RECORD (Type 6) -> SESSION_START');
  const sor = log.openSession({
    session_id,
    actor_id: 'agent-2',
    mandate_id,
    timestamp: new Date().toISOString(),
    kernel_id,
    sov,
  });
  processor.emit(sor);
  const msb = sov.events.find((e) => e.event_id === sor.sov_binding_event_id)!;
  console.log(`  session_sequence_number: ${sor.session_sequence_number}`);
  console.log(`  sov_binding_event_id:    ${sor.sov_binding_event_id} (SOV ${msb.event_type})`);
  console.log(`  MANDATE_SESSION_BOUND.prior_event_id -> MANDATE_BOUND: ${msb.prior_event_id === mandateBound}`);
  console.log(`  prev_span_hash:          ${short(sor.prev_span_hash)}... (first-span sentinel)`);

  const start = log.append({
    entry_id: randomUUID(),
    ale_type: ALEType.SESSION_START,
    session_id,
    actor_id: 'agent-2',
    timestamp: new Date().toISOString(),
    causal_parent_id: sor.entry_id,
    decision: 'PERMIT',
    kernel_id,
    cap_profile_hash,
  });
  processor.emit(start);
  console.log(`  SESSION_START entry_id:  ${start.entry_id}`);
  console.log(`  own_span_hash:           ${short(start.own_span_hash)}...`);

  // -------------------------------------------------------------
  // 2. Cedar DENY logged
  // -------------------------------------------------------------
  section('2. CEDAR_DENY — cedar_policy_id / authority_source_uri visible');
  const deny = log.append({
    entry_id: randomUUID(),
    ale_type: ALEType.CEDAR_DENY,
    session_id,
    actor_id: 'agent-2',
    timestamp: new Date().toISOString(),
    causal_parent_id: start.entry_id,
    decision: 'DENY',
    kernel_id,
    cap_profile_hash,
    cedar_policy_id: 'policy-deny-demo-b',
    cedar_action: 'Action::"transfer_funds"',
    cap_rrs_control_id: 'ctrl-deny-demo-b',
    authority_source_uri: 'https://law.example/deny-demo-b',
    tier: 'Tier0',
    conflict_detected: false,
  });
  processor.emit(deny);
  console.log(`  entry_id:            ${deny.entry_id}`);
  console.log(`  cedar_policy_id:     ${deny.cedar_policy_id}`);
  console.log(`  cedar_action:        ${deny.cedar_action}`);
  console.log(`  authority_source_uri: ${deny.authority_source_uri}`);
  console.log(`  causal_parent_id:    ${deny.causal_parent_id} (-> SESSION_START)`);
  console.log(`  prev_span_hash:      ${short(deny.prev_span_hash)}...`);
  console.log(`  own_span_hash:       ${short(deny.own_span_hash)}...`);

  // -------------------------------------------------------------
  // 3. HEM escalation logged
  // -------------------------------------------------------------
  section('3. HEM_ESCALATION — class + causal_parent_id chain visible');
  const escalation = log.append({
    entry_id: randomUUID(),
    ale_type: ALEType.HEM_ESCALATION,
    session_id,
    actor_id: 'agent-2',
    timestamp: new Date().toISOString(),
    causal_parent_id: deny.entry_id,
    decision: 'ESCALATE',
    kernel_id,
    cap_profile_hash,
    escalation_class: 'POLICY_AMBIGUITY',
    so_reference: `so://mission-plan/${session_id}/step-1`,
  });
  processor.emit(escalation);
  console.log(`  entry_id:          ${escalation.entry_id}`);
  console.log(`  escalation_class:  ${escalation.escalation_class}`);
  console.log(`  so_reference:      ${escalation.so_reference}`);
  console.log(`  causal_parent_id:  ${escalation.causal_parent_id} (-> CEDAR_DENY)`);
  console.log(`  prev_span_hash:    ${short(escalation.prev_span_hash)}...`);
  console.log(`  own_span_hash:     ${short(escalation.own_span_hash)}...`);

  // -------------------------------------------------------------
  // 4. Session closes
  // -------------------------------------------------------------
  section('4. SESSION_END');
  const end = log.append({
    entry_id: randomUUID(),
    ale_type: ALEType.SESSION_END,
    session_id,
    actor_id: 'agent-2',
    timestamp: new Date().toISOString(),
    causal_parent_id: escalation.entry_id,
    decision: 'ESCALATE',
    kernel_id,
    cap_profile_hash,
  });
  processor.emit(end);
  console.log(`  entry_id:          ${end.entry_id}`);
  console.log(`  causal_parent_id:  ${end.causal_parent_id} (-> HEM_ESCALATION)`);
  console.log(`  prev_span_hash:    ${short(end.prev_span_hash)}...`);
  console.log(`  own_span_hash:     ${short(end.own_span_hash)}...`);

  // -------------------------------------------------------------
  // 5. Session Block: Merkle root over all 5 entries + KIA signature
  // -------------------------------------------------------------
  section('5. Session Block — RFC 9162 Merkle root over 5 entries + KIA stub signature');
  const entries = log.getSession(session_id);
  // KIA stub signer — replace with real KIA Governance Identity Keypair when Step 6 completes
  const signer = new KIAStubSigner();
  const block = closeSessionBlock(session_id, entries, signer, log.sessionHead(session_id));
  console.log(`  block_id:          ${block.block_id}  (stand-in for OTel trace_id)`);
  console.log(`  entries in block:  ${block.events.length}`);
  console.log(`  merkle_root:       ${short(block.merkle_root)}...`);
  console.log(`  signature.alg:     ${block.block_signature.algorithm}`);
  console.log(`  signature.key_id:  ${block.block_signature.key_id}`);
  console.log(`  signature:         ${short(block.block_signature.signature)}...`);
  const blockCheck = verifySessionBlock(block);
  console.log(`  verifySessionBlock: ${blockCheck.valid ? 'PASS' : 'FAIL'}`);

  // -------------------------------------------------------------
  // 5b. Pipeline tamper: drop the DENY in transit, recompute the chain
  // -------------------------------------------------------------
  section('5b. Pipeline tamper — DENY dropped, chain recomputed (GAR-14 CONF-GAR-BLOCK-03)');
  const forged = entries.filter((e) => e.ale_type !== ALEType.CEDAR_DENY).map((e) => ({ ...e }));
  let p = '';
  for (const e of forged) {
    e.prev_span_hash = p;
    e.own_span_hash = computePrevSpanHash({
      session_id: e.session_id, decision: e.decision, kernel_id: e.kernel_id,
      cap_profile_hash: e.cap_profile_hash, timestamp: e.timestamp, prev_span_hash: p,
    });
    p = e.own_span_hash;
  }
  console.log(`  forged block: ${forged.length} spans, chain internally consistent`);
  try {
    closeSessionBlock(session_id, forged, signer, log.sessionHead(session_id));
    console.log('  ✗ unexpected: GEC signed the forged block');
  } catch (err) {
    if (!(err instanceof GarBlockHeadMismatchError)) throw err;
    console.log(`  ✓ GEC refused to sign: emitted ${err.expected.count}, offered ${err.offered.count}`);
  }

  // -------------------------------------------------------------
  // 6. Chain verification — before tampering
  // -------------------------------------------------------------
  section('6. Chain verification: BEFORE tamper');
  const before = log.verifyChain(session_id);
  console.log(`  ${before.valid ? 'PASS' : 'FAIL'}${before.valid ? '' : ` at entry ${before.failedAt}`}`);

  // -------------------------------------------------------------
  // 7. Tamper: byte modified in entry 3 (the CEDAR_DENY entry, index 2)
  // -------------------------------------------------------------
  section('7. [Tamper: byte modified in entry 3 — CEDAR_DENY.decision]');
  (entries[2] as any).decision = 'TAMPERED';
  console.log('  entries[2].decision overwritten in place (simulating storage-layer corruption)');

  // -------------------------------------------------------------
  // 8. Chain verification — after tampering
  // -------------------------------------------------------------
  section('8. Chain verification: AFTER tamper');
  const after = log.verifyChain(session_id);
  console.log(`  ${after.valid ? 'PASS' : 'FAIL'}${after.valid ? '' : ` at entry ${after.failedAt}`}`);
  console.log();
  console.log(
    after.valid === false && after.failedAt === 2
      ? '  ✓ Correctly localized to entry index 2 (the tampered CEDAR_DENY entry).'
      : '  ✗ Unexpected result — see gar-core.ts verifyChain() / Step 1b notes.'
  );

  line();
}

main();
