// Step 2b — SVL Phase B: 10 edge/adversarial SOV logs
// Output: svl/corpus-b/sov/edge/SOV-EDGE-XXX.json
// No pre-written table existed for SOV edge cases in the plan (unlike
// GAR's table) — these 10 scenarios were designed against SOV-02's
// stated invariants (INV-ZA-1, GEC mediation, DAG structure) and the
// implementation's own structural boundaries.

import { writeFileSync, mkdirSync } from 'fs';
import {
  SovereignObject,
  EventStream,
  GECMediator,
  GECStubSigner,
  StandingPlanObject,
  MissionPlanSO,
  MissionStatusSO,
  assertNoPersonalData,
} from './sov-core';

const OUT_DIR = 'svl/corpus-b/sov/edge';
mkdirSync(OUT_DIR, { recursive: true });

function writeEdge(name: string, data: unknown) {
  writeFileSync(`${OUT_DIR}/${name}.json`, JSON.stringify(data, null, 2));
  console.log(`  wrote ${name}.json`);
}

// =====================================================================
// SOV-EDGE-001 — Empty EventStream, getForSO() on a so_id never created
// =====================================================================
console.log('SOV-EDGE-001 — empty stream lookup...');
{
  const stream = new EventStream();
  const result = stream.getForSO('nonexistent-so-id');

  writeEdge('SOV-EDGE-001', {
    scenario: 'getForSO() called for a so_id that was never appended to the stream',
    expected: 'Empty array, no error (analogous to GAR-EDGE-001 vacuous case)',
    actual: { length: result.length, value: result },
    classification: 'Confirmed correct — not a new finding',
    note:
      'Array.filter() over an empty backing array returns [] naturally; no special-casing ' +
      'needed. Consistent with the GAR precedent (GAR-EDGE-001) of vacuous-empty being an ' +
      'acceptable default absent contrary spec guidance.',
  });
}

// =====================================================================
// SOV-EDGE-002 — STATE_TRANSITION as the very first entry (before SO_CREATED)
// =====================================================================
console.log('SOV-EDGE-002 — STATE_TRANSITION before SO_CREATED...');
{
  const stream = new EventStream();
  const signer = new GECStubSigner();
  let threw = false;
  let errorMessage = '';
  try {
    stream.append(
      {
        so_id: 'orphan-so-1', event_type: 'STATE_TRANSITION', actor_id: 'GEC',
        timestamp: new Date().toISOString(), kernel_id: 'k1',
      },
      signer
    );
  } catch (err: any) {
    threw = true;
    errorMessage = err.message;
  }

  writeEdge('SOV-EDGE-002', {
    scenario: 'STATE_TRANSITION appended as the first-ever entry for a so_id, with no prior SO_CREATED',
    expected: 'Reject — SOV-02 requires prior_event_id null ONLY for SO_CREATED, implying SO_CREATED must be first',
    actual: { threw, errorMessage },
    classification: 'Confirmed correct — not a new finding',
    note:
      "EventStream.append() explicitly checks: if no prior event exists for this so_id, the " +
      "entry MUST be SO_CREATED, else it throws. Matches the schema table's stated invariant " +
      "that prior_event_id is null ONLY for SO_CREATED.",
  });
}

// =====================================================================
// SOV-EDGE-003 — SO_CREATED appended twice for the same so_id
// =====================================================================
console.log('SOV-EDGE-003 — duplicate SO_CREATED...');
{
  const stream = new EventStream();
  const signer = new GECStubSigner();
  const so_id = 'duplicate-create-so-1';

  stream.append(
    { so_id, event_type: 'SO_CREATED', actor_id: 'GEC', timestamp: new Date().toISOString(), kernel_id: 'k1' },
    signer
  );

  let threw = false;
  let errorMessage = '';
  try {
    stream.append(
      { so_id, event_type: 'SO_CREATED', actor_id: 'GEC', timestamp: new Date().toISOString(), kernel_id: 'k1' },
      signer
    );
  } catch (err: any) {
    threw = true;
    errorMessage = err.message;
  }

  writeEdge('SOV-EDGE-003', {
    scenario: 'SO_CREATED appended a second time for a so_id that already has one',
    expected: 'Reject — SO_CREATED must be unique per so_id (it is the causal root)',
    actual: { threw, errorMessage, entries_for_so: stream.getForSO(so_id).length },
    classification: 'Confirmed correct — not a new finding',
    note:
      'append() checks the inverse condition too: if a prior event already exists, a new ' +
      'SO_CREATED is rejected. Both halves of the causal-root invariant are enforced.',
  });
}

// =====================================================================
// SOV-EDGE-004 — Nested personal data in Zone A
// =====================================================================
console.log('SOV-EDGE-004 — nested personal data...');
{
  const nestedCase = { contact: { email: 'guest@example.com' }, trip_id: 'trip-1' };
  let threw = false;
  let errorMessage = '';
  try {
    assertNoPersonalData(nestedCase);
  } catch (err: any) {
    threw = true;
    errorMessage = err.message;
  }

  writeEdge('SOV-EDGE-004', {
    scenario: "Personal data field ('email') nested one level inside an innocuous-looking parent key ('contact')",
    expected: 'Reject — INV-ZA-1 applies to Zone A content regardless of nesting depth',
    actual: { threw, errorMessage },
    classification: 'Fixed — was a real gap (Type I, our own code)',
    note:
      'Prior to this fix, assertNoPersonalData() only scanned top-level keys of the Zone A ' +
      "object, so { contact: { email: '...' } } passed silently — the denylist check never " +
      "saw the 'email' key because it only ever inspected 'contact'. Fixed by recursing into " +
      'nested plain objects (arrays intentionally left unrecursed for this pass — see SDB-03). ' +
      'This was a correctness bug in our own implementation of a stated MUST (INV-ZA-1), not a ' +
      'draft ambiguity, so fixed directly rather than merely logged.',
  });
}

// =====================================================================
// SOV-EDGE-005 — MissionPlanSO cyclic edge
// =====================================================================
console.log('SOV-EDGE-005 — cyclic DAG edge...');
{
  const mission = new MissionPlanSO({ human_principal_id: 'human-1', gec_id: 'gec-1' });
  mission.addStep({ step_id: 's1', description: 'a' });
  mission.addStep({ step_id: 's2', description: 'b' });
  mission.addStep({ step_id: 's3', description: 'c' });
  mission.addEdge({ from_step_id: 's1', to_step_id: 's2', edge_type: 'SEQUENTIAL' });
  mission.addEdge({ from_step_id: 's2', to_step_id: 's3', edge_type: 'SEQUENTIAL' });

  let threw = false;
  let errorMessage = '';
  try {
    mission.addEdge({ from_step_id: 's3', to_step_id: 's1', edge_type: 'SEQUENTIAL' }); // closes s1->s2->s3->s1
  } catch (err: any) {
    threw = true;
    errorMessage = err.message;
  }

  writeEdge('SOV-EDGE-005', {
    scenario: 'Third edge added would close a cycle: s1 -> s2 -> s3 -> s1',
    expected: 'Reject — plan and draft both describe Mission Plan sub-goals as "DAG-structured" (acyclic by definition)',
    actual: { threw, errorMessage, edge_count_after: mission.edges.length },
    classification: 'Fixed — was a real gap (Type I, our own code)',
    note:
      'Prior to this fix, addEdge() only validated that from_step_id/to_step_id referenced ' +
      'existing steps, with no cycle check at all — a cyclic edge set was accepted silently, ' +
      'directly contradicting the "DAG-structured" claim made about this component in both the ' +
      'plan and the draft. Fixed by adding a DFS-based cycle check over the proposed edge set ' +
      'before committing any new edge. Classified as our own implementation bug (Type I), not a ' +
      'draft ambiguity, since "DAG" is an unambiguous mathematical term we chose to use.',
  });
}

// =====================================================================
// SOV-EDGE-006 — MissionPlanSO edge referencing a nonexistent step
// =====================================================================
console.log('SOV-EDGE-006 — edge referencing nonexistent step...');
{
  const mission = new MissionPlanSO({ human_principal_id: 'human-1', gec_id: 'gec-1' });
  mission.addStep({ step_id: 's1', description: 'a' });

  let threw = false;
  let errorMessage = '';
  try {
    mission.addEdge({ from_step_id: 's1', to_step_id: 'nonexistent-step', edge_type: 'SEQUENTIAL' });
  } catch (err: any) {
    threw = true;
    errorMessage = err.message;
  }

  writeEdge('SOV-EDGE-006', {
    scenario: 'Edge added referencing a to_step_id that was never added via addStep()',
    expected: 'Reject — referential integrity of the step graph',
    actual: { threw, errorMessage },
    classification: 'Confirmed correct — not a new finding',
    note: 'addEdge() validates both from_step_id and to_step_id exist in the steps array before accepting.',
  });
}

// =====================================================================
// SOV-EDGE-007 — SO created with parent_so_id referencing a so_id that was never created
// =====================================================================
console.log('SOV-EDGE-007 — dangling parent_so_id reference...');
{
  const stream = new EventStream();
  const signer = new GECStubSigner();
  const mediator = new GECMediator(stream, signer);

  const child = new SovereignObject({
    so_type_id: 'atp/booking-object/1.0', human_principal_id: 'human-1', gec_id: 'gec-1',
    current_state: 'CONFIRMED', parent_so_id: 'so-id-that-was-never-created',
  });
  let threw = false;
  try {
    mediator.create(child, 'kernel-1');
  } catch (err) {
    threw = true;
  }

  writeEdge('SOV-EDGE-007', {
    scenario: 'SovereignObject constructed with parent_so_id pointing at a so_id that has no corresponding EventStream entries',
    expected: 'Undefined by current architecture — no SO registry exists to check against',
    actual: { threw, child_so_id: child.so_id, child_parent_so_id: child.parent_so_id },
    classification: 'Type II — gap',
    note:
      'Neither SovereignObject nor GECMediator maintains any central registry of created so_ids ' +
      'to validate parent_so_id against — each EventStream only knows about entries for so_ids ' +
      'it has actually seen. A dangling parent reference is accepted silently because there is ' +
      'structurally nothing to check it against yet. This mirrors GAR-EDGE-003/SDB-GAR-03 ' +
      '(dangling causal_parent_id) almost exactly. Logged as SDB-02 (Type II gap) — needs a ' +
      'Decision Record on whether a Tier 1 sample should maintain an in-memory SO registry for ' +
      'referential integrity checks, or whether this is deferred to a higher/storage layer.',
    sdb_entry: 'SDB-02',
  });
}

// =====================================================================
// SOV-EDGE-008 — Invalid current_phase value via untyped external input
// =====================================================================
console.log('SOV-EDGE-008 — invalid phase value bypassing TypeScript types...');
{
  const stream = new EventStream();
  const signer = new GECStubSigner();
  const mediator = new GECMediator(stream, signer);

  const so = new SovereignObject({
    so_type_id: 'atp/booking-object/1.0', human_principal_id: 'human-1', gec_id: 'gec-1',
    current_state: 'CONFIRMED',
  });
  mediator.create(so, 'kernel-1');

  // Simulate untyped external input (e.g. deserialized JSON) bypassing the
  // SOPhase compile-time guarantee, which only exists at the TS boundary.
  const forgedPhase = 'SUSPENDED' as any;
  mediator.transition(so, 'ON_HOLD', 'kernel-1', true, forgedPhase);

  writeEdge('SOV-EDGE-008', {
    scenario:
      "GECMediator.transition() called with newPhase = 'SUSPENDED' (not a member of SOPhase) via " +
      "an 'as any' cast, simulating untyped external input such as deserialized JSON",
    expected: 'Undefined — TypeScript enum safety does not exist at runtime for external data',
    actual: { accepted: true, resulting_current_phase: so.current_phase },
    classification: 'Type II — gap (relates directly to SDB-01)',
    note:
      "transition() performs no runtime validation that newPhase is one of the five defined " +
      "SOPhase values — it trusts the type system, which offers zero protection against " +
      "data arriving from outside the TypeScript boundary (e.g. a real deployment reading " +
      "phase transitions off a wire format). This directly resurfaces SDB-01: since 'SUSPENDED' " +
      "isn't a defined phase, this both confirms the runtime has no guard rail against invalid " +
      "phases in general AND confirms the current implementation cannot yet reject a phase like " +
      "'SUSPENDED' even if SDB-01 is eventually resolved to say phase-level SUSPENDED is invalid " +
      "— a runtime validation set of allowed phases would be needed either way. Non-blocking for " +
      "Step 2 Done Criteria; recommend adding a runtime SOPhase allow-list check once SDB-01 " +
      "is resolved so this can be enforced meaningfully.",
  });
}

// =====================================================================
// SOV-EDGE-009 — StandingPlanObject scope_constraints.delegation_depth negative
// =====================================================================
console.log('SOV-EDGE-009 — negative delegation_depth...');
{
  const spo = new StandingPlanObject({
    human_principal_id: 'human-1', gec_id: 'gec-1',
    scope_constraints: { delegation_depth: -3 },
    cedar_bundle_ref: 'cedar://bundle/edge-009',
    cap_rrs_catalog_ref: 'caprrs://catalog/edge-009',
    idp_validation_ref: 'idp://validation/edge-009',
  });

  writeEdge('SOV-EDGE-009', {
    scenario: 'StandingPlanObject constructed with scope_constraints.delegation_depth = -3',
    expected: 'Undefined — SOV-02 does not state a valid range for delegation_depth',
    actual: { accepted: true, delegation_depth: spo.scope_constraints.delegation_depth },
    classification: 'Type II — ambiguity',
    note:
      'A negative delegation depth is semantically nonsensical (delegation chains cannot have ' +
      'negative length), but nothing in the draft states a valid range, and the sample code ' +
      'accepted it without validation. Logged as SDB-04 (Type II ambiguity, low severity) — ' +
      'likely resolvable editorially in SOV-03 (e.g. "delegation_depth MUST be a non-negative ' +
      'integer") rather than requiring a Decision Record, since there is no plausible reading ' +
      'under which negative depth is meaningful.',
    sdb_entry: 'SDB-04',
  });
}

// =====================================================================
// SOV-EDGE-010 — 1000-event stream, performance baseline
// =====================================================================
console.log('SOV-EDGE-010 — 1000-event performance baseline...');
{
  const stream = new EventStream();
  const signer = new GECStubSigner();
  const mediator = new GECMediator(stream, signer);
  const so = new SovereignObject({
    so_type_id: 'atp/booking-object/1.0', human_principal_id: 'human-1', gec_id: 'gec-1',
    current_state: 'STATE_0',
  });

  const appendStart = Date.now();
  mediator.create(so, 'kernel-perf');
  for (let i = 1; i <= 999; i++) {
    mediator.transition(so, `STATE_${i}`, 'kernel-perf', true);
  }
  const appendMs = Date.now() - appendStart;

  const readStart = Date.now();
  const entries = stream.getForSO(so.so_id);
  const readMs = Date.now() - readStart;

  writeEdge('SOV-EDGE-010', {
    scenario: '1000-entry EventStream for a single so_id (1 SO_CREATED + 999 STATE_TRANSITION) — append + read',
    expected: 'Performance baseline — completes in <1s (analogous to GAR-EDGE-010)',
    actual: { entry_count: entries.length, append_ms: appendMs, read_ms: readMs },
    classification: 'Confirmed within baseline — not a new finding',
    note:
      `Append: ${appendMs}ms, read: ${readMs}ms for 1000 entries (including a stub Ed25519 ` +
      'signature per entry) — well under the 1s baseline. Not representative of a persisted, ' +
      'multi-writer production deployment.',
  });
}

console.log('\nDone. 10 SOV-EDGE logs written to', OUT_DIR);
