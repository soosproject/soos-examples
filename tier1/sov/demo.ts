// Step 2c — demo.ts
// Readable end-to-end walkthrough of SOV (Sovereign Object):
// root SO -> child SO (parent reference) -> GEC-mediated transition ->
// agent-direct transition rejected -> Zone A personal-data write rejected ->
// SPO creation + activation -> Mission Plan DAG (SEQUENTIAL/PARALLEL) ->
// cyclic edge rejected -> Mission Status SO (GEC-exclusive write).

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

function line() {
  console.log('─'.repeat(70));
}
function section(title: string) {
  line();
  console.log(title);
  line();
}

async function main() {
  const stream = new EventStream();
  const signer = new GECStubSigner();
  const mediator = new GECMediator(stream, signer);

  // -------------------------------------------------------------
  // 1. Root SO creation
  // -------------------------------------------------------------
  section('1. Root SO creation (no parent)');
  const root = new SovereignObject({
    so_type_id: 'atp/mission-object/1.0',
    human_principal_id: 'human-tom',
    gec_id: 'gec-demo',
    current_state: 'ACTIVE_ROOT',
    zoneA: { destination_region: 'Nagano', trip_duration_days: 4 },
  });
  const rootCreated = mediator.create(root, 'kernel-demo');
  console.log(`  so_id:            ${root.so_id}`);
  console.log(`  so_type_id:       ${root.so_type_id}`);
  console.log(`  parent_so_id:     ${root.parent_so_id} (root — no parent)`);
  console.log(`  current_phase:    ${root.current_phase}`);
  console.log(`  event prior_event_id: ${rootCreated.prior_event_id} (null — causal root)`);

  // -------------------------------------------------------------
  // 2. Child SO with parent reference
  // -------------------------------------------------------------
  section('2. Child SO (parent reference)');
  const child = new SovereignObject({
    so_type_id: 'atp/booking-object/1.0',
    human_principal_id: 'human-tom',
    gec_id: 'gec-demo',
    current_state: 'CONFIRMED',
    parent_so_id: root.so_id,
  });
  mediator.create(child, 'kernel-demo');
  console.log(`  so_id:            ${child.so_id}`);
  console.log(`  parent_so_id:     ${child.parent_so_id} (-> root SO above)`);

  // -------------------------------------------------------------
  // 3. GEC-mediated state transition
  // -------------------------------------------------------------
  section('3. GEC-mediated state transition on child');
  const transition = mediator.transition(child, 'IN_JOURNEY', 'kernel-demo', true);
  console.log(`  from_state -> to_state: ${(transition.payload as any).from_state} -> ${(transition.payload as any).to_state}`);
  console.log(`  causal_parent_id:       ${transition.prior_event_id}`);

  // -------------------------------------------------------------
  // 4. Agent-direct transition rejected
  // -------------------------------------------------------------
  section('4. Agent-direct transition attempt (should reject)');
  try {
    mediator.transition(child, 'CANCELLED', 'kernel-demo', false);
    console.log('  ✗ UNEXPECTED: agent-direct transition was accepted');
  } catch (err: any) {
    console.log(`  ✓ Rejected: ${err.message}`);
  }

  // -------------------------------------------------------------
  // 5. Zone A personal-data write rejected
  // -------------------------------------------------------------
  section('5. Zone A personal-data write attempt (should reject)');
  try {
    assertNoPersonalData({ contact: { email: 'guest@example.com' } });
    console.log('  ✗ UNEXPECTED: personal data was accepted');
  } catch (err: any) {
    console.log(`  ✓ Rejected: ${err.message}`);
  }

  // -------------------------------------------------------------
  // 6. SPO creation and activation
  // -------------------------------------------------------------
  section('6. Standing Plan Object — creation + activation');
  const spo = new StandingPlanObject({
    human_principal_id: 'human-tom',
    gec_id: 'gec-demo',
    scope_constraints: { geographic: ['JP'], agent_role: ['booking-agent'], delegation_depth: 2 },
    cedar_bundle_ref: 'cedar://bundle/demo-spo',
    cap_rrs_catalog_ref: 'caprrs://catalog/demo-spo',
    idp_validation_ref: 'idp://validation/demo-spo',
  });
  mediator.create(spo, 'kernel-demo');
  spo.activate(mediator, 'kernel-demo');
  console.log(`  so_id:        ${spo.so_id}`);
  console.log(`  active:       ${spo.active}`);
  console.log(`  cedar_bundle_ref: ${spo.cedar_bundle_ref}`);

  // -------------------------------------------------------------
  // 7. Mission Plan SO — DAG with SEQUENTIAL and PARALLEL edges
  // -------------------------------------------------------------
  section('7. Mission Plan SO — DAG with SEQUENTIAL and PARALLEL edges');
  const mission = new MissionPlanSO({ human_principal_id: 'human-tom', gec_id: 'gec-demo' });
  mediator.create(mission, 'kernel-demo');
  mission.addStep({ step_id: 's1', description: 'gather requirements' });
  mission.addStep({ step_id: 's2', description: 'book primary activity' });
  mission.addStep({ step_id: 's3', description: 'book alternate activity' });
  mission.addStep({ step_id: 's4', description: 'confirm itinerary' });
  mission.addEdge({ from_step_id: 's1', to_step_id: 's2', edge_type: 'SEQUENTIAL' });
  mission.addEdge({ from_step_id: 's1', to_step_id: 's3', edge_type: 'PARALLEL' });
  mission.addEdge({ from_step_id: 's2', to_step_id: 's4', edge_type: 'SEQUENTIAL' });
  mission.addEdge({ from_step_id: 's3', to_step_id: 's4', edge_type: 'SEQUENTIAL' });
  console.log(`  steps: ${mission.steps.map((s) => s.step_id).join(', ')}`);
  for (const e of mission.edges) {
    console.log(`  edge: ${e.from_step_id} --[${e.edge_type}]--> ${e.to_step_id}`);
  }

  // -------------------------------------------------------------
  // 8. Cyclic edge rejected
  // -------------------------------------------------------------
  section('8. Cyclic edge attempt (should reject — Mission Plan is a DAG)');
  try {
    mission.addEdge({ from_step_id: 's4', to_step_id: 's1', edge_type: 'SEQUENTIAL' }); // would close a cycle
    console.log('  ✗ UNEXPECTED: cyclic edge was accepted');
  } catch (err: any) {
    console.log(`  ✓ Rejected: ${err.message}`);
  }

  // -------------------------------------------------------------
  // 9. Mission Status SO — GEC-exclusive write
  // -------------------------------------------------------------
  section('9. Mission Status SO — GEC-exclusive write');
  const status = new MissionStatusSO({
    human_principal_id: 'human-tom', gec_id: 'gec-demo', mission_plan_so_id: mission.so_id,
  });
  mediator.create(status, 'kernel-demo');

  try {
    status.writeStepState('s1', 'IN_PROGRESS', false); // agent attempt
    console.log('  ✗ UNEXPECTED: agent-authored mission status write was accepted');
  } catch (err: any) {
    console.log(`  ✓ Agent write rejected: ${err.message}`);
  }
  status.writeStepState('s1', 'IN_PROGRESS', true); // GEC write
  console.log(`  ✓ GEC write accepted: ${JSON.stringify(status.step_states)}`);

  line();
  console.log(`Total events in stream: ${stream.all().length}`);
  line();
}

main();
