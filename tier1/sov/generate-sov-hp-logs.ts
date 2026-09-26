// Step 2a — SVL Phase A: 20 happy-path SOV logs
// Output: svl/corpus-b/sov/hp/SOV-HP-XXX.json
//
// Categories (per Sample Code Plan v4):
//   001-003  SO creation (root, no parent)
//   004-006  SO with parent reference
//   007-010  SO state transition (GEC-mediated)
//   011-013  SPO creation and activation
//   014-016  Mission Plan SO with SEQUENTIAL and PARALLEL edges
//   017-018  Zone A personal data check (should reject)
//   019-020  Mission Status SO as GEC-exclusive (agent write -> reject)

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

const OUT_DIR = 'svl/corpus-b/sov/hp';
mkdirSync(OUT_DIR, { recursive: true });

function writeLog(name: string, data: unknown) {
  writeFileSync(`${OUT_DIR}/${name}.json`, JSON.stringify(data, null, 2));
  console.log(`  wrote ${name}.json`);
}

// =====================================================================
// SOV-HP-001 to 003 — SO creation (root, no parent)
// =====================================================================
console.log('Generating SOV-HP-001 to 003 (root SO creation)...');
for (let n = 1; n <= 3; n++) {
  const stream = new EventStream();
  const signer = new GECStubSigner();
  const mediator = new GECMediator(stream, signer);

  const so = new SovereignObject({
    so_type_id: 'atp/booking-object/1.0',
    human_principal_id: `human-${n}`,
    gec_id: `gec-${n}`,
    current_state: 'CONFIRMED',
    zoneA: { destination_region: 'Nagano', trip_duration_days: 3 + n },
  });
  const created = mediator.create(so, `kernel-root-${n}`);

  writeLog(`SOV-HP-${String(n).padStart(3, '0')}`, {
    scenario: 'SO creation (root, no parent)',
    so: { so_id: so.so_id, so_type_id: so.so_type_id, parent_so_id: so.parent_so_id, current_phase: so.current_phase },
    events: stream.getForSO(so.so_id),
    root_check: { parent_so_id_is_null: so.parent_so_id === null, prior_event_id_is_null: created.prior_event_id === null },
  });
}

// =====================================================================
// SOV-HP-004 to 006 — SO with parent reference
// =====================================================================
console.log('Generating SOV-HP-004 to 006 (SO with parent reference)...');
for (let n = 1; n <= 3; n++) {
  const stream = new EventStream();
  const signer = new GECStubSigner();
  const mediator = new GECMediator(stream, signer);

  const parent = new SovereignObject({
    so_type_id: 'atp/mission-object/1.0', human_principal_id: `human-${n}`,
    gec_id: `gec-${n}`, current_state: 'ACTIVE_ROOT',
  });
  mediator.create(parent, `kernel-parent-${n}`);

  const child = new SovereignObject({
    so_type_id: 'atp/booking-object/1.0', human_principal_id: `human-${n}`,
    gec_id: `gec-${n}`, current_state: 'CONFIRMED', parent_so_id: parent.so_id,
  });
  const childCreated = mediator.create(child, `kernel-child-${n}`);

  writeLog(`SOV-HP-${String(3 + n).padStart(3, '0')}`, {
    scenario: 'SO with parent reference',
    parent_so: { so_id: parent.so_id, so_type_id: parent.so_type_id },
    child_so: { so_id: child.so_id, so_type_id: child.so_type_id, parent_so_id: child.parent_so_id },
    parent_reference_check: { child_parent_so_id_matches: child.parent_so_id === parent.so_id },
    events: stream.all(),
  });
}

// =====================================================================
// SOV-HP-007 to 010 — SO state transition (GEC-mediated)
// =====================================================================
console.log('Generating SOV-HP-007 to 010 (GEC-mediated state transition)...');
for (let n = 1; n <= 4; n++) {
  const stream = new EventStream();
  const signer = new GECStubSigner();
  const mediator = new GECMediator(stream, signer);

  const so = new SovereignObject({
    so_type_id: 'atp/booking-object/1.0', human_principal_id: `human-${n}`,
    gec_id: `gec-${n}`, current_state: 'CONFIRMED',
  });
  mediator.create(so, `kernel-trans-${n}`);
  const t1 = mediator.transition(so, 'IN_JOURNEY', `kernel-trans-${n}`, true);
  const t2 = mediator.transition(so, 'COMPLETED', `kernel-trans-${n}`, true, 'OPERATIONALLY_COMPLETE');

  writeLog(`SOV-HP-${String(6 + n).padStart(3, '0')}`, {
    scenario: 'SO state transition (GEC-mediated)',
    so: { so_id: so.so_id, final_state: so.current_state, final_phase: so.current_phase },
    events: stream.getForSO(so.so_id),
    gec_mediation_check: {
      t1_causal_chain_valid: t1.prior_event_id !== null,
      t2_causal_chain_valid: t2.prior_event_id === t1.entry_id,
    },
  });
}

// =====================================================================
// SOV-HP-011 to 013 — SPO creation and activation
// =====================================================================
console.log('Generating SOV-HP-011 to 013 (SPO creation and activation)...');
for (let n = 1; n <= 3; n++) {
  const stream = new EventStream();
  const signer = new GECStubSigner();
  const mediator = new GECMediator(stream, signer);

  const spo = new StandingPlanObject({
    human_principal_id: `human-${n}`, gec_id: `gec-${n}`,
    scope_constraints: { geographic: ['JP'], agent_role: ['booking-agent'], delegation_depth: 2 },
    cedar_bundle_ref: `cedar://bundle/spo-${n}`,
    cap_rrs_catalog_ref: `caprrs://catalog/spo-${n}`,
    idp_validation_ref: `idp://validation/spo-${n}`,
  });
  mediator.create(spo, `kernel-spo-${n}`);
  const activated = spo.activate(mediator, `kernel-spo-${n}`);

  writeLog(`SOV-HP-${String(10 + n).padStart(3, '0')}`, {
    scenario: 'SPO creation and activation',
    spo: {
      so_id: spo.so_id, so_type_id: spo.so_type_id, active: spo.active,
      scope_constraints: spo.scope_constraints, cedar_bundle_ref: spo.cedar_bundle_ref,
    },
    events: stream.getForSO(spo.so_id),
    activation_check: { active_flag_true: spo.active, activation_event_type: activated.event_type },
  });
}

// =====================================================================
// SOV-HP-014 to 016 — Mission Plan SO with SEQUENTIAL and PARALLEL edges
// =====================================================================
console.log('Generating SOV-HP-014 to 016 (Mission Plan DAG)...');
for (let n = 1; n <= 3; n++) {
  const stream = new EventStream();
  const signer = new GECStubSigner();
  const mediator = new GECMediator(stream, signer);

  const mission = new MissionPlanSO({ human_principal_id: `human-${n}`, gec_id: `gec-${n}` });
  mediator.create(mission, `kernel-mission-${n}`);

  mission.addStep({ step_id: 's1', description: 'gather requirements' });
  mission.addStep({ step_id: 's2', description: 'book primary activity' });
  mission.addStep({ step_id: 's3', description: 'book alternate activity' });
  mission.addStep({ step_id: 's4', description: 'confirm itinerary' });

  mission.addEdge({ from_step_id: 's1', to_step_id: 's2', edge_type: 'SEQUENTIAL' });
  mission.addEdge({ from_step_id: 's1', to_step_id: 's3', edge_type: 'PARALLEL' });
  mission.addEdge({ from_step_id: 's2', to_step_id: 's4', edge_type: 'SEQUENTIAL' });
  mission.addEdge({ from_step_id: 's3', to_step_id: 's4', edge_type: 'SEQUENTIAL' });

  writeLog(`SOV-HP-${String(13 + n).padStart(3, '0')}`, {
    scenario: 'Mission Plan SO with SEQUENTIAL and PARALLEL edges',
    mission: { so_id: mission.so_id, steps: mission.steps, edges: mission.edges },
    events: stream.getForSO(mission.so_id),
    dag_check: {
      sequential_edge_count: mission.edges.filter((e) => e.edge_type === 'SEQUENTIAL').length,
      parallel_edge_count: mission.edges.filter((e) => e.edge_type === 'PARALLEL').length,
    },
  });
}

// =====================================================================
// SOV-HP-017 to 018 — Zone A personal data check (should reject)
// =====================================================================
console.log('Generating SOV-HP-017 to 018 (Zone A personal data rejection)...');
const personalDataCases = [
  { email: 'guest@example.com', trip_id: 'trip-1' },
  { full_name: 'Jane Doe', passport: 'XX1234567' },
];
for (let n = 1; n <= 2; n++) {
  let threw = false;
  let errorMessage = '';
  try {
    assertNoPersonalData(personalDataCases[n - 1]);
  } catch (err: any) {
    threw = true;
    errorMessage = err.message;
  }

  writeLog(`SOV-HP-${String(16 + n).padStart(3, '0')}`, {
    scenario: 'Zone A personal data check (should reject)',
    attempted_zone_a_fields: personalDataCases[n - 1],
    result: { threw, errorMessage },
    invariant: 'INV-ZA-1 — Zone A MUST NOT contain personal data',
  });
}

// =====================================================================
// SOV-HP-019 to 020 — Mission Status SO GEC-exclusive (agent write -> reject)
// =====================================================================
console.log('Generating SOV-HP-019 to 020 (Mission Status GEC-exclusive)...');
for (let n = 1; n <= 2; n++) {
  const stream = new EventStream();
  const signer = new GECStubSigner();
  const mediator = new GECMediator(stream, signer);

  const mission = new MissionPlanSO({ human_principal_id: `human-${n}`, gec_id: `gec-${n}` });
  mediator.create(mission, `kernel-status-${n}`);
  mission.addStep({ step_id: 's1', description: 'step one' });

  const status = new MissionStatusSO({
    human_principal_id: `human-${n}`, gec_id: `gec-${n}`, mission_plan_so_id: mission.so_id,
  });
  mediator.create(status, `kernel-status-${n}`);

  let agentWriteThrew = false;
  let errorMessage = '';
  try {
    status.writeStepState('s1', 'IN_PROGRESS', false);
  } catch (err: any) {
    agentWriteThrew = true;
    errorMessage = err.message;
  }
  status.writeStepState('s1', 'IN_PROGRESS', true); // GEC write succeeds

  writeLog(`SOV-HP-${String(18 + n).padStart(3, '0')}`, {
    scenario: 'Mission Status SO GEC-exclusive (agent write -> reject)',
    mission_status_so_id: status.so_id,
    agent_write_result: { threw: agentWriteThrew, errorMessage },
    gec_write_result: { step_states: status.step_states },
  });
}

console.log('\nDone. 20 SOV-HP logs written to', OUT_DIR);
