// SOOS Step 11 — MAD demo. draft-sato-soos-mad-03.
import { randomUUID } from 'crypto';
import { GARLog, KIAStubSigner } from '../deps/gar/gar-core.js';
import { RevocationRegistry } from '../deps/kia/event-log.js';
import { MadGec } from './gec.js';
import { DelegationTree, RevocationEngine } from './revocation.js';
import { deriveSubAgentXpid, verifySubAgentXpid } from './xpid.js';
import { MadDenyError, type AuthorizedParentScope, type SpawnRequest } from './types.js';

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

const gar = new GARLog();
const signer = new KIAStubSigner();
const revocationRegistry = new RevocationRegistry();
const gec = new MadGec(gar, signer, revocationRegistry);
const tree = new DelegationTree();
const revocation = new RevocationEngine(gar, signer, revocationRegistry, tree, gec);

// ---------------------------------------------------------------------
// Scenario setup: a hub orchestrator session with mandate authority to
// spawn up to 2 levels of sub-agents.
// ---------------------------------------------------------------------

const orchestratorSessionId = 'session-orchestrator-001';
const orchestratorMandateId = `mjwt-${randomUUID()}`;
const orchestratorXpid = randomUUID();

tree.register({
  session_id: orchestratorSessionId,
  mandate_id: orchestratorMandateId,
  parent_session_id: null,
  responsive: true,
});

const orchestratorScope: AuthorizedParentScope = {
  session_id: orchestratorSessionId,
  cedar_action_set: ['atp:booking:confirm', 'atp:booking:cancel', 'atp:booking:suspend'],
  tool_access: ['flight_search', 'hotel_search', 'payment_processor'],
  max_spawn_depth: 2,
  hub_only: true,
  revoked: false,
};

// ---------------------------------------------------------------------
section('1. SACR Issuance — 7-step flow (§4.3)');
// ---------------------------------------------------------------------

const spawnRequest: SpawnRequest = {
  parent_assignment_id: `assignment-${randomUUID()}`,
  parent_session_id: orchestratorSessionId,
  parent_mandate_id: orchestratorMandateId,
  parent_xpid: orchestratorXpid,
  scope_constraints: {
    cedar_action_subset: ['atp:booking:confirm'], // strict subset of orchestrator's set
    so_type_scope: ['atp/booking-object/1.0'],
    resource_envelope: { max_compute_seconds: 30 },
    tool_subset: ['flight_search'], // strict subset of orchestrator's tools
  },
  can_decompose: true,
  max_spawn_depth: 1, // must be <= orchestrator's (2) - 1 = 1
  hub_only: true,
  replan_authority: 'BOUNDED',
};

// Steps 1-6 (GEC-mediated):
const sacr = gec.spawnSubAgent(spawnRequest, orchestratorScope);
console.log('SACR issued:', { sacr_id: sacr.sacr_id, ephemeral_kia_ref: sacr.ephemeral_kia_ref });

// Step 7 (spawning agent's own follow-up, per §4.3): issue the Assignment
// using ephemeral_kia_ref as assigned_agent_id. Assignment schema itself
// is DR-PLAN-01's (not in this session's dependency set) — represented
// here only as the linkage MAD-03 requires.
const assignment = {
  assignment_id: sacr.parent_assignment_id,
  assigned_agent_id: sacr.ephemeral_kia_ref, // MUST equal SACR's ephemeral_kia_ref (§10)
};
console.log('Assignment issued (Step 7):', assignment);

const specialistSessionId = sacr.ephemeral_kia_ref;
tree.register({
  session_id: specialistSessionId,
  mandate_id: `mjwt-${randomUUID()}`, // ephemeral mandate scope, not a persistent Party Registry entry
  parent_session_id: orchestratorSessionId,
  responsive: true,
});

// ---------------------------------------------------------------------
section('2. XPID Derivation (§6.1) — UUID5(KIA_XPID_NAMESPACE, parent_xpid + ":" + sacr_id)');
// ---------------------------------------------------------------------

const subAgentXpid = deriveSubAgentXpid(orchestratorXpid, sacr.sacr_id);
console.log('Derived sub-agent XPID:', subAgentXpid);

const verification = verifySubAgentXpid(subAgentXpid, orchestratorXpid, sacr.sacr_id);
console.log('Cross-cluster verification (§6.2) — recompute-and-compare, never trust-on-receipt:', verification);

// ---------------------------------------------------------------------
section('3. Hub-Only Enforcement (§5) — DirectSubAgentComm Cedar DENY');
// ---------------------------------------------------------------------

// Spawn a sibling specialist to demonstrate the DENY.
const siblingRequest: SpawnRequest = {
  ...spawnRequest,
  parent_assignment_id: `assignment-${randomUUID()}`,
};
const siblingSacr = gec.spawnSubAgent(siblingRequest, orchestratorScope);
tree.register({
  session_id: siblingSacr.ephemeral_kia_ref,
  mandate_id: `mjwt-${randomUUID()}`,
  parent_session_id: orchestratorSessionId,
  responsive: true,
});

try {
  gec.checkDirectSubAgentComm(specialistSessionId, siblingSacr.ephemeral_kia_ref, 'STATUS_UPDATE');
} catch (err) {
  if (err instanceof MadDenyError) {
    console.log(`DENY (expected): ${err.code} — ${err.message}`);
  } else {
    throw err;
  }
}

// ---------------------------------------------------------------------
section('4. max_spawn_depth decrement enforcement (§4.2, CONF-MAD-19)');
// ---------------------------------------------------------------------

// The specialist (max_spawn_depth: 1) attempts to spawn a grandchild
// requesting max_spawn_depth: 1 — must be rejected; only 0 is allowed.
const specialistScope: AuthorizedParentScope = {
  session_id: specialistSessionId,
  cedar_action_set: spawnRequest.scope_constraints.cedar_action_subset,
  tool_access: spawnRequest.scope_constraints.tool_subset,
  max_spawn_depth: sacr.max_spawn_depth, // 1
  hub_only: sacr.hub_only,
  revoked: false,
};

try {
  gec.spawnSubAgent(
    {
      parent_assignment_id: `assignment-${randomUUID()}`,
      parent_session_id: specialistSessionId,
      parent_mandate_id: sacr.parent_mandate_id,
      parent_xpid: subAgentXpid,
      scope_constraints: spawnRequest.scope_constraints,
      can_decompose: false,
      max_spawn_depth: 1, // INVALID: must be <= (1 - 1) = 0
      hub_only: true,
    },
    specialistScope,
  );
} catch (err) {
  if (err instanceof MadDenyError) {
    console.log(`DENY (expected): ${err.code} — ${err.message}`);
  } else {
    throw err;
  }
}

// Valid grandchild spawn at depth 0 (leaf):
const grandchildSacr = gec.spawnSubAgent(
  {
    parent_assignment_id: `assignment-${randomUUID()}`,
    parent_session_id: specialistSessionId,
    parent_mandate_id: sacr.parent_mandate_id,
    parent_xpid: subAgentXpid,
    scope_constraints: spawnRequest.scope_constraints,
    can_decompose: false,
    max_spawn_depth: 0,
    hub_only: true,
  },
  specialistScope,
);
console.log('Valid leaf grandchild SACR issued:', { sacr_id: grandchildSacr.sacr_id, max_spawn_depth: grandchildSacr.max_spawn_depth });
tree.register({
  session_id: grandchildSacr.ephemeral_kia_ref,
  mandate_id: `mjwt-${randomUUID()}`,
  parent_session_id: specialistSessionId,
  responsive: true,
});

// ---------------------------------------------------------------------
section('5. R-1 revocation — CAP Tier 0-A violation (completion_state: PARTIAL always)');
// ---------------------------------------------------------------------

const r1Result = revocation.trigger('R-1', specialistSessionId);
console.log('R-1 result:', r1Result);
console.log(
  'Note: SDB-MAD-01 — the plan\'s Step 11 block asked for a "MANDATE_HOLD propagation" SVL scenario, ' +
    'but no such term exists anywhere in draft-sato-soos-mad-03. Built against the real draft instead: ' +
    'R-1\'s actual "hold" state is CONTINUATION_AWAITING_PRINCIPAL (§7.1), emitted above as part of the ' +
    'R-1 trigger and held until a human principal issues a continuation mandate.',
);

// ---------------------------------------------------------------------
section('6. R-3 revocation — Non-Response (completion_state: UNKNOWN always)');
// ---------------------------------------------------------------------

tree.register({
  session_id: 'session-nonresponsive-001',
  mandate_id: `mjwt-${randomUUID()}`,
  parent_session_id: orchestratorSessionId,
  responsive: false,
});
const r3Result = revocation.trigger('R-3', 'session-nonresponsive-001');
console.log('R-3 result:', r3Result);

// ---------------------------------------------------------------------
section('Summary');
// ---------------------------------------------------------------------
console.log(`GAR entries recorded: ${gar.all().length}`);
console.log(`GAR chain valid for orchestrator session: ${gar.verifyChain(orchestratorSessionId).valid}`);
