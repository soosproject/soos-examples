# SOV — Sovereign Object

Sample TypeScript implementation of `draft-sato-soos-sov-02` (Tier 1,
standalone, no external SOOS dependencies beyond Node's built-in `crypto`).

A Sovereign Object gives every governed resource an immutable identity, a
declared finite state machine, a tamper-evident append-only Event Stream,
and a lifecycle that ends in cryptographic erasure of personal data while
preserving the audit record intact. All state transitions are
**GEC-mediated** — no agent may write Zone A directly.

## Files

| File | Purpose |
|---|---|
| `sov-core.ts` | Core implementation — `SovereignObject`, `EventStream`, `GECMediator`, `GECStubSigner`, `StandingPlanObject`, `MissionPlanSO`, `MissionStatusSO`, `uuidv7()`, `assertNoPersonalData()` |
| `demo.ts` | End-to-end walkthrough: root SO → child SO → GEC-mediated transition → agent-direct transition rejected → Zone A personal-data write rejected → SPO activation → Mission Plan DAG → cyclic edge rejected → Mission Status GEC-exclusive write |
| `generate-sov-hp-logs.ts` | Generates the 20 happy-path sample logs (`svl/corpus-b/sov/hp/`) |
| `generate-sov-edge-logs.ts` | Generates the 10 adversarial/edge-case logs (`svl/corpus-b/sov/edge/`) |

## Quick start

```bash
npx tsx demo.ts
```

## 20-line usage snippet

```typescript
import { SovereignObject, EventStream, GECMediator, GECStubSigner } from './sov-core';

const stream = new EventStream();
const mediator = new GECMediator(stream, new GECStubSigner());

const so = new SovereignObject({
  so_type_id: 'atp/booking-object/1.0',
  human_principal_id: 'human-1', gec_id: 'gec-1',
  current_state: 'CONFIRMED',
});
mediator.create(so, 'kernel-1'); // SO_CREATED — causal root, prior_event_id null

// Only the GEC may transition state — isGEC=true required, else throws
mediator.transition(so, 'IN_JOURNEY', 'kernel-1', true);

// Agent-direct transitions are rejected (SOV §GEC mediation)
try {
  mediator.transition(so, 'CANCELLED', 'kernel-1', false);
} catch (e) {
  console.log('rejected as expected');
}
```

## UUID v7

`so_id` and Event Stream `entry_id` values use a locally-implemented
`uuidv7()` (RFC 9562, time-ordered), not Node's built-in `randomUUID()`
(which only produces v4). SOV-02 requires time-ordered identity, so this
is a deliberate Type I mapping decision — see the comment above `uuidv7()`
in `sov-core.ts`.

## GEC stub signer

`GECStubSigner` generates a local Ed25519 keypair at construction time and
signs each Event Stream entry with it — same pattern as `KIAStubSigner` in
the GAR sample code. This is a **stand-in only**, with no relationship to
a real GEC identity or trust anchor. Replace when real GEC integration
lands; see the comment above the class in `sov-core.ts`.

## Zone A / Zone B

Zone A (operational fields) is checked against a personal-data denylist
recursively (`assertNoPersonalData()`) at `SovereignObject` construction
time, enforcing `INV-ZA-1`. Zone B (attachments) is represented only as a
lightweight content-hash reference index (`AttachmentRef[]`) — no actual
content storage or retrieval is implemented in this Tier 1 sample.

## Known gaps (see `svl/issue-log.md`)

- **SDB-01** — SOV-01/-02 does not name `SUSPENDED` as a `current_phase`
  value (five defined phases: `ACTIVE` → `OPERATIONALLY_COMPLETE` →
  `ADMINISTRATIVELY_CLOSED` → `ARCHIVED` → `CRYPTOGRAPHICALLY_ERASED`).
  The draft's own Cedar example uses `current_state == "HEM_PENDING"` for
  an escalation pause, suggesting pauses may belong at the state level —
  not confirmed as a general rule. `// TODO: SDB-01` marker at `SOPhase`.
- **SDB-02** — no in-memory SO registry exists, so `parent_so_id` can
  point at a `so_id` that was never created; accepted silently. Same
  shape as GAR's `SDB-GAR-03` (dangling `causal_parent_id`).
- **SDB-03** — the Zone A recursive personal-data check does not yet
  recurse into arrays (e.g. `{ contacts: [{ email: '...' }] }` would
  still slip through). Flagged, not yet fixed.
- **SDB-04** — `StandingPlanObject.scope_constraints.delegation_depth`
  accepts negative values; SOV-02 doesn't state a valid range.
- Related to SDB-01: `GECMediator.transition()` performs no runtime
  validation that `newPhase` is one of the five defined values —
  TypeScript's type safety doesn't survive contact with real
  (deserialized) data. A runtime allow-list check is needed once SDB-01
  is resolved.

None of these block the Step 2 sample-code deliverable; they're flagged
for resolution in `draft-sato-soos-sov-03`.

## Two bugs found and fixed during Step 2b (not draft ambiguities — our own code)

- `assertNoPersonalData()` originally only scanned top-level Zone A keys;
  personal data nested one level down (e.g. inside a `contact` object)
  slipped through silently. Fixed by recursing into nested plain objects.
- `MissionPlanSO.addEdge()` originally had no cycle check at all, despite
  Mission Plan sub-goals being described as "DAG-structured" throughout
  the plan and draft. Fixed with a DFS-based cycle check before
  committing any new edge.

## What this sample code does NOT give you

This is Layer 1 / Tier 1 sample code: an in-memory array, SHA-256/Ed25519
stub signing, and no persistence, multi-writer concurrency control, real
OTel span emission (`soos.so.*` / `soos.event.*`), real GEC-issued
signatures, live Cedar/CAP-RRS/MJWT policy engines (the
`POLICY_EVALUATION_ORDER` constant documents the intended evaluation order
but nothing enforces it end-to-end), or Zone B content storage/retrieval.
