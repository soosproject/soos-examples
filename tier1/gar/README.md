# GAR — Governance Audit Record

Sample TypeScript implementation of `draft-sato-soos-gar-04` (Tier 1,
standalone, no external SOOS dependencies).

GAR is the **AUDIT leg** of the Agent Accountability Stack
(CAN / WHO / WHAT / AUDIT). It provides an append-only, hash-chained,
periodically Merkle-rooted and Ed25519-signed record of every governance
decision (`CEDAR_PERMIT`, `CEDAR_DENY`), escalation (`HEM_ESCALATION`), and
session lifecycle event (`SESSION_START`/`SESSION_END`/...) in an agent
session.

## Files

| File | Purpose |
|---|---|
| `gar-core.ts` | Core implementation — `GAREntry`, `GARLog`, `computePrevSpanHash()`, `verifyChain()`, `GARProcessor`, `SessionBlock`, `KIAStubSigner`, `closeSessionBlock()`, `tamperDetect()` |
| `demo.ts` | End-to-end walkthrough: session open → Cedar DENY → HEM escalation → session close → Session Block → chain verification pass → tamper → chain verification fail |
| `generate-hp-logs.ts` | Generates the 20 happy-path sample logs (`svl/corpus-b/gar/hp/`) |
| `generate-edge-logs.ts` | Generates the 10 adversarial/edge-case logs (`svl/corpus-b/gar/edge/`) |

## Quick start

```bash
npx tsx demo.ts
```

## 20-line usage snippet

```typescript
import { GARLog, ALEType } from './gar-core';

const log = new GARLog();
const session_id = 'my-session';

// First entry — prev_span_hash auto-set to 'GENESIS'
const start = log.append({
  entry_id: 'e1', ale_type: ALEType.SESSION_START, session_id,
  actor_id: 'agent-1', timestamp: new Date().toISOString(),
  causal_parent_id: null, decision: 'PERMIT', kernel_id: 'k1',
  cap_profile_hash: 'abc123',
});

// CEDAR_PERMIT/DENY require 3 provenance fields — append() throws if missing
log.append({
  entry_id: 'e2', ale_type: ALEType.CEDAR_PERMIT, session_id,
  actor_id: 'agent-1', timestamp: new Date().toISOString(),
  causal_parent_id: start.entry_id, decision: 'PERMIT', kernel_id: 'k1',
  cap_profile_hash: 'abc123', cedar_policy_id: 'p1',
  cap_rrs_control_id: 'c1', authority_source_uri: 'https://law.example/1',
});

// Recomputes and compares each entry's own_span_hash; localizes tampering
console.log(log.verifyChain(session_id)); // { valid: true, failedAt: null }
```

## KIA stub signer

`KIAStubSigner` generates a local Ed25519 keypair at construction time and
signs Session Block Merkle roots with it. This is a **stand-in only** — it
has no relationship to a real identity or trust anchor. Replace with the
real KIA Governance Identity Keypair when Step 6 (KIA) is implemented; see
the `// KIA stub` comment directly above the class in `gar-core.ts`.

## OTel stub

`GARProcessor.emit()` prints `soos.governance.*` and `soos.cap.*` fields to
`console.log` in place of emitting real OpenTelemetry spans. A production
implementation would use `@opentelemetry/api` to emit these as span
attributes on the actual trace, with `block_id` set to the OTel `trace_id`
at Session Block close (see the comment on `SessionBlock.block_id` and
`closeSessionBlock()` in `gar-core.ts`).

## Known gaps (see `svl/issue-log.md`)

The sample code is intentionally faithful to what GAR-03 currently
specifies, and no further. Several edge cases surfaced open questions the
draft doesn't yet resolve — logged rather than silently guessed at:

- **SDB-GAR-01** (resolved) — `prev_span_hash` for the first entry in a
  session is the sentinel string `'GENESIS'`.
- **SDB-GAR-02** — `verifyChain()` on a session with zero entries returns
  vacuous `{ valid: true }`; GAR-03 doesn't define this case.
- **SDB-GAR-03** — `append()` does not validate that `causal_parent_id`
  references an existing entry, nor that timestamps are monotonic.
- **SDB-GAR-04** — no `verifySessionBlock()` counterpart exists to detect
  a Session Block whose `merkle_root` doesn't match its claimed entries.
- **SDB-GAR-05** — `GOVERNANCE_SUSPENDED` has no enforced mandatory field
  set, unlike `CEDAR_PERMIT`/`CEDAR_DENY`.

None of these block the Step 1 Done Criteria for the sample code sprint;
they're flagged for resolution in `draft-sato-soos-gar-04`.

## What this sample code does NOT give you

This is Layer 1 / Tier 1 sample code: an in-memory array, SHA-256 hash
chain, and a single Ed25519 stub signer. It does not provide durable
storage, multi-writer concurrency control, real OTel span emission, real
KIA-issued signatures, or performance characteristics representative of a
production deployment. See the Sample Code Plan's "What Sample Code Does
Not Give You" section for the full list.
