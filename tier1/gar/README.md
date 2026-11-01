# GAR — Governance Audit Record

Sample TypeScript implementation of `draft-sato-soos-gar-13` —
Session Audit Record path (`gar-core.ts`) and Authority Lifecycle Events
(`authority-lifecycle.ts`) — Tier 1, standalone, no external SOOS
dependencies. Pairs with `draft-sato-soos-sov-05` (MANDATE_SESSION_BOUND).

## GAR-13 alignment (1 November 2026)

Two copies of `gar-core.ts` had been in circulation (D21). The copy on
`main` was an older base with only the Type 6 Session-Open Record and
`cedar_action` added; it had lost the GAR-06 repairs (canonical leaf
encoding, RFC 6962/9162 Merkle tree, signer-failure handling,
`causal_parent_id` check, `verifySessionBlock()`), and
`generate-edge-logs.ts` and this README did not compile/match against it.
This pass merges the two:

- `gar-core.ts` = the GAR-06-repaired copy **plus** `SESSION_OPEN_RECORD`
  (`GARLog.openSession()`, CONF-GAR-SEQ-01/-02) and
  `soos.cap.cedar_action`. `openSession()` now follows GAR-13 §4.6
  exactly: resolve the mandate's `MANDATE_BOUND` entry, commit a SOV-05
  `MANDATE_SESSION_BOUND` entry, carry its `event_id` as
  `sov_binding_event_id`; on failure append `KERNEL_AUDIT_ANOMALY` and
  throw `GarSessionOpenRejectedError`. `InMemorySov` is a sample stub for
  the SOV side.
- `authority-lifecycle.ts` uses the GAR-13 §12.1 shared vocabulary with
  KIA-09/MJWT-08: `mandate_jti` family, `revoked_jti`,
  `revocation_type` (`DIRECT`/`CASCADE`) + `cascade_root_jti`,
  `authority_type`, `revocation_event_ref`, `revocation_source` without
  `CASCADE` (adds `PRINCIPAL`, `FEDERATED_ISSUER`), `R-1`..`R-9`, and the
  hold events `ALE_MANDATE_HELD` / `ALE_MANDATE_HOLD_RELEASED`.
- `demo.ts` opens the session through `openSession()` (including a
  rejected open); `demo-revocation.ts` adds hold → conversion and
  vocabulary-conformance scenarios.

GAR is the **AUDIT leg** of the Agent Accountability Stack
(CAN / WHO / WHAT / AUDIT). It has two event categories, covered by two
separate modules in this sample code:

- **Session Audit Record** (`gar-core.ts`) — an append-only, hash-chained,
  periodically Merkle-rooted and Ed25519-signed record of every governance
  decision (`CEDAR_PERMIT`, `CEDAR_DENY`), escalation (`HEM_ESCALATION`),
  and session lifecycle event (`SESSION_START`/`SESSION_END`/...) in an
  agent session.
- **Authority Lifecycle Events** (`authority-lifecycle.ts`, Section 12) —
  the revocation and recovery chain: a session gets revoked
  (`ALE_SESSION_REVOKED`, `revocation_class` R-1 through R-9), recovery
  gates MJWT issuance (`mandate_hold`) until credentials are restored, and
  multi-agent delegation/cluster effects propagate outward
  (`ALE_DELEGATION_CHILD_REVOKED`, `ALE_CLUSTER_PARTIAL_REVOCATION`, etc.).
  **Did not exist in this sample code before this pass** — GAR-06/07's
  `revocation_class` enum picked up R-7 (DEADLOCK) and R-8 (Compromise)
  during the WIMSE Phase 2 review, and nothing here modeled any of
  ALE-001 through ALE-012 at all until now.

## Files

| File | Purpose |
|---|---|
| `gar-core.ts` | Session Audit Record core — `GAREntry`, `GARLog` (incl. `openSession()`), `SovMandateBinding`/`InMemorySov`, `GarSessionOpenRejectedError`, `computePrevSpanHash()`, `verifyChain()`, `GARProcessor`, `SessionBlock`, `GarBlockSigner`, `KIAStubSigner`, `closeSessionBlock()`, `verifySessionBlock()`, `GarSignerFailureError`, `tamperDetect()` |
| `authority-lifecycle.ts` | Authority Lifecycle Events (ALE-001–012 + mandate holds, Section 12) — `AuthorityLedger`, full event type definitions, causal-ordering + `mandate_hold` gate + R-8 external-signing enforcement |
| `demo.ts` | Session Audit Record walkthrough: session open → Cedar DENY → HEM escalation → session close → Session Block → chain verification pass → tamper → chain verification fail |
| `demo-revocation.ts` | Authority Lifecycle Events walkthrough — 12 scenarios covering ALE-001–012 and mandate holds, including negative-path checks |
| `generate-hp-logs.ts` | Generates the 20 happy-path Session Audit Record sample logs (`svl/corpus-b/gar/hp/`) |
| `generate-edge-logs.ts` | Generates the 11 adversarial/edge-case Session Audit Record logs (`svl/corpus-b/gar/edge/`) |

No happy-path/edge-case JSON corpus exists yet for the Authority
Lifecycle Events side (`demo-revocation.ts` covers the same ground
inline) — a natural next-session task, matching the same
build-core-first-then-corpus pattern used for PT and CAP-RRS.

## Quick start

```bash
npx tsx demo.ts              # Session Audit Record walkthrough
npx tsx demo-revocation.ts   # Authority Lifecycle Events walkthrough
npx tsc --noEmit             # type-check (tsconfig.json included)
```

## 20-line usage snippet

```typescript
import { GARLog, ALEType, InMemorySov } from './gar-core';

const log = new GARLog();
const sov = new InMemorySov();
sov.bindMandate('m1');                      // SOV MANDATE_BOUND
const session_id = 'my-session';

// Type 6 Session-Open Record first (CONF-GAR-SEQ-01/-02); throws if m1 is unbound
const sor = log.openSession({ session_id, actor_id: 'agent-1', mandate_id: 'm1',
  timestamp: new Date().toISOString(), kernel_id: 'k1', sov });

const start = log.append({
  entry_id: 'e1', ale_type: ALEType.SESSION_START, session_id,
  actor_id: 'agent-1', timestamp: new Date().toISOString(),
  causal_parent_id: sor.entry_id, decision: 'PERMIT', kernel_id: 'k1',
  cap_profile_hash: 'abc123',
});

// CEDAR_PERMIT/DENY require 3 provenance fields — append() throws if missing
log.append({
  entry_id: 'e2', ale_type: ALEType.CEDAR_PERMIT, session_id,
  actor_id: 'agent-1', timestamp: new Date().toISOString(),
  causal_parent_id: start.entry_id, decision: 'PERMIT', kernel_id: 'k1',
  cap_profile_hash: 'abc123', cedar_policy_id: 'p1',
  cap_rrs_control_id: 'c1', authority_source_uri: 'https://law.example/1',
  cedar_action: 'Action::"read"',
});

// Recomputes and compares each entry's own_span_hash; localizes tampering
console.log(log.verifyChain(session_id)); // { valid: true, failedAt: null }
```

## Authority Lifecycle Events (`authority-lifecycle.ts`)

The revocation/recovery chain — a separate event category from the
Session Audit Record above, covering GAR-13 Section 12 (ALE-001–012,
ALE_MANDATE_HELD, ALE_MANDATE_HOLD_RELEASED).

```typescript
import { AuthorityLedger, buildALE001, buildALE004, buildALE006, buildALE008, stubSignature } from './authority-lifecycle';

const ledger = new AuthorityLedger();

const rev = ledger.append(buildALE001({
  prior_event_id: 'aep-event-abc', session_id: 's1', agent_id: 'a1',
  mandate_jti: 'm1', so_id: 'so://x', revocation_class: 'R-2',
  authority_type: 'KERNEL', revocation_event_ref: 'mjwt-revoked-1',
  revocation_reason: 'scope boundary', revocation_type: 'DIRECT',
  revocation_source: 'CAP_VIOLATION',
  trigger_event_ref: 'evt-1', completion_state: 'CLEAN',
  natural_breakpoint_reached: true, irreversible_actions_taken: false,
  rollback_available: true, so_state_at_revocation: 'in_progress',
  iterations_completed: 3, cascade_depth: 0, gec_signature: stubSignature('gec-1'),
}));

const rec = ledger.append(buildALE004({
  prior_event_id: rev.event_id, agent_id: 'a1', recovery_ref: 'r1',
  initiated_by: 'OPERATOR', initiator_ref: 'op-1', revocation_ref: rev.event_id,
  recovery_type: 'CREDENTIAL_ROTATION', gec_signature: stubSignature('gec-1'),
}));

ledger.hasMandateHold('a1'); // true -- MJWT issuance blocked until ALE-008
```

**Causal ordering (Section 12.2)** is enforced per event type, not just
"any prior entry exists": `append()` checks each type's `prior_event_id`
against the specific prior type(s) the spec names — e.g. `ALE_AUTHORITY_
RESTORED` rejects a `prior_event_id` that resolves to `ALE_RECOVERY_
INITIATED` instead of the required `ALE_CREDENTIAL_RESTORED` or `ALE_KIA_
REATTESTATION_COMPLETED`. `ALE-001`/`ALE-002` (true chain roots) and
`ALE-009`/`ALE-011` (which reference the last event in a *different*
session's own Event Log, not this ledger) are treated as opaque external
references and not checked against this store.

**`mandate_hold` gate (Section 12.6)**: `ALE_RECOVERY_INITIATED` sets the
hold; `assertCanIssueMandate(agent_id)` throws `AgentInRecoveryError`
(`.code === 'AGENT_IN_RECOVERY'`) while it's active. Only `ALE_AUTHORITY_
RESTORED` with `mandate_hold_lifted: true` clears it — and `append()`
blocks that event with `UnresolvedPartialStateError` if any `ALE_PARTIAL_
STATE_DISPOSITION` for the same `recovery_ref` is still `DEFER` (Section
12.7).

**R-8 external signing (Section 12.1/12.9) — the fix this pass**:
`ALE_KIA_REATTESTATION_COMPLETED` (ALE-007) is signed by an external KIA
Verification Service via `kia_verifier_signature`, which *replaces*
`gec_signature` entirely on this event type — a compromised kernel can't
self-attest its own recovery. GAR-07 previously mislabeled this carve-out
"R-3" in three places (Section 12.1, Section 12.9, and the Section 15
changelog) — MAD's actual R-3 is Non-Response, not Attestation Integrity
Failure. Fixed to R-8 (Compromise) in the draft this pass, and enforced
in code: `append()` walks an `ALE-007`'s `prior_event_id` back through
its `ALE-004` to the originating `ALE_SESSION_REVOKED` and throws
`ExternalSigningRequiredError` if that revocation's `revocation_class`
wasn't `R-8` — seen in `demo-revocation.ts` scenario 9.

**Naming note**: this module does not reuse `gar-core.ts`'s exported
`ALEType` enum. That enum predates GAR-07 Section 12 and uses stale,
conflicting comments (its own `// ALE-002`/`// ALE-003`/`// ALE-004`
refer to `SESSION_HALTED_CLEAN`/`PARTIAL`/`UNKNOWN` — nothing like this
module's real `ALE-002` = `ALE_AUTHORITY_SUSPENDED`, `ALE-003` =
`ALE_PARTIAL_STATE_RECORDED`, `ALE-004` = `ALE_RECOVERY_INITIATED`).
Flagged, not fixed — renaming `gar-core.ts`'s enum touches the existing
Session Audit Record path this module doesn't own.

**Shared vocabulary checks (GAR-13 Section 12.3/12.21)**: `append()`
throws `VocabularyConformanceError` when `cascade_root_jti` is present
without `revocation_type`/`hold_type` `CASCADE` (or missing with it), and
refuses `revocation_source: 'CAEP_SIGNAL'` with `authority_type: 'KERNEL'`
— an external signal alone only holds a mandate (MJWT-08 §7.7); it must
be converted under PRINCIPAL or OPERATOR authority. `isMandateHeld(jti)`
reports active holds.

## KIA stub signer

`KIAStubSigner` generates a local Ed25519 keypair at construction time and
signs Session Block Merkle roots with it. This is a **stand-in only** — it
has no relationship to a real identity or trust anchor. It implements
`GarBlockSigner`, the narrowed interface (`sign()` + `publicKeyId`) that
`closeSessionBlock()` actually depends on — a real KIA Governance Identity
Keypair, or a real FROST threshold-signing cluster, can be substituted by
implementing the same interface. See `// KIA stub` in `gar-core.ts`.

If a signer's `sign()` throws (e.g. a FROST cluster below quorum),
`closeSessionBlock()` wraps the failure as `GarSignerFailureError` rather
than returning a Session Block — see "Signer failure handling" below.

## OTel stub

`GARProcessor.emit()` prints `soos.governance.*` and `soos.cap.*` fields to
`console.log` in place of emitting real OpenTelemetry spans. A production
implementation would use `@opentelemetry/api` to emit these as span
attributes on the actual trace, with `block_id` set to the OTel `trace_id`
at Session Block close (see the comment on `SessionBlock.block_id` and
`closeSessionBlock()` in `gar-core.ts`).

## Signer failure handling

`closeSessionBlock()` does not swallow or retry a signer failure. On
`sign()` throwing, it raises `GarSignerFailureError` (original error
preserved on `.cause`) instead of returning a partially-built
`SessionBlock` — GAR-06 §14.3 requires session close MUST NOT proceed
with an unsigned block. The retry/backoff loop is left to the caller,
since only the caller knows its deployment's quorum-restoration policy:

```typescript
try {
  const block = closeSessionBlock(session_id, entries, signer);
} catch (err) {
  if (err instanceof GarSignerFailureError) {
    log.append({ ale_type: ALEType.KERNEL_AUDIT_ANOMALY, /* ... */ });
    // retry once quorum is restored — session remains open meanwhile
  } else {
    throw err;
  }
}
```

See `generate-edge-logs.ts` GAR-EDGE-011 for this exercised end to end.

## Known gaps (see `svl/issue-log.md` and `SDB-GAR-issues.md`)

The sample code is intentionally faithful to what GAR-06 currently
specifies, and no further. Several edge cases surfaced open questions —
logged rather than silently guessed at:

- **SDB-GAR-01** (resolved) — `prev_span_hash` for the first entry in a
  session is the sentinel string `'GENESIS'`.
- **SDB-GAR-02** (open) — `verifyChain()` on a session with zero entries
  returns vacuous `{ valid: true }`; GAR-06 doesn't define this case.
  Non-blocking, genuinely ambiguous.
- **SDB-GAR-03** (resolved) — `append()` now validates that
  `causal_parent_id`, when present, references an existing `entry_id` in
  the log, throwing otherwise. Timestamp monotonicity remains
  intentionally unenforced (GAR-06 doesn't require it).
- **SDB-GAR-04** (resolved) — `verifySessionBlock()` recomputes the
  Merkle root from a Session Block's own events and compares against the
  claimed root, for a receiving party to detect a mismatched/tampered
  block. Does not verify the Ed25519 signature itself (no public key
  distribution in this Tier-1 stub).
- **SDB-GAR-05** (open, and the premise itself may be stale) —
  `GOVERNANCE_SUSPENDED` has no enforced mandatory field set. GAR-06's
  own ALE registry no longer lists `GOVERNANCE_SUSPENDED` at all — this
  may be superseded by CAP-04's own `CAP_POLICY_SUSPENDED` event, which
  already has a full field set. Needs confirmation before investing in
  enforcement for a type GAR may no longer own.
- **SDB-GAR-06** (resolved) — Merkle leaf/parent hashing operates on raw
  digest bytes, not hex text.
- **SDB-GAR-07** (tracked at spec level, not a code gap) — Layer 1
  (`prev_span_hash`) covers only six fields; Layer 2 (Merkle) covers the
  full entry. GAR-06 documents this explicitly as S.15.d / OQ-GAR-04-01,
  left unresolved pending a Decision Record on whether to widen Layer 1.
- **SDB-GAR-08** (resolved) — `block_id` is attached before Merkle
  hashing on both sides, so anchored events always match the claimed root.
- **SDB-GAR-09** (resolved) — RFC 6962 §2.1 Merkle Tree Hash (MTH)
  construction: domain-separated leaf/internal-node hashes (0x00/0x01
  prefix) and no-duplication tree shape (k-split), closing a
  CVE-2012-2459-class malleability gap.
- **SDB-GAR-10** (resolved) — signer failure at Session Block close now
  raises `GarSignerFailureError` distinguishably, so a caller can emit
  `KERNEL_AUDIT_ANOMALY` and retry, instead of the failure surfacing as
  whatever error shape the underlying signer happened to throw.
- **SDB-GAR-11** (documented, not a code gap) — the empty-tree Merkle
  root convention (`SHA-256('')`, per RFC 6962) already matches GAR-06's
  spec; it's ARP-03's 32-zero-octet assumption that's out of step with
  GAR here, not the other way around.

- **SDB-GAR-13** (open, new) — first-span sentinel. GAR-13 §2 says the
  empty string for the first span in a session; this code and the
  corpus use `'GENESIS'`. Isolated as `FIRST_PREV_SPAN_HASH` in
  `gar-core.ts`; switching needs a corpus regeneration and re-confirming
  any shared test vectors, so it is left for a decision.
- **SDB-GAR-14** (open, new) — the Session-Open Record is not signed
  individually here (GAR-13 §4.6 lists `gec_signature`); it is covered by
  the Session Block signature at close. `sequence_record_id` uses
  `randomUUID()` (v4) in place of UUID v7. `cedar_action` is emitted but
  not yet in `MANDATORY_PROVENANCE`.

None of the remaining open items (SDB-GAR-02, SDB-GAR-05) block
correct operation of the sample code as written.

- **SDB-GAR-12** (resolved, this pass) — GAR-07 Section 12.1/12.9 and the
  Section 15 changelog mislabeled the external-KIA-signing carve-out for
  `ALE_KIA_REATTESTATION_COMPLETED` as "R-3" (MAD's Non-Response class).
  The actual match is R-8 (Compromise) — its detection sources explicitly
  include a KIA reattestation failure. Fixed in `draft-sato-soos-gar-07`
  (all four instances) and enforced in `authority-lifecycle.ts`'s
  `append()`, which rejects an `ALE-007` whose originating revocation
  wasn't R-8.
- **SDB-GAR-13** (open) — `authority-lifecycle.ts`'s `AuthorityLedger` is
  a separate in-memory store from `gar-core.ts`'s `GARLog`. A real
  deployment needs these unified (or at least cross-referenceable) since
  `ALE_SESSION_REVOKED` fires from `AEP_SESSION_CLOSED` in the Session
  Audit Record path, and `ALE-009`/`ALE-011`'s `prior_event_id` opaquely
  references an entry in a *different* session's Session Audit Record
  that this module has no way to actually verify exists. Not attempted
  this pass — a real integration needs a decision on whether GAR ships
  one unified store or two coordinated ones, which is a design question
  for Tom, not something to guess at in sample code.

## What this sample code does NOT give you

This is Layer 1 / Tier 1 sample code: an in-memory array, SHA-256 hash
chain, and a single Ed25519 stub signer. It does not provide durable
storage, multi-writer concurrency control, real OTel span emission, real
KIA-issued signatures, or performance characteristics representative of a
production deployment. See the Sample Code Plan's "What Sample Code Does
Not Give You" section for the full list.
