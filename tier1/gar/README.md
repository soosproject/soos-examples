# GAR — Governance Audit Record

Sample TypeScript implementation of `draft-sato-soos-gar-06` (Tier 1,
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
| `gar-core.ts` | Core implementation — `GAREntry`, `GARLog`, `computePrevSpanHash()`, `verifyChain()`, `GARProcessor`, `SessionBlock`, `GarBlockSigner`, `KIAStubSigner`, `closeSessionBlock()`, `verifySessionBlock()`, `GarSignerFailureError`, `tamperDetect()` |
| `demo.ts` | End-to-end walkthrough: session open → Cedar DENY → HEM escalation → session close → Session Block → chain verification pass → tamper → chain verification fail |
| `generate-hp-logs.ts` | Generates the 20 happy-path sample logs (`svl/corpus-b/gar/hp/`) |
| `generate-edge-logs.ts` | Generates the 11 adversarial/edge-case logs (`svl/corpus-b/gar/edge/`) |

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

None of the two remaining open items (SDB-GAR-02, SDB-GAR-05) block
correct operation of the sample code as written.

## What this sample code does NOT give you

This is Layer 1 / Tier 1 sample code: an in-memory array, SHA-256 hash
chain, and a single Ed25519 stub signer. It does not provide durable
storage, multi-writer concurrency control, real OTel span emission, real
KIA-issued signatures, or performance characteristics representative of a
production deployment. See the Sample Code Plan's "What Sample Code Does
Not Give You" section for the full list.
