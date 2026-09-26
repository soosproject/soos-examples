# Step 13 (PEER) + RGP + ACD — Issue Log

Three modules built this turn to unblock PEER: RGP (draft-sato-soos-rgp-00),
ACD (draft-sato-soos-acd-01), and PEER itself (draft-sato-soos-peer-00).
RGP and ACD weren't previously built — they're PEER's real, load-bearing
dependencies (Gate 1 and Gate 2), not tier-note mentions, so they got
built as their own scoped modules rather than stubbed inline.

## SDB-RGP-01 (Type II — three-way cross-draft field mismatch, resolved)

**Found:** while building PEER's Gate 2 conditional logic.
**Item:** PEER-00 §4.3 says a regulated Responding Agent is "indicated
in its RGP Stage 1 fingerprint via the regulated_provider flag." ACD-01
§7.1 independently says the same concept is named `acd_required` and
lives in "the RGP capability declaration." RGP-00 itself — checked by
grep across the entire draft — defines **neither field**, in either the
Stage 1 fingerprint schema (§7.3) or the Stage 2 full declaration schema
(§7.4). All three drafts assume a field that only two of them name, and
none of them actually specify.
**Resolution:** Added `acd_required` (ACD's name, since ACD is the
consuming spec and the more descriptive name) as an extension field on
RGP's `Stage1Fingerprint` type (`soos-rgp-sample/src/types.ts`), flagged
inline as not part of RGP-00's actual §7.3 schema. Stage 1 is what
PEER's Gate 1 queries before Gate 2 would even run, so that's the layer
it has to live at for PEER's described flow to work at all.
**Status:** Non-blocking, resolved with a documented extension — same
category as Step 11's SDB-MAD-01. Worth surfacing to whoever authors
RGP-01 or ACD-02, since right now the actual field name and owning
schema are undefined in the normative text of either draft.

## RGP — build scope

Built: capability class registry (§6), trust levels (§7.1), Stage 1
fingerprint discovery (§8) with freshness rejection, Stage 2 full
declaration + the 5-step validation procedure (§9.3). GAR gets
ALE-022/024/025 emitted from real code paths (ALE-023 RESOURCE_MAP_CLOSED,
ALE-026 FALLBACK_ACTIVATED, and ALE-027 ATTESTATION_DOWNGRADE are
registered in GAR's ALEType enum but not emitted — no session-close or
attestation-downgrade path was built).

Not built (flagged, not on PEER's critical path): Resource Map Sovereign
Object (§10), RGP-Model (§11), RGP-Physical (§12), Fallback and
Re-Routing (§13), ATP Profile Integration (§14). All real RGP surface
area; none of it gates PEER's Gate 1, which only needs Stage 1 discovery
+ the capability-class-coverage check.

## ACD — build scope

Built: full ACD Record schema (§6, all three layers + the mjwt_jti
binding addition from §9.1), the Presentation Protocol handshake (§7.2)
with the four-check sequence (§7.4) gating record issuance, and
resource-provider-side validation (§7.3, all 6 steps). Data minimization
(§10.3) is enforced in code, not just documented: ALE-057 stores
`record_hash` only, never the record body — verified in corpus scenario
ACD-HP-02.

Design note: ACD-01's `denial_reason` enum (`FOUR_CHECK_FAILED` |
`LAYER_INSPECTION_FAILED` | `EXPIRED` | `XPID_MISMATCH`) has no literal
value for a resource-provider-side signature-verification failure (§7.3
Step 1) — used `LAYER_INSPECTION_FAILED` as the closest fit rather than
misusing `FOUR_CHECK_FAILED` (that value is specifically for the GEC-side
§7.4 sequence, a different step of the protocol). Not logged as a
blocking SDB since it's a minor enum-coverage gap, not a contradiction.

Not built: full ACD Trust Hierarchy (§8) operator credential chains,
sub-agent MJWT chain-tracing beyond the single `mjwt_jti` field (§9.3).

## SDB-PEER-01 (Type II — self-caught interoperability bug, fixed)

**Found:** after KEE-1 (`draft-sato-soos-kee-01`) became available and
turned out to contain, in §10 ("XPID Derivation Function"), the actual
authoritative specification for the function PEER-00 §5.1 delegates
`ptxn_id` derivation to ("the GEC's ptxn_id derivation function...
KEE-1 minor addition"). Before this, no normative source for the
derivation's exact namespace UUID or field-separator character was
available, so this module used placeholder values.

**The placeholders were wrong in two ways, not just "unconfirmed":**
- Namespace UUID: this module used an invented value
  (`6b3f8a1e-9c2d-4e5f-8a0b-1c2d3e4f5a6b`). KEE-1 §10 specifies a fixed
  real value, the "SOOS Namespace UUID"
  (`bcab38fe-febf-4632-8fc9-2a23cb9e4ee3`, also assigned in §14.3).
- Field separator: this module joined fields with `"||"` (double pipe).
  KEE-1 §10 specifies a literal single `"|"` (U+007C VERTICAL LINE).

**Impact:** every `ptxn_id` this module produced before the fix would
NOT match what a real KEE-1-conformant kernel computes for the same
five inputs — silently breaking the exact property PEER-00 §5.1 relies
on ("No trusted third party is required. The ptxn_id is unforgeable by
either party acting alone... each nonce is generated independently by
its respective GEC" — this only holds if both GECs are running the
*same* derivation function). A real Responding GEC verifying against
this module's old output would always see a mismatch and reject every
transaction.

**Fixed:** `derivePtxnId()` now uses the real namespace and `"|"`
separator. Corpus scenario PEER-HP-06 cross-checks this module's output
against an *independent* computation using the `uuid` package directly
against KEE-1 §10's own worked TypeScript reference — not a tautological
check against this module's own code path.

## Nonce replay defense (§8.3) — now wired in

Previously flagged as implemented-but-unused: `isReplayedNonce()`
existed but `runPeerExchange()` never called it. Fixed:
- `issueNonce()` no longer self-records — it generates a fresh CSPRNG
  nonce only.
- `runPeerExchange()` checks both nonces against each GEC's set of
  nonces from prior *successful* handshakes immediately after issuance,
  before mutual attestation completion is logged. A hit rejects the
  exchange with `failedAt: 'ATTESTATION'` and logs `ALE-PEER-04`.
- Nonces are only recorded as "used" once the handshake fully succeeds
  (past RGP/ACD gates and ptxn_id verification) — a failed or abandoned
  handshake doesn't burn its nonces, so a legitimate retry with
  regenerated (and coincidentally identical, vanishingly unlikely)
  values isn't blocked by its own prior failure.

Corpus scenarios PEER-EDGE-08 (replay rejected) and PEER-HP-07 (failed
handshake doesn't burn nonces) exercise both halves of this.

## PEER — build scope

Built: the full §4.1-§4.3 sequence (mutual KIA attestation with an
exact-string-match allow-list per §8.4, nonce contribution, RGP Gate 1,
conditional ACD Gate 2), `ptxn_id` derivation and independent
verification (§5.1) reusing KIA's real `uuid5` primitive, the complete
PTR schema (§5.2), and all four candidate `ALE-PEER` types (§5.4). The
demo/corpus both confirm the core correlation property empirically:
`ptxn_id` shows up in two genuinely separate `GARLog` instances
(simulating two independently-rooted GECs), not shared state.

AEP integration is intentionally thin, per the draft's own framing:
PEER-00 §1.3 calls itself "a thin correlation layer... it does not
replace or extend any existing primitive," and §5.3 only requires that
`ptxn_id` be "referenced in the AEP session metadata" — a field
attachment, not a functional dependency on AEP's GEC Execution Sequence.
Modeled here as a `domain_transaction_ref`/`ptxn_id` pair a caller
attaches to their own AEP session object; the full AEP module wasn't
pulled in as a dependency since nothing in PEER-00's normative text
calls into AEP's session lifecycle machinery.

Not built (all explicitly deferred to PEER-01 by the draft itself, §7):
normative ALE-PEER schemas beyond the candidate shape (OQ-PEER-07),
dispute resolution when two GAR chains disagree on terminal state
(OQ-PEER-03), the ATP Booking Object ↔ PTR lifecycle alignment
(OQ-PEER-04), and the AIP IBCT transport-layer composability (§4.4) —
informative only in PEER-00, no normative behavior to implement yet.
