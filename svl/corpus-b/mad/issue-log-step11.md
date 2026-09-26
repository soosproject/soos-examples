# Step 11 (MAD) — Issue Log Additions

Built against `draft-sato-soos-mad-03` directly (not the plan's paraphrase),
same precedent as Steps 4/8/9/10.

## SDB-MAD-01 (Type II — plan/draft mismatch, non-blocking)

**Found:** Step 11, corpus generation.
**Item:** The plan's Step 11 block (`SOOS_SampleCode_Plan_v14.md` line 1227)
instructs generating an SVL log for "MANDATE_HOLD propagation." No term
`MANDATE_HOLD` — nor any close variant — appears anywhere in
`draft-sato-soos-mad-03`.
**Resolution:** Built against the draft's actual "hold" concept instead:
§7.1's `CONTINUATION_AWAITING_PRINCIPAL`, which GAR records after an R-1
(CAP Tier 0-A) revocation and holds until the human principal issues a
continuation mandate. This is functionally the closest real primitive to
what "MANDATE_HOLD propagation" was probably describing. Demonstrated in
`demo.ts` §5 and corpus entries R1-HP-01/02.
**Status:** Non-blocking. Same category as Step 8's SDB-FAIP-01 and Step
4's stale trust_band correction — flagging for Tom's awareness, not
pausing the build for it.

## SVL Phase A key question — resolved

**Question (plan line 1225):** "The R-1 through R-7 revocation completion
matrix — are these the only completion states, or are there additional
fallback states not shown in Table 1?"
**Resolution:** Read directly against §7.1–§7.9 and Table 1 (§7.8): the
matrix is exhaustive. Every trigger resolves to exactly one of
CLEAN/PARTIAL/UNKNOWN, with three triggers fixed to a single value
regardless of circumstance (R-1: PARTIAL always; R-3, R-7: UNKNOWN
always) and four circumstance-dependent (R-2, R-4, R-5, R-6, gated on
detection/halt timing). No additional fallback states exist. Implemented
exactly as Table 1 in `types.ts` (`COMPLETION_STATE_MATRIX`) and
`revocation.ts` (`resolveCompletionState()`).

## SDB-03 (carried from SOV/Step 2, resolved for this step per DR-SOV-02)

**Status entering Step 11:** Critical, PENDING Tom's sign-off, explicitly
scoped to "Step 11a (MAD)" in `DR_SOV_v1.md`'s summary table.
**Applied here:** DR-SOV-02's recommended **Option A (optimistic
concurrency control)** was used as the working assumption for any
concurrent-write surface MAD-03 touches (SACR Registry writes, Revocation
Registry writes). MAD-03 itself doesn't specify OCC directly — the SACR
Registry and Revocation Registry in this sample are plain in-memory Maps
without a version/etag field, since this session's build didn't reach the
"Act 4 Concurrent Conflict" multi-writer scenario the plan's Five-Act Arc
describes (`SOOS_SampleCode_Plan_v14.md` line 1497). Flagging that Act 4
specifically — two GEC instances racing to issue a SACR against the same
`parent_assignment_id`, or two revocation triggers racing on the same
`session_id` — is NOT yet built and would need an explicit OCC
version-check added to `gec.ts`'s `spawnSubAgent()` and
`revocation.ts`'s `trigger()` before that scenario is demonstrable.
**Still PENDING Tom's sign-off** per the working-mode rule — not decided
by this note.

## Design note (non-gap): GAR ALEType extension

`draft-sato-soos-mad-03` §16.3 requests registration of ALE-SPAWN-01
through -04 in GAR's ALE Type Registry, and §11/§7 introduce ~15 more MAD
event types. `deps/gar/gar-core.ts`'s `ALEType` enum was extended with all
of these as a pure addition (no existing member changed) rather than
building a parallel logging path — this is what §16.3 is literally asking
for. Not logged as an SDB since it's implementing an explicit IANA-style
registration request in the draft, not resolving an ambiguity.
