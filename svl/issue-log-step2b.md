## ISSUE-007 — SDB-02 (Type II — gap)

**Found:** SOV Step 2b, `SOV-EDGE-007`
**Item:** `SovereignObject.parent_so_id` is never checked against a registry
of actually-created SOs.
**Gap:** A child SO can be constructed and created via `GECMediator.create()`
with `parent_so_id` pointing at a `so_id` that has no `EventStream` entries
at all — accepted silently. Neither `SovereignObject` nor `GECMediator`
maintains a central registry of created `so_id` values to validate
against; each `EventStream` only knows about entries for `so_id`s it has
actually seen.
**Precedent:** Nearly identical in shape to `SDB-GAR-03` (GAR's dangling
`causal_parent_id` gap) — same root cause pattern (a "reference" field
with no referential-integrity enforcement) recurring in a second draft.
**Status:** Needs a Decision Record — should a Tier 1 sample maintain an
in-memory SO registry for referential integrity checks, or is this
deferred to a storage/higher layer? Worth resolving once, generally,
rather than per-draft, given the recurrence.
**Resolution for sample code:** Not yet resolved. Non-blocking for Step 2
Done Criteria.

---

## ISSUE-008 — SDB-03 (Type II — gap, minor)

**Found:** SOV Step 2b, `SOV-EDGE-004` fix
**Item:** `assertNoPersonalData()`'s recursive fix does not recurse into
arrays (e.g. `{ contacts: [{ email: '...' }] }` would still slip through).
**Status:** Noted during the nested-object fix; not separately tested in
this pass. Low severity — Zone A content in the sample corpus does not
currently use array-of-object shapes, but a real implementation should
extend the recursion to array elements.
**Resolution for sample code:** Deferred — flagged for the next SVL pass
on SOV rather than fixed reactively without a test case demonstrating it.

---

## ISSUE-009 — SDB-04 (Type II — ambiguity, low severity)

**Found:** SOV Step 2b, `SOV-EDGE-009`
**Item:** `StandingPlanObject.scope_constraints.delegation_depth` accepts
negative values (tested with `-3`) with no validation.
**Gap:** SOV-02 does not state a valid range for `delegation_depth`. A
negative value is semantically nonsensical (delegation chains cannot have
negative length) but nothing rejects it.
**Status:** Likely resolvable editorially in SOV-03 — e.g. "`delegation_depth`
MUST be a non-negative integer" — rather than requiring a full Decision
Record, since there's no plausible reading under which negative depth is
meaningful.
**Resolution for sample code:** Not yet resolved. Non-blocking.

---

**Also confirmed in Step 2b (relates to open SDB-01):**

`SOV-EDGE-008` demonstrated that `GECMediator.transition()` performs no
runtime validation that `newPhase` is one of the five defined `SOPhase`
values — a forged `'SUSPENDED'` phase (via an `as any` cast simulating
untyped external input) was accepted and silently written into
`current_phase`. This means that whichever way `SDB-01` is eventually
resolved, a runtime allow-list check will be needed in `transition()` to
actually enforce it — TypeScript's compile-time `SOPhase` union offers no
protection against data arriving from outside the TS boundary (e.g. a
real deployment reading phase values off a wire format). Recommend adding
this runtime check once SDB-01 is resolved, rather than before, so the
allow-list can be built against a confirmed enum rather than a guess.
