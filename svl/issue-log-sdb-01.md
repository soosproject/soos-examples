## ISSUE-006 — SDB-01 (Type II — Scenario C, state machine incompleteness)

**Found:** SOV Step 2a
**Item:** Does `SOV-02` define `SUSPENDED` as a named `current_phase` value?
**Gap:** No. The SOV-01/-02 schema table defines `current_phase` as a
five-value lifecycle enum: `ACTIVE` -> `OPERATIONALLY_COMPLETE` ->
`ADMINISTRATIVELY_CLOSED` -> `ARCHIVED` -> `CRYPTOGRAPHICALLY_ERASED`.
`SUSPENDED` does not appear.

**Relevant precedent found in the draft:** SOV-02's own minimal Cedar
policy example uses `resource.current_state == "HEM_PENDING"` to gate an
escalation pause — i.e. at least one place in the draft models an
escalation/pause condition as a `current_state` value, not a
`current_phase` value. This is suggestive but not stated as a general
rule, and does not resolve whether a *phase-level* SUSPENDED (as opposed
to a *state-level* pause like HEM_PENDING) is ever needed — e.g. for a
SOV suspended pending legal/regulatory hold that should survive a
state-machine reset.

**Classification rationale:** Scenario C (state machine incompleteness) —
sample code (`sov-core.ts`) needed a concrete `SOPhase` type to compile
against; the draft doesn't specify all phase values a real deployment
might need, so a decision had to be made now rather than deferred.

**Resolution for sample code:** `SOPhase` implemented as the five-value
enum with no `SUSPENDED` member. `// TODO: SDB-01` marker added at the
`SOPhase` type definition and at the top of `sov-core.ts` documenting the
HEM_PENDING precedent and the open question.

**Status:** Non-blocking for Step 2 Done Criteria. Recommend GAR/SOV
co-authors confirm in `SOV-03` whether pause/suspension belongs at the
phase level, the state level (mirroring `HEM_PENDING`), or both, and if
phase-level, name it explicitly.

**DR needed:** Yes — before SOV-03 revision, per the plan's own worked
example of this exact issue in the Sprint Issue Log Format reference.
