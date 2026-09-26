## ISSUE-002 — SDB-GAR-02 (Type II — ambiguity)

**Found:** Step 1c, GAR-EDGE-001
**Item:** `verifyChain()` behavior on a session_id with zero entries.
**Gap:** GAR-03 does not define this case. Current implementation returns
`{ valid: true, failedAt: null }` via vacuous-truth empty-loop fallthrough,
rather than a defined error or a distinct "no such session" state.
**Status:** Non-blocking for sample code. Recommend GAR-04 specify explicitly.
**Resolution for sample code:** Vacuous truth accepted as current behavior.

---

## ISSUE-003 — SDB-GAR-03 (Type II — gap)

**Found:** Step 1c, GAR-EDGE-003
**Item:** `GARLog.append()` performs no validation of (a) timestamp
monotonicity, or (b) whether `causal_parent_id` references an entry that
actually exists in the log.
**Gap:** Both were silently accepted in testing — an entry with an earlier
timestamp than its predecessor, referencing a nonexistent `causal_parent_id`,
appended without error. `verifyChain()` still reports valid because the hash
chain is keyed on append-call order, not on `causal_parent_id` or timestamp.
**Classification rationale:** Integration gap — the hash chain correctly
guarantees append-order integrity, but `causal_parent_id` is currently
decorative; nothing enforces it references a real prior entry.
**Status:** Needs a Decision Record — should `GARLog` validate
`causal_parent_id` referential integrity and/or timestamp ordering at
append() time, or is this a higher-layer concern (e.g. SOV Event Stream)?
**Resolution for sample code:** Not yet resolved. TODO marker to be added
in `gar-core.ts`. Non-blocking — does not affect Step 1 Done Criteria.

---

## ISSUE-004 — SDB-GAR-04 (Type II — gap)

**Found:** Step 1c, GAR-EDGE-008
**Item:** No `verifySessionBlock()` counterpart to `closeSessionBlock()`.
**Gap:** GAR-03 does not specify who verifies a received Session Block's
`merkle_root` against an independently-held copy of the entries.
`closeSessionBlock()` only constructs; nothing in the sample verifies.
**Status:** Non-blocking. A `verifySessionBlock(block, entries)` function,
analogous to `verifyChain()` for the span-level chain, may be needed for a
receiving party to detect entry-dropped or entry-substituted tampering at
the Session Block layer.
**Resolution for sample code:** Deferred — not required for Step 1 Done
Criteria, since the Merkle root itself was confirmed to differ correctly
under a dropped entry (GAR-EDGE-008 actual result).

---

## ISSUE-005 — SDB-GAR-05 (Type II — gap)

**Found:** Step 1c, GAR-EDGE-009
**Item:** `GOVERNANCE_SUSPENDED` has no mandatory-field enforcement at all.
**Gap:** `MANDATORY_PROVENANCE` enforcement in `append()` applies only to
`CEDAR_PERMIT` / `CEDAR_DENY`. A `GOVERNANCE_SUSPENDED` entry — arguably the
highest-severity ALE type — was accepted in testing with zero identifying
or escalation fields. GAR-03 §13.3 names only `CEDAR_PERMIT`/`CEDAR_DENY`
explicitly; the draft is silent on `GOVERNANCE_SUSPENDED`'s own required
field set (plausibly `escalation_class` + `so_reference`, mirroring
`HEM_ESCALATION`).
**Status:** Needs normative clarification in GAR-04.
**Resolution for sample code:** Not yet resolved. TODO marker to be added
in `gar-core.ts` pending that decision — no enforcement added since the
correct field set isn't yet defined; adding the wrong one would be worse
than adding none.
