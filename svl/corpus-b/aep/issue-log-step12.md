# Step 12 (AEP) — Issue Log Additions

Built against `draft-sato-soos-aep-02` directly. Tier 2 — genuinely
integrates real Step 1 (GAR), 2 (SOV), 3 (MJWT), 5 (IDP), 6 (KIA),
9 (CAP) modules, not stubs. HEM's real module (Step 7) is copied into
`deps/hem/` for completeness but this build's Transition Request
sequence only reaches the `hem_required`-routing decision point — full
`HEM_PENDING` session-state exit handling (APPROVE/REDIRECT/TERMINATE/
DEFER dispositions, §5.3) is flagged below as not yet built.

## Design notes (not gaps — integration choices worth recording)

**MJWT verification at session init (§5.1(a)).** The 13-step
`verifyMandate()` protocol is written for a Transition-Request context:
Step 10 checks a `requested_cedar_action` against the mandate's
`cedar_actions`. Session initiation has no target action yet. Resolved
by peeking the unverified claims (same technique `verifyMandate()`'s own
Steps 1-2 use before signature verification) and supplying one of the
mandate's own declared `cedar_actions` as Step 10's comparison value —
keeps all 13 steps meaningfully enforced at session init rather than
skipping the protocol or forking a session-init-only variant.

**CAP CEE scoped to Tier 0/1.** AEP-02 §9.2 Step 2 explicitly limits
itself to "CAP Tier 0 (constitutional) and Tier 1 (jurisdictional)".
CAP's real `evaluateCee()` runs a fixed six-step sequence including
Tier 2 (operator ethics). Called here with `tier2Records: []` always, so
Tier 2 never matches — this scopes the integration to what AEP-02
actually asks for without needing a partial-CEE variant.

**State-machine edge validation (§9.2 Step 4).** SOV's `SO_TYPE_REGISTRY`
(from IDP's `stubs.ts`) has a state list and action space per SO Type,
but no explicit `(state, action) -> state` transition graph — that's
AEP's own Transition Graph (§8.1), which lives in a Discussion-App-level
integration this session's dependency set doesn't include. Approximated
here as "any action in the SO Type's action space is valid from any
non-terminal state," same category of approximation as SOV's own
`POLICY_EVALUATION_ORDER` stub. The demo/corpus's `deriveTargetState()`
action→state mapping is similarly a hand-authored stand-in for the real
Transition Graph.

**EOD reuses IDP's `intakeEndorsement()`.** AEP-02's EOD (§6.2) is
richer than IDP's own `EOD`/`EndorsedEOD` pair (§4.6, built for AOP's
endorsement flow), but both validate `primary_outcome.target_state` /
`plan_b_target_state` against the same SO Type state machine. Rather
than reimplementing that check, `initiateSession()` calls the real
`intakeEndorsement()` for the state-machine-validity half of EOD commit
and layers AEP-02's own fields (`acceptance_envelope`,
`submitter_mjwt_id`, `auto_activate_plan_b`, etc.) around it.

## SVL Phase A key question — resolved

**Question (plan's Step 12 block, referencing an earlier open item):**
what is the exact input to `soos.aep.cp_hash`?
**Resolution:** §12.2 states it plainly — "SHA-256 of Context Package."
No ambiguity; implemented in `otel.ts` reusing KIA's `canon.ts` canonical-
JSON + SHA-256 helpers, same as every other hash in this codebase.
`OTel-CONF-02`'s cp_hash/cp_hash_ref binding is also implemented (SENSE
and ACT spans compute the hash the same way).

## Not yet built (flagged, not blocking)

- **HEM_PENDING full lifecycle.** `act()` currently has the routing
  *decision points* (CAP/Cedar DENY-with-escalation would route here)
  but doesn't yet drive a session into `HEM_PENDING` and back out via
  HEM's real `HemEscalationRequest`/decision-type flow (§5.3). HEM's
  module is integrated Step-6/Step-7-style (real types, real
  `handleManipulationDetected()` etc. available in `deps/hem/`) but the
  AEP-side session-state wiring for entry/exit isn't wired up in this
  pass.
- **STALL_PATH_EXHAUSTED / STALL_PLAN_B_BLOCKED / STALL_ITERATION_LIMIT.**
  Only `STALL_DENY_THRESHOLD` (§5.4(a)) is implemented. The other three
  stall conditions need the Transition Graph (path_to_goal) and mandate
  iteration-ceiling fields this session's dependency set doesn't carry.
- **§13 Standard Mode Conformance / §14 GEE Orchestration Mode** — not
  built; this pass covers the governance loop itself, not the
  conformance self-test suite OTel-CONF-01 calls for.

These are scoped-out, not silently dropped — same posture as Step 6
(KIA)'s 7HP+8edge scoped corpus rather than the full 20+21 pattern.
