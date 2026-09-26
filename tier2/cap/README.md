# CAP — Constitutional AI Protocol

Sample TypeScript implementation of `draft-sato-soos-cap-04` (Tier 2).

CAP is the tiered, prohibition-only policy layer that governs what an
agent may actually do. Every proposed action runs through the six-step
CEE (Constitutional Evaluation Engine) protocol: a Tier 0-A absolute
pre-pass, Tier 0-B clearance check, a catalog-suspension check, Tier 1
(jurisdictional) evaluation, Tier 2 (operator) evaluation, and PERMIT
fallthrough if nothing forbids the action. No tier can grant permission —
each tier can only narrow what the tier above it already allows.

**Read this before assuming CAP "runs Cedar": it doesn't, yet.** See
**Known gaps** below — this is not a footnote, it changes what you can
and can't claim about this module.

## Files

| File | Purpose |
|---|---|
| `types.ts` | Core types — `CapError`, `Tier0ProhibitionRecord`/`Tier1.../Tier2...`, `ProhibitionClearanceRecord`, `CatalogVersion` — and the module-level note on the Cedar engine decision |
| `cedar-semantics.ts` | `evaluateCedarPolicySet()` — the hand-modeled "forbid wins" tier semantics. **Not the real Cedar engine** — see Known gaps |
| `cee.ts` | `evaluateCee()` — the six-step CEE Evaluation Protocol (§6.2), producing all ten defined outputs (PERMIT, CONSTITUTIONAL_VIOLATION, SUSPENDED, TIER_0B_PCR_ACTIVE, JURISDICTIONAL_CONFLICT, TIER_1_DENY, TIER_1_PCR_ACTIVE, LEGAL_AMBIGUITY_DETECTED, TIER_2_DENY, SESSION_SUSPEND) plus the agent-facing `GOVERNANCE_SUSPENDED` error |
| `catalog.ts` | Cedar Policy Conflict Resolution Rule (§8.7, `CONF-CAP-CONFLICT-01/02/03`), Catalog Load Validation (§8.8), and the four-phase Catalog Update Propagation workflow (§8.9 — detection/suspension/re-publication/re-activation, 30-day max suspension window) |
| `pcm.ts` | Prohibition Clearance Mechanism — Mode 1/2 clearance, the five-class unclearable floor, `ClearanceRegistry` with expiry |
| `consent.ts` | MJWT `consent_scope` → Cedar context population, fail-closed, with the no-agent-override guarantee (§5.4, `CONF-CAP-CONSENT-01`) |
| `violation-handling.ts` | CAP Violation Handling — AI-initiated vs. human-directed violations, `APPROVE_WITH_LEGAL_BASIS` (with the Tier-0-A-never exclusion), session-suspension threshold |
| `ptd.ts` | GEC Policy Transparency Disclosure — tier disclosure rules, all four `CAP_TRANSPARENCY_VIOLATION` triggers, regulatory-override prohibition |
| `jurisdictional-conflict.ts` | Jurisdictional Conflict Resolution — three resolution methods, HEM Class 5 decision-type constraints |
| `otel.ts` | Five-attribute OTel span emission (§13.5, `CONF-CAP-OTEL-01/02`). **Validates and returns attributes — does not emit to GAR or any real telemetry pipeline** — see Known gaps |
| `demo.ts` | End-to-end walkthrough exercising all of the above |

## Quick start

```bash
tsx demo.ts
```

No external dependencies — this module imports only Node's built-in `node:fs` and its own local files.

## Known gaps

**CAP does not run the real Cedar policy engine.** `draft-sato-soos-cap-04`
specifies Cedar as CAP's policy engine. This module does not integrate
`@cedar-policy/cedar-wasm` — that decision (`OQ-SC-02`: WASM build vs.
native Rust via N-API) is still genuinely open. Instead, `cedar-semantics.ts`
hand-models Cedar's "forbid wins" tier-conflict semantics directly as a
typed TypeScript function. This is tested and correct *as a model of the
intended outcome* — `CONF-CAP-CONFLICT-01/02/03` and the full tier-ordering
behavior are exercised against the adversarial corpus below — but no real
`.cedar` policy file is parsed or evaluated anywhere in this module.
`evaluateCedarPolicySet()` in `cedar-semantics.ts` is the single, isolated
function that would be replaced once `OQ-SC-02` is resolved; nothing else
in CAP would need to change.

**CAP does not write to GAR.** `emitCapOtelSpan()` validates that all five
required `soos.cap.*` attributes are present and returns them — it does
not call into GAR's real log, and `demo.ts` never imports `GARLog` or
anything from `gar-core`. See the top-level README's "A note on
integration" section — this is one instance of a pattern across the whole
release, not unique to CAP.

**Otherwise: no logged spec-drift items as of this release.** This is the
most thoroughly adversarially-tested module in the set — 7 happy-path and
11 edge/adversarial logs, covering all ten CEE outputs, all five Tier 0-A
classes (including the three `-04` additions: MANIPULATION,
PERFORMED_EMOTION, BIOMETRIC_SIGNAL_INFERENCE), all four Tier 0-B classes,
and the full Prohibition Clearance Mechanism.

## What this sample code does NOT give you

- **Not a real Cedar evaluation.** See Known gaps above — this is the
  central caveat for this module, not a minor one.
- **Not wired to GAR or KIA.** CAP's decisions are not written to a real
  audit log in this release, and nothing in this module verifies a KIA
  signature on anything it consumes.
- No durable policy-catalog storage, no real amendment-detection polling
  against a live `amendment_detection_endpoint`, and no performance
  characteristics representative of a production deployment.
