# PT — Progressive Trust

TypeScript sample implementation of Progressive Trust (PT), the SOOS behavioral
trust model that measures five properties of an agent's governed behavior from
the tamper-evident GEC-signed Event Stream, and translates them into
human-approved authority evolution recommendations.

Draft: [draft-sato-soos-pt-02](https://datatracker.ietf.org/doc/draft-sato-soos-pt-02/)

## Install

No external dependencies.

## What the demo shows

`demo.ts` walks the Azusa Journey OTA booking agent through Appendix A's
illustrative PT evolution: baseline (zero sessions, all dimensions at 0.5) →
10 sessions (still `low_confidence`, no elevation possible) → 30 sessions
(elevation-eligible, `PT_RECOMMENDATION_ISSUED`, human-approved ceiling 2→3)
→ a 45-day inactivity gap (trust decay). It also shows each dimension scorer
computing from raw Event Stream-shaped signals rather than hand-entered
numbers, and one edge case: a `HEM_TIMEOUT` at `REQUIRED` urgency, which must
require human approval even when an operator has configured `auto_apply`.

```
tsx tier1/pt/demo.ts
```

The decay computation is checked against Appendix A.4's illustrative JS value
(0.69 after a 45-day gap on a 45-day half-life) and matches exactly.

## Core snippet

```typescript
/**
 * Exponential-to-baseline decay. Satisfies all four normative properties
 * in §6.2 exactly: monotone (a), floor at baseline (b), >=50% gap
 * reduction at exactly one half-life (c), and composes with signal
 * reset (d) since callers restart the clock from the post-signal score.
 */
export function applyDecay(score: number, daysSinceSignal: number, halfLifeDays: number): number {
  if (daysSinceSignal <= 0) return score;
  const decayFactor = Math.pow(0.5, daysSinceSignal / halfLifeDays);
  return PT_BASELINE + (score - PT_BASELINE) * decayFactor;
}
```

## Note on plan drift

`SOOS_SampleCode_Plan_v6.md`'s Step 4 "what to tell your coding assistant" block
describes a different, stale PT model (a `trust_band` state machine; SAS/JS/ES/PS/AS
glossed as scope-adherence/judgement-stability/escalation-sensitivity/principal-signal-
responsiveness/anomaly-score). This implementation is built against the actual
`draft-sato-soos-pt-02` text, where the same five letters mean Self-Assessment,
Judgment, Effectiveness, Precision, and Adaptability — a materially different model.
See `MJWT-02_RelatedWork_Draft.md`'s handling of the `delegation_chain` question for
the precedent: draft text is authoritative over the plan's coding-assistant prompts.

## Spec gaps found (logged, not silently resolved)

- **SDB-PT-01** — decay formula given only as four bounding properties (§6.2), not
  an exact function. Implemented as standard exponential-to-baseline decay.
- **SDB-PT-02** — SAS/JS/ES/AS defined by qualitative signal category tables, not a
  numeric formula (contrast PS, which has one). Implemented as a signal-weight mapping.
- **SDB-PT-03** — `ELEVATION_THRESHOLD`, `REDUCTION_THRESHOLD`, and
  `DECAY_REDUCTION_THRESHOLD` have no stated default (unlike `CAR_threshold=0.05`).
  Sample defaults are illustrative only.
