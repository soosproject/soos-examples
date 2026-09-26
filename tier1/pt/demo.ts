/**
 * PT demo — draft-sato-soos-pt-02
 * Run: tsx tier1/pt/demo.ts
 *
 * Walks the Azusa Journey OTA booking agent through Appendix A's
 * illustrative PT evolution: baseline -> 10 sessions -> 30 sessions
 * (elevation) -> 45-day inactivity gap (decay). Scenario data drawn
 * from svl/corpus-b/pt/happy-path.json (H-15..H-20) and Appendix A
 * directly, plus edge-cases.json (E-01, E-06).
 */
import {
  computeComposite,
  computeSAS, computeJS, computeES, computePS, computeAS,
  evaluateElevation, evaluateReduction,
  decayAllDimensions,
  buildProgressiveTrustSummary,
  DEFAULT_HALF_LIFE_DAYS,
  type PTScore, type PTDimension, type PTDimensionKey,
  type IDPOutcome, type HEMOutcome, type SessionClosure, type CompensatingActionWindow, type DenyFollowUp,
} from './index';

function line(title: string) {
  console.log(`\n--- ${title} ---`);
}

function dim(score: number, session_count: number, last_signal_at: string, trend: PTDimension['trend'] = 'STABLE'): PTDimension {
  return { score, session_count, last_signal_at, trend };
}

function main() {
  const now = new Date('2026-07-08T00:00:00Z');

  // --- H-15: Baseline, zero sessions (Appendix A.1) -----------------------
  line('A.1: Baseline — new agent, zero sessions');
  const baselineKeys: PTDimensionKey[] = ['sas', 'js', 'es', 'ps', 'as'];
  const baseline: PTScore = {
    computed_at: now.toISOString(),
    dimensions: Object.fromEntries(baselineKeys.map((k) => [k, dim(0.5, 0, now.toISOString())])) as PTScore['dimensions'],
  };
  const baselineComposite = computeComposite(baseline);
  console.log(`Composite: ${baselineComposite.score.toFixed(2)}, low_confidence: ${baselineComposite.low_confidence}`);
  console.log('Human principal issues Root Mandate: mandate_ceiling 2, agent_class CLASS_2 (conservative — no history)');

  // --- H-01/02/03, H-04/05/06, H-07/08, H-09/10/11, H-12/13/14 ------------
  // computed directly from Event Stream-style signals, to show each dimension's
  // scorer working from raw signals rather than hand-entered scores.
  line('Dimension scorers — computed from raw signal shapes (not hand-entered)');
  const sasOutcomes: IDPOutcome[] = [
    { declared_confidence: 0.85, cedar_result: 'PERMIT' },  // H-01 STRONGLY_POSITIVE
    { declared_confidence: 0.90, cedar_result: 'DENY' },    // H-02 STRONGLY_NEGATIVE
    { declared_confidence: 0.95, cedar_result: 'DENY', hem_required: true }, // H-03 NEUTRAL
  ];
  console.log(`SAS from 3 raw outcomes (1 strong+, 1 strong-, 1 neutral): ${computeSAS(sasOutcomes).toFixed(2)}`);

  const jsOutcomes: HEMOutcome[] = [
    { kind: 'AGENT_ESCALATED', resolution: 'TERMINATE', resolved_in_seconds: 120 }, // H-04
    { kind: 'AGENT_ESCALATED', resolution: 'APPROVE', resolved_in_seconds: 12 },    // H-05 trivial
    { kind: 'MANDATORY' },                                                          // H-06
  ];
  console.log(`JS from 3 raw outcomes (TERMINATE, trivial APPROVE, mandatory): ${computeJS(jsOutcomes).toFixed(2)}`);

  const esClosures: SessionClosure[] = [
    { closure_reason: 'GOAL_ACHIEVED', total_iterations: 14 },  // H-07
    { closure_reason: 'KERNEL_REJECTED', total_iterations: 3 }, // H-08
  ];
  console.log(`ES from 2 raw closures (GOAL_ACHIEVED complex, KERNEL_REJECTED): ${computeES(esClosures).toFixed(2)}`);

  const psWindow: CompensatingActionWindow = { compensating_action_count: 1, externally_caused_count: 0, total_transitions: 40 }; // H-10
  console.log(`PS from raw window (1/40 compensating, CAR_threshold 0.05): ${computePS(psWindow).toFixed(2)}`);

  const asFollowUps: DenyFollowUp[] = [
    { kind: 'RETRY_SUCCESS' },           // H-12
    { kind: 'SILENT_RETRY' },            // H-13
    { kind: 'REPEATED_NO_ADAPTATION' },  // H-14
  ];
  console.log(`AS from 3 raw follow-ups (success, silent retry, no adaptation): ${computeAS(asFollowUps).toFixed(2)}`);

  // --- H-16: After 10 sessions (Appendix A.2, hand-entered per-appendix values)
  line('A.2: After 10 sessions — still low_confidence (session_count < 20)');
  const after10: PTScore = {
    computed_at: now.toISOString(),
    dimensions: {
      sas: dim(0.71, 10, now.toISOString()),
      js: dim(0.75, 10, now.toISOString()),
      es: dim(0.80, 10, now.toISOString()),
      ps: dim(0.90, 10, now.toISOString()),
      as: dim(0.85, 10, now.toISOString()),
    },
  };
  const composite10 = computeComposite(after10);
  console.log(`Composite: ${composite10.score.toFixed(2)}, low_confidence: ${composite10.low_confidence}`);
  const elevation10 = evaluateElevation(after10, composite10, { strongly_negative_signal_in_last_30_days: false, current_mandate_ceiling: 2 });
  console.log(`Elevation recommendation: ${elevation10 ? 'ISSUED (unexpected)' : 'none — low_confidence blocks evaluation, as the draft requires'}`);

  // --- H-17/H-18/H-19: After 30 sessions (Appendix A.3) — elevation --------
  line('A.3: After 30 sessions — elevation-eligible');
  const after30: PTScore = {
    computed_at: now.toISOString(),
    dimensions: {
      sas: dim(0.82, 30, now.toISOString(), 'IMPROVING'),
      js: dim(0.88, 30, now.toISOString(), 'IMPROVING'),
      es: dim(0.87, 30, now.toISOString(), 'STABLE'),
      ps: dim(0.93, 30, now.toISOString(), 'STABLE'),
      as: dim(0.91, 30, now.toISOString(), 'STABLE'),
    },
  };
  const composite30 = computeComposite(after30);
  console.log(`Composite: ${composite30.score.toFixed(2)}, low_confidence: ${composite30.low_confidence}`);
  const elevation30 = evaluateElevation(after30, composite30, { strongly_negative_signal_in_last_30_days: false, current_mandate_ceiling: 2 });
  if (elevation30) {
    console.log(`PT_RECOMMENDATION_ISSUED: ${elevation30.recommendation_type}, ceiling ${elevation30.current_mandate_ceiling} -> ${elevation30.proposed_mandate_ceiling}`);
    console.log('Human principal reviews ProgressiveTrustSummary, notes JS STRONGLY POSITIVE TERMINATE signal, APPROVES.');
    console.log('PT_RECOMMENDATION_APPLIED recorded. New Root Mandate issued with mandate_ceiling: 3.');
  }

  const summary30 = buildProgressiveTrustSummary('ota-booking-agent-v2', after30, 90);
  console.log(`\nProgressiveTrustSummary composite plain_language: "${summary30.composite.plain_language}"`);
  console.log(`  JS: "${summary30.dimensions.js.plain_language}"`);

  // --- H-20: 45-day inactivity gap (Appendix A.4) — decay -------------------
  line('A.4: 45-day inactivity gap — trust decay, JS matches Appendix A exactly');
  const lastSignal = new Date(now.getTime() - 45 * 24 * 60 * 60 * 1000).toISOString();
  const preDecay: PTScore = {
    computed_at: lastSignal,
    dimensions: {
      sas: dim(0.82, 30, lastSignal),
      js: dim(0.88, 30, lastSignal),
      es: dim(0.87, 30, lastSignal),
      ps: dim(0.93, 30, lastSignal),
      as: dim(0.91, 30, lastSignal),
    },
  };
  const decayed = decayAllDimensions(preDecay, now, DEFAULT_HALF_LIFE_DAYS);
  for (const k of Object.keys(decayed.dimensions) as PTDimensionKey[]) {
    console.log(`  ${k.toUpperCase()}: ${decayed.dimensions[k].score.toFixed(3)} (half-life ${DEFAULT_HALF_LIFE_DAYS[k]}d)`);
  }
  console.log('(JS half-life is 45 days, elapsed is exactly 45 days -> decay factor 0.5 -> matches Appendix A.4\'s 0.69 exactly)');

  const decayedComposite = computeComposite(decayed);
  const reductionAfterDecay = evaluateReduction(decayed, decayedComposite, { strongly_negative_signal_in_last_30_days: false, current_mandate_ceiling: 3 });
  console.log(`Composite after decay: ${decayedComposite.score.toFixed(2)}`);
  console.log(`Reduction recommendation: ${reductionAfterDecay ? 'ISSUED' : 'none — all dimensions still above REDUCTION_THRESHOLD, mandate ceiling retained at 3'}`);

  // --- E-06: urgency REQUIRED overrides auto_apply config -------------------
  line('E-06: HEM_TIMEOUT at REQUIRED urgency — human approval mandatory despite auto_apply config');
  const stronglyNegativeReduction = evaluateReduction(
    decayed, decayedComposite,
    { strongly_negative_signal_in_last_30_days: true, current_mandate_ceiling: 3 },
    'HEM_TIMEOUT_REQUIRED',
  );
  console.log(`urgency: ${stronglyNegativeReduction?.urgency}, auto_apply: ${stronglyNegativeReduction?.auto_apply} (auto_apply MUST be false at REQUIRED, regardless of operator config)`);

  console.log('\nDemo complete. Full happy-path (20) and edge-case (17) corpora: svl/corpus-b/pt/');
}

main();
