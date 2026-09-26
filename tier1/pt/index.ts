/**
 * Progressive Trust (PT) — SOOS behavioral trust model.
 * Implements draft-sato-soos-pt-02.
 *
 * PT measures five behavioral properties of an agent from the
 * tamper-evident GEC-signed Event Stream: Self-Assessment (SAS),
 * Judgment (JS), Effectiveness (ES), Precision (PS), and
 * Adaptability (AS). PT-02 §5.1: "The PT Score is a structured,
 * multi-dimensional measurement. It is NOT a single scalar value."
 *
 * NOTE ON PLAN DRIFT: SOOS_SampleCode_Plan_v6.md's Step 4
 * "what to tell your coding assistant" block describes a different,
 * stale PT model (trust_band state machine; SAS/JS/ES/PS/AS defined
 * as scope-adherence/judgement-stability/escalation-sensitivity/
 * principal-signal-responsiveness/anomaly-score). This file is built
 * against the actual draft-sato-soos-pt-02 text, where the same five
 * letters mean Self-Assessment/Judgment/Effectiveness/Precision/
 * Adaptability. See MJWT-02_RelatedWork_Draft.md for the precedent
 * on how plan/draft drift is handled — draft text is authoritative.
 */

// ---------------------------------------------------------------------------
// SDB markers — see svl/corpus-b/pt/edge-cases.json E-15/E-16/E-17 for detail
// ---------------------------------------------------------------------------
// SDB-PT-01: decay formula given only as four bounding properties, not an
//            exact function. This sample uses standard exponential-to-baseline
//            decay: score(t) = baseline + (score0 - baseline) * 0.5^(t/halflife)
// SDB-PT-02: SAS/JS/ES/AS defined by qualitative signal tables, not a formula
//            (contrast PS, which has an explicit CAR_score formula in §5.5).
//            This sample maps signal categories to numeric weights.
// SDB-PT-03: ELEVATION_THRESHOLD / REDUCTION_THRESHOLD / DECAY_REDUCTION_THRESHOLD
//            have no stated default (unlike CAR_threshold=0.05, PT Baseline=0.5).
//            This sample's defaults are illustrative only, not normative.

export const PT_BASELINE = 0.5; // §6.2(b), stated default
export const CAR_THRESHOLD_DEFAULT = 0.05; // §5.5, stated default
export const LOW_CONFIDENCE_SESSION_FLOOR = 20; // §5.7, §8.2(b), stated

// SDB-PT-03 — illustrative only, draft states no default.
export const ELEVATION_THRESHOLD_DEFAULT = 0.8;
export const REDUCTION_THRESHOLD_DEFAULT = 0.55;
export const DECAY_REDUCTION_THRESHOLD_DEFAULT = 0.45;

export const DEFAULT_HALF_LIFE_DAYS: Record<PTDimensionKey, number> = {
  sas: 60, js: 45, es: 30, ps: 30, as: 45, // §6.3, all stated defaults
};

export const DEFAULT_WEIGHTS: Record<PTDimensionKey, number> = {
  sas: 0.30, js: 0.25, es: 0.20, ps: 0.15, as: 0.10, // §5.7, all stated defaults
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type PTDimensionKey = 'sas' | 'js' | 'es' | 'ps' | 'as';
export type Trend = 'IMPROVING' | 'STABLE' | 'DECLINING';

export interface PTDimension {
  score: number;              // [0.0, 1.0]
  session_count: number;
  last_signal_at: string;     // ISO 8601
  trend: Trend;
}

export interface PTScore {
  dimensions: Record<PTDimensionKey, PTDimension>;
  computed_at: string;
}

export interface CompositeScore {
  score: number;
  confidence: number;
  low_confidence: boolean;
}

/** §5.7 composite score, plus §8.2/§8.3 elevation/reduction machinery. */
export function computeComposite(
  pt: PTScore,
  weights: Record<PTDimensionKey, number> = DEFAULT_WEIGHTS,
): CompositeScore {
  const keys = Object.keys(pt.dimensions) as PTDimensionKey[];
  const weighted = keys.reduce((sum, k) => sum + pt.dimensions[k].score * weights[k], 0);
  const totalWeight = keys.reduce((sum, k) => sum + weights[k], 0);
  const score = totalWeight > 0 ? weighted / totalWeight : PT_BASELINE;

  const minSessionCount = Math.min(...keys.map((k) => pt.dimensions[k].session_count));
  const low_confidence = minSessionCount < LOW_CONFIDENCE_SESSION_FLOOR;
  // confidence is a simple monotone function of session_count, capped at 1.0 —
  // draft specifies the low_confidence *flag* precisely (§5.7) but not a
  // continuous confidence formula, so this scaling is illustrative (rides on
  // the same SDB-PT-03 gap as the thresholds: "how much evidence is enough"
  // is operator/implementation judgment beyond the low_confidence cutoff).
  const confidence = Math.min(1.0, minSessionCount / (LOW_CONFIDENCE_SESSION_FLOOR * 2));

  return { score, confidence, low_confidence };
}

// ---------------------------------------------------------------------------
// Signal-to-score mapping (SDB-PT-02) — used by SAS, JS, ES, AS
// ---------------------------------------------------------------------------

export type SignalCategory =
  | 'STRONGLY_POSITIVE' | 'POSITIVE' | 'NEUTRAL'
  | 'MILDLY_NEGATIVE' | 'NEGATIVE' | 'STRONGLY_NEGATIVE';

const SIGNAL_WEIGHT: Record<SignalCategory, number> = {
  STRONGLY_POSITIVE: 1.0,
  POSITIVE: 0.5,
  NEUTRAL: 0.0,
  MILDLY_NEGATIVE: -0.5,
  NEGATIVE: -0.75,
  STRONGLY_NEGATIVE: -1.0,
};

/** Rolling mean of signal weights, rescaled from [-1,1] to [0,1]. SDB-PT-02. */
export function scoreFromSignals(signals: SignalCategory[]): number {
  if (signals.length === 0) return PT_BASELINE;
  const mean = signals.reduce((sum, s) => sum + SIGNAL_WEIGHT[s], 0) / signals.length;
  return (mean + 1) / 2;
}

// ---------------------------------------------------------------------------
// Dimension 1 — SAS, Self-Assessment Score (§5.2)
// ---------------------------------------------------------------------------

export interface IDPOutcome {
  declared_confidence: number;
  cedar_result: 'PERMIT' | 'DENY';
  hem_required?: boolean;
}

/** Classifies a single IDP outcome per the §5.2 SAS signal table. */
export function classifySASSignal(o: IDPOutcome): SignalCategory {
  if (o.cedar_result === 'DENY' && o.hem_required) return 'NEUTRAL'; // special case, §5.2
  const c = o.declared_confidence;
  if (o.cedar_result === 'PERMIT') {
    if (c >= 0.80) return 'STRONGLY_POSITIVE';
    if (c >= 0.60) return 'POSITIVE';
    return 'NEUTRAL';
  }
  // DENY
  if (c >= 0.80) return 'STRONGLY_NEGATIVE';
  if (c >= 0.60) return 'NEGATIVE';
  return 'NEUTRAL';
}

export function computeSAS(outcomes: IDPOutcome[]): number {
  return scoreFromSignals(outcomes.map(classifySASSignal));
}

// ---------------------------------------------------------------------------
// Dimension 2 — JS, Judgment Score (§5.3)
// ---------------------------------------------------------------------------

export type HEMOutcome =
  | { kind: 'AGENT_ESCALATED'; resolution: 'APPROVE' | 'TERMINATE' | 'REDIRECT'; resolved_in_seconds: number }
  | { kind: 'MANDATORY' }
  | { kind: 'PROXIMITY_TRIGGERED' }
  | { kind: 'TIMEOUT'; urgency: 'ADVISORY' | 'RECOMMENDED' | 'REQUIRED' }
  | { kind: 'UNDER_ESCALATION' }; // uncertainty_flags present, hem_urgency ADVISORY across multiple transitions

const T_TRIVIAL_SECONDS_DEFAULT = 30; // §5.3, stated default

export function classifyJSSignal(o: HEMOutcome, tTrivialSeconds = T_TRIVIAL_SECONDS_DEFAULT): SignalCategory {
  switch (o.kind) {
    case 'AGENT_ESCALATED':
      if (o.resolution === 'TERMINATE') return 'STRONGLY_POSITIVE';
      if (o.resolution === 'REDIRECT') return 'POSITIVE';
      // APPROVE
      return o.resolved_in_seconds < tTrivialSeconds ? 'MILDLY_NEGATIVE' : 'POSITIVE';
    case 'MANDATORY':
    case 'PROXIMITY_TRIGGERED':
      return 'NEUTRAL';
    case 'TIMEOUT':
      return o.urgency === 'REQUIRED' ? 'STRONGLY_NEGATIVE' : 'NEUTRAL';
    case 'UNDER_ESCALATION':
      return 'MILDLY_NEGATIVE';
  }
}

export function computeJS(outcomes: HEMOutcome[]): number {
  return scoreFromSignals(outcomes.map((o) => classifyJSSignal(o)));
}

// ---------------------------------------------------------------------------
// Dimension 3 — ES, Effectiveness Score (§5.4)
// ---------------------------------------------------------------------------

export type ClosureReason =
  | 'GOAL_ACHIEVED' | 'MANDATE_EXPIRED' | 'AGENT_DECLARED'
  | 'GEE_CLOSED' | 'HEM_TERMINATED' | 'KERNEL_REJECTED' | 'MANDATE_REVOKED';

export interface SessionClosure {
  closure_reason: ClosureReason;
  total_iterations: number;
}

export function classifyESSignal(c: SessionClosure): SignalCategory {
  switch (c.closure_reason) {
    case 'GOAL_ACHIEVED': return 'POSITIVE';
    case 'MANDATE_EXPIRED':
    case 'HEM_TERMINATED': return 'MILDLY_NEGATIVE';
    case 'AGENT_DECLARED':
    case 'GEE_CLOSED': return 'NEUTRAL';
    case 'KERNEL_REJECTED':
    case 'MANDATE_REVOKED': return 'STRONGLY_NEGATIVE';
  }
}

const COMPLEXITY_MULTIPLIER_ITERATIONS_FLOOR = 10; // §5.4, stated
const COMPLEXITY_MULTIPLIER = 1.5; // magnitude not stated by draft — illustrative, part of SDB-PT-02

/** ES is weighted by goal complexity (§5.4): sessions with total_iterations >= 10 count more. */
export function computeES(closures: SessionClosure[]): number {
  if (closures.length === 0) return PT_BASELINE;
  let weightedSum = 0;
  let totalWeight = 0;
  for (const c of closures) {
    const w = c.total_iterations >= COMPLEXITY_MULTIPLIER_ITERATIONS_FLOOR ? COMPLEXITY_MULTIPLIER : 1.0;
    weightedSum += SIGNAL_WEIGHT[classifyESSignal(c)] * w;
    totalWeight += w;
  }
  const mean = weightedSum / totalWeight;
  return (mean + 1) / 2;
}

// ---------------------------------------------------------------------------
// Dimension 4 — PS, Precision Score (§5.5) — exact formula given by the draft
// ---------------------------------------------------------------------------

export interface CompensatingActionWindow {
  compensating_action_count: number;
  externally_caused_count: number; // excluded from PS per draft's SHOULD provision
  total_transitions: number;
}

export function computePS(w: CompensatingActionWindow, carThreshold = CAR_THRESHOLD_DEFAULT): number {
  if (w.total_transitions === 0) return PT_BASELINE;
  const attributable = Math.max(0, w.compensating_action_count - w.externally_caused_count);
  const compensating_action_rate = attributable / w.total_transitions;
  return 1.0 - Math.min(1.0, compensating_action_rate / carThreshold); // §5.5, exact formula
}

// ---------------------------------------------------------------------------
// Dimension 5 — AS, Adaptability Score (§5.6)
// ---------------------------------------------------------------------------

export type DenyFollowUp =
  | { kind: 'RETRY_SUCCESS' }
  | { kind: 'RETRY_NEW_DENY_CODE' }
  | { kind: 'RETRY_SAME_DENY_CODE' }
  | { kind: 'SILENT_RETRY' } // CONF-AEP-07 violation
  | { kind: 'SESSION_CLOSED' }
  | { kind: 'REPEATED_NO_ADAPTATION' };

export function classifyASSignal(f: DenyFollowUp): SignalCategory {
  switch (f.kind) {
    case 'RETRY_SUCCESS': return 'POSITIVE';
    case 'RETRY_NEW_DENY_CODE':
    case 'RETRY_SAME_DENY_CODE':
    case 'SESSION_CLOSED': return 'NEUTRAL';
    case 'SILENT_RETRY': return 'MILDLY_NEGATIVE';
    case 'REPEATED_NO_ADAPTATION': return 'NEGATIVE';
  }
}

export function computeAS(followUps: DenyFollowUp[]): number {
  return scoreFromSignals(followUps.map(classifyASSignal));
}

// ---------------------------------------------------------------------------
// Trend (session-window comparison, N default 10 per §5.1)
// ---------------------------------------------------------------------------

const TREND_WINDOW_DEFAULT = 10;
const TREND_EPSILON = 0.03; // magnitude not stated by draft — illustrative, SDB-PT-02

export function computeTrend(recentScores: number[], windowSize = TREND_WINDOW_DEFAULT): Trend {
  const window = recentScores.slice(-windowSize);
  if (window.length < 2) return 'STABLE';
  const first = window[0]!;
  const last = window[window.length - 1]!;
  const delta = last - first;
  if (delta > TREND_EPSILON) return 'IMPROVING';
  if (delta < -TREND_EPSILON) return 'DECLINING';
  return 'STABLE';
}

// ---------------------------------------------------------------------------
// Trust Decay Model (§6) — SDB-PT-01
// ---------------------------------------------------------------------------

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

export function decayDimension(dim: PTDimension, now: Date, halfLifeDays: number): PTDimension {
  const daysSince = (now.getTime() - Date.parse(dim.last_signal_at)) / (1000 * 60 * 60 * 24);
  return { ...dim, score: applyDecay(dim.score, daysSince, halfLifeDays) };
}

export function decayAllDimensions(pt: PTScore, now: Date, halfLives: Record<PTDimensionKey, number> = DEFAULT_HALF_LIFE_DAYS): PTScore {
  const keys = Object.keys(pt.dimensions) as PTDimensionKey[];
  const dimensions = {} as Record<PTDimensionKey, PTDimension>;
  for (const k of keys) {
    dimensions[k] = decayDimension(pt.dimensions[k], now, halfLives[k]);
  }
  return { dimensions, computed_at: now.toISOString() };
}

// ---------------------------------------------------------------------------
// PT-Informed Mandate Management — Elevation / Reduction (§8)
// ---------------------------------------------------------------------------

export interface EvaluationContext {
  strongly_negative_signal_in_last_30_days: boolean;
  current_mandate_ceiling: 1 | 2 | 3;
  elevation_threshold?: number;
  reduction_threshold?: number;
  decay_reduction_threshold?: number;
}

export interface PTRecommendation {
  recommendation_type: 'ELEVATION' | 'REDUCTION';
  current_mandate_ceiling: 1 | 2 | 3;
  proposed_mandate_ceiling: 1 | 2 | 3;
  urgency?: 'ADVISORY' | 'RECOMMENDED' | 'REQUIRED';
  trigger?: string;
  auto_apply?: boolean;
  recommendation_rationale: string;
}

/** §8.2 — all four conditions (a)-(d) must hold. */
export function evaluateElevation(
  pt: PTScore,
  composite: CompositeScore,
  ctx: EvaluationContext,
): PTRecommendation | null {
  const threshold = ctx.elevation_threshold ?? ELEVATION_THRESHOLD_DEFAULT;
  const keys = Object.keys(pt.dimensions) as PTDimensionKey[];

  const allAboveThreshold = keys.every((k) => pt.dimensions[k].score >= threshold); // (a)
  if (composite.low_confidence) return null; // (b)
  const noDeclining = keys.every((k) => pt.dimensions[k].trend !== 'DECLINING'); // (c)
  const noRecentStronglyNegative = !ctx.strongly_negative_signal_in_last_30_days; // (d)

  if (!(allAboveThreshold && noDeclining && noRecentStronglyNegative)) return null;
  if (ctx.current_mandate_ceiling >= 3) return null;

  return {
    recommendation_type: 'ELEVATION',
    current_mandate_ceiling: ctx.current_mandate_ceiling,
    proposed_mandate_ceiling: (ctx.current_mandate_ceiling + 1) as 1 | 2 | 3,
    recommendation_rationale: `All five dimensions >= ${threshold}, session_count sufficient, no declining trend, no recent strongly negative signal.`,
  };
}

/** §8.3 — any of (a)-(c) trigger a reduction recommendation. */
export function evaluateReduction(
  pt: PTScore,
  composite: CompositeScore,
  ctx: EvaluationContext,
  strongestNegativeTrigger?: 'MANDATE_REVOKED' | 'KERNEL_REJECTED' | 'HEM_TIMEOUT_REQUIRED',
): PTRecommendation | null {
  const reductionThreshold = ctx.reduction_threshold ?? REDUCTION_THRESHOLD_DEFAULT;
  const decayThreshold = ctx.decay_reduction_threshold ?? DECAY_REDUCTION_THRESHOLD_DEFAULT;
  const keys = Object.keys(pt.dimensions) as PTDimensionKey[];

  const belowThreshold = keys.some((k) => pt.dimensions[k].score < reductionThreshold); // (a)
  const stronglyNegative = strongestNegativeTrigger !== undefined; // (b)
  const decayedBelow = composite.score < decayThreshold; // (c)

  if (!(belowThreshold || stronglyNegative || decayedBelow)) return null;
  if (ctx.current_mandate_ceiling <= 1) return null;

  const urgency = stronglyNegative ? 'REQUIRED' : belowThreshold ? 'RECOMMENDED' : 'ADVISORY';
  // §8.3: auto_apply only permitted at ADVISORY urgency, never RECOMMENDED/REQUIRED.
  const auto_apply = urgency === 'ADVISORY';

  return {
    recommendation_type: 'REDUCTION',
    current_mandate_ceiling: ctx.current_mandate_ceiling,
    proposed_mandate_ceiling: (ctx.current_mandate_ceiling - 1) as 1 | 2 | 3,
    urgency,
    trigger: strongestNegativeTrigger ?? (belowThreshold ? 'DIMENSION_BELOW_THRESHOLD' : 'DECAY_REDUCTION_THRESHOLD'),
    auto_apply,
    recommendation_rationale: stronglyNegative
      ? `Strongly negative signal: ${strongestNegativeTrigger}.`
      : belowThreshold
        ? `A PT dimension fell below ${reductionThreshold}.`
        : `Composite decayed below ${decayThreshold}.`,
  };
}

// ---------------------------------------------------------------------------
// ProgressiveTrustSummary (§7.2)
// ---------------------------------------------------------------------------

export interface ProgressiveTrustSummary {
  agent_id: string;
  computed_at: string;
  session_count: number;
  measurement_window_days: number;
  dimensions: Record<PTDimensionKey, { score: number; trend: Trend; session_count: number; last_signal_at: string; plain_language: string }>;
  composite: CompositeScore & { plain_language: string };
}

const PLAIN_LANGUAGE: Record<PTDimensionKey, (d: PTDimension) => string> = {
  sas: (d) => `Agent confidence calibration is ${d.score >= 0.8 ? 'well-calibrated' : d.score >= 0.6 ? 'reasonably calibrated' : 'poorly calibrated'} (${d.session_count} sessions).`,
  js: (d) => `Agent escalation judgment is ${d.score >= 0.8 ? 'strong' : d.score >= 0.6 ? 'adequate' : 'weak'} (${d.session_count} sessions).`,
  es: (d) => `Agent reaches its declared goal state in most sessions (${d.session_count} sessions).`,
  ps: (d) => `Agent ${d.score >= 0.9 ? 'rarely' : d.score >= 0.7 ? 'occasionally' : 'frequently'} requires compensating actions.`,
  as: (d) => `Agent ${d.score >= 0.8 ? 'consistently' : 'inconsistently'} adapts to denied transitions.`,
};

export function buildProgressiveTrustSummary(
  agent_id: string,
  pt: PTScore,
  windowDays: number,
  weights: Record<PTDimensionKey, number> = DEFAULT_WEIGHTS,
): ProgressiveTrustSummary {
  const keys = Object.keys(pt.dimensions) as PTDimensionKey[];
  const composite = computeComposite(pt, weights);
  const totalSessions = Math.max(...keys.map((k) => pt.dimensions[k].session_count));

  const dimensions = {} as ProgressiveTrustSummary['dimensions'];
  for (const k of keys) {
    const d = pt.dimensions[k];
    dimensions[k] = { score: d.score, trend: d.trend, session_count: d.session_count, last_signal_at: d.last_signal_at, plain_language: PLAIN_LANGUAGE[k](d) };
  }

  return {
    agent_id,
    computed_at: pt.computed_at,
    session_count: totalSessions,
    measurement_window_days: windowDays,
    dimensions,
    composite: {
      ...composite,
      plain_language: `This agent has a ${composite.score >= 0.8 ? 'strong' : composite.score >= 0.6 ? 'moderate' : 'limited'} behavioral track record across ${totalSessions} sessions.`,
    },
  };
}
