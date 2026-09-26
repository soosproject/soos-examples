import { HemError } from "./types.js";

/** §8.3 Table 1 — normative default thresholds, with operator-configurable bounds. */
export const HRS_THRESHOLDS = {
  HRS_FATIGUE_FLOOR: { default: 0.4, min: 0.2, max: 0.6 },
  HRS_EMOTIONAL_ADVISORY_FLOOR: { default: 0.35, min: 0.2, max: 0.5 },
  HRS_WARNING_THRESHOLD: { default: 0.55, min: 0.35, max: 0.7 },
  HRS_NOMINAL_FLOOR: { default: 0.7, min: 0.6, max: 0.85 },
} as const;

export interface HrsWeights {
  w1_latency_trend: number;
  w2_decision_variance: number;
  w3_drr_completion: number;
  w4_session_duration: number;
  w5_emotional_proxy: number;
}

/** §8.2 default weights (D1 .25, D2 .20, D3 .20, D4 .20, D5 .15). */
export const DEFAULT_HRS_WEIGHTS: HrsWeights = {
  w1_latency_trend: 0.25,
  w2_decision_variance: 0.2,
  w3_drr_completion: 0.2,
  w4_session_duration: 0.2,
  w5_emotional_proxy: 0.15,
};

/** CONF-HEM-HRS-01/02: weights MUST sum to 1.0, each MUST be in [0.05, 0.50]. */
export function validateHrsWeights(w: HrsWeights): void {
  const sum =
    w.w1_latency_trend + w.w2_decision_variance + w.w3_drr_completion + w.w4_session_duration + w.w5_emotional_proxy;
  if (Math.abs(sum - 1.0) > 1e-9) {
    throw new HemError("HEM_WEIGHT_CONFIG_ERROR", `HRS_WEIGHT_CONFIGURATION_ERROR: weights sum to ${sum}, MUST equal 1.0`);
  }
  for (const [name, v] of Object.entries(w)) {
    if (v < 0.05 || v > 0.5) {
      throw new HemError("HEM_WEIGHT_CONFIG_ERROR", `HRS_WEIGHT_CONFIGURATION_ERROR: ${name}=${v} outside [0.05, 0.50]`);
    }
  }
}

export interface HrsInputs {
  // D1: Response Latency Trend
  currentLatencySeconds: number;
  baselineLatencySeconds: number;
  rubberStampFloorSeconds: number; // default 3s

  // D2: Decision Variance
  runLengthOfIdenticalDecisions: number; // capped at 10 per §8.2

  // D3: DRR Completion Rate
  drrRecommendedSlots: number;
  drrSubmittedCount: number;

  // D4: Session Duration
  sessionElapsedMinutes: number;
  maxSessionMinutes: number;

  // D5: Emotional State Proxy — three adverse signals per §8.2
  highResponseTimeVariance: boolean;
  negativeDrrSentiment: boolean;
  explicitSelfReport: boolean;
}

export interface HrsResult {
  hrs_value: number;
  d1_score: number;
  d2_score: number;
  d3_score: number;
  d4_score: number;
  d5_score: number;
}

function clamp01(x: number): number {
  return Math.max(0, Math.min(1, x));
}

/** §8.2 D1 — linear interpolation between baseline (1.0) and rubber-stamp floor (0.0). */
function scoreD1(i: HrsInputs): number {
  const { currentLatencySeconds, baselineLatencySeconds, rubberStampFloorSeconds } = i;
  if (baselineLatencySeconds <= rubberStampFloorSeconds) return 1.0; // degenerate baseline, avoid divide-by-zero
  const t = (currentLatencySeconds - rubberStampFloorSeconds) / (baselineLatencySeconds - rubberStampFloorSeconds);
  return clamp01(t);
}

/** §8.2 D2 — 1 - (run_length_of_identical_decisions / 10). */
function scoreD2(i: HrsInputs): number {
  return clamp01(1 - Math.min(i.runLengthOfIdenticalDecisions, 10) / 10);
}

/** §8.2 D3 — proportion of RECOMMENDED DRR slots actually submitted. */
function scoreD3(i: HrsInputs): number {
  if (i.drrRecommendedSlots <= 0) return 1.0; // no RECOMMENDED slots — nothing to penalize
  return clamp01(i.drrSubmittedCount / i.drrRecommendedSlots);
}

/** §8.2 D4 — linear interpolation; 1.0 within first quarter of max, 0.0 at/after max. */
function scoreD4(i: HrsInputs): number {
  const quarter = i.maxSessionMinutes / 4;
  if (i.sessionElapsedMinutes <= quarter) return 1.0;
  if (i.sessionElapsedMinutes >= i.maxSessionMinutes) return 0.0;
  const t = (i.sessionElapsedMinutes - quarter) / (i.maxSessionMinutes - quarter);
  return clamp01(1 - t);
}

/** §8.2 D5 — 1 - (adverse_signals_count / 3). */
function scoreD5(i: HrsInputs): number {
  const count = [i.highResponseTimeVariance, i.negativeDrrSentiment, i.explicitSelfReport].filter(Boolean).length;
  return clamp01(1 - count / 3);
}

/** CONF-HEM-HRS-03: computed before every APPROVE/APPROVE_WITH_CONSTRAINTS decision. */
export function computeHrs(inputs: HrsInputs, weights: HrsWeights = DEFAULT_HRS_WEIGHTS): HrsResult {
  validateHrsWeights(weights);
  const d1 = scoreD1(inputs);
  const d2 = scoreD2(inputs);
  const d3 = scoreD3(inputs);
  const d4 = scoreD4(inputs);
  const d5 = scoreD5(inputs);
  const hrs_value =
    weights.w1_latency_trend * d1 +
    weights.w2_decision_variance * d2 +
    weights.w3_drr_completion * d3 +
    weights.w4_session_duration * d4 +
    weights.w5_emotional_proxy * d5;
  return { hrs_value, d1_score: d1, d2_score: d2, d3_score: d3, d4_score: d4, d5_score: d5 };
}

export type HrsBand = "NOMINAL" | "WARNING" | "FATIGUE_FLOOR_BREACH";

/** §8.3 — banding for logging/UX; does NOT itself decide whether HEM-FAT-1 fires (secondary signals required, §7.5.2). */
export function bandHrs(hrs: number): HrsBand {
  if (hrs < HRS_THRESHOLDS.HRS_FATIGUE_FLOOR.default) return "FATIGUE_FLOOR_BREACH";
  if (hrs < HRS_THRESHOLDS.HRS_WARNING_THRESHOLD.default) return "WARNING";
  return "NOMINAL";
}
