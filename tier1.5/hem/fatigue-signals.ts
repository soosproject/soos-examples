/**
 * §7.5.2 HEM-FAT-1 secondary signals — this is the exact list the plan's
 * SVL Phase A question asked about ("What constitutes a secondary signal?
 * If the list is not normative → SDB-HEM-01"). The draft DOES enumerate
 * it normatively as three precise, independently-computable conditions.
 * No SDB-HEM-01 gap exists — this resolves cleanly, unlike the plan's
 * speculative framing assumed.
 */
export interface FatigueSecondarySignalInputs {
  /** (a) latency drop vs. session baseline over last 5 consecutive approvals, as a fraction (0.65 = 65% drop). */
  latencyDropFractionLast5: number;
  /** (b) 3+ consecutive APPROVE decisions each under 10 seconds. */
  threeConsecutiveFastApprovals: boolean;
  /** (c) DRR-to-APPROVE ratio in session, where DRRs are RECOMMENDED. */
  drrToApproveRatio: number;
}

export type FatigueSecondarySignalCode = "LATENCY_DROP_60PCT" | "THREE_FAST_APPROVALS" | "DRR_RATIO_BELOW_10PCT";

export function evaluateFatigueSecondarySignals(i: FatigueSecondarySignalInputs): FatigueSecondarySignalCode[] {
  const codes: FatigueSecondarySignalCode[] = [];
  if (i.latencyDropFractionLast5 > 0.6) codes.push("LATENCY_DROP_60PCT"); // (a)
  if (i.threeConsecutiveFastApprovals) codes.push("THREE_FAST_APPROVALS"); // (b)
  if (i.drrToApproveRatio < 0.1) codes.push("DRR_RATIO_BELOW_10PCT"); // (c)
  return codes;
}

/** CONF-HEM-HRS-04 combined with §7.5.2: HRS < floor AND >=1 secondary signal. */
export function shouldFireHemFat1(hrsValue: number, fatigueFloor: number, secondarySignals: FatigueSecondarySignalCode[]): boolean {
  return hrsValue < fatigueFloor && secondarySignals.length > 0;
}

/**
 * §7.6.1 HEM-EMO-1 signals — also fully enumerated (a/b/c), same pattern as
 * HEM-FAT-1. Advisory only; MUST NOT block execution or enter HEM_PENDING.
 */
export interface EmotionalSecondarySignalInputs {
  /** (a) coefficient of variation > 0.5 over last 5 responses. */
  responseTimeCoefficientOfVariation: number;
  /** (b) negative sentiment markers in a submitted DRR rationale_text. */
  negativeDrrSentimentDetected: boolean;
  /** (c) principal explicitly self-reported via GEC interface. */
  explicitSelfReport: boolean;
}

export type EmotionalSecondarySignalCode = "HIGH_RESPONSE_VARIANCE" | "NEGATIVE_DRR_SENTIMENT" | "EXPLICIT_SELF_REPORT";

export function evaluateEmotionalSecondarySignals(i: EmotionalSecondarySignalInputs): EmotionalSecondarySignalCode[] {
  const codes: EmotionalSecondarySignalCode[] = [];
  if (i.responseTimeCoefficientOfVariation > 0.5) codes.push("HIGH_RESPONSE_VARIANCE");
  if (i.negativeDrrSentimentDetected) codes.push("NEGATIVE_DRR_SENTIMENT");
  if (i.explicitSelfReport) codes.push("EXPLICIT_SELF_REPORT");
  return codes;
}

export function shouldFireHemEmo1(
  emotionalProxyScore: number,
  emotionalAdvisoryFloor: number,
  secondarySignals: EmotionalSecondarySignalCode[],
): boolean {
  return emotionalProxyScore < emotionalAdvisoryFloor && secondarySignals.length > 0;
}
