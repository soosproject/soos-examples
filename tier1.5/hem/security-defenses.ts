import { HemError, type DeliberationRecord } from "./types.js";

// ---------------------------------------------------------------------------
// §18.10 — Manipulation Attack via HEM Channel
// ---------------------------------------------------------------------------

const PROHIBITED_FRAMING_PATTERN = /unfortunately|urgently|must act now|regrettably|sadly|tragically|you should|it's critical that you/i;

/** CONF-HEM-SEC-MANIP-02/03: classify + substitute kernel-generated summary on violation. */
export function classifyAndSubstituteFraming(
  agentGeneratedSummary: string,
  kernelGeneratedSummary: string,
): { finalSummary: string; substituted: boolean } {
  if (PROHIBITED_FRAMING_PATTERN.test(agentGeneratedSummary)) {
    return { finalSummary: kernelGeneratedSummary, substituted: true }; // HEM_FRAMING_SUBSTITUTED logged by caller
  }
  return { finalSummary: agentGeneratedSummary, substituted: false };
}

// ---------------------------------------------------------------------------
// §18.11 — Performed Emotion Detection Bypass
// ---------------------------------------------------------------------------

const EMOTIONAL_CONTENT_PATTERN = /please|i beg|desperately|i'm scared|help me|i need you to understand|heartbroken/i;

/** CONF-HEM-SEC-PERF-02/03: check principal-visible agent metadata, substitute neutral content on detection. */
export function checkAndSubstitutePerformedEmotion(
  agentMetadataText: string,
  neutralKernelText: string,
): { finalText: string; substituted: boolean } {
  if (EMOTIONAL_CONTENT_PATTERN.test(agentMetadataText)) {
    return { finalText: neutralKernelText, substituted: true }; // PERFORMED_EMOTION_SUBSTITUTION logged by caller
  }
  return { finalText: agentMetadataText, substituted: false };
}

// ---------------------------------------------------------------------------
// §18.12 — HRS Scoring Manipulation
// ---------------------------------------------------------------------------

/** CONF-HEM-SEC-HRS-02: flag anomalous trigger-timing correlation with principal fast-response periods. */
export function detectHrsGaming(triggerIntervalsMs: number[], fastResponsePeriodsMs: Array<[number, number]>): boolean {
  if (triggerIntervalsMs.length === 0) return false;
  let correlatedCount = 0;
  for (const t of triggerIntervalsMs) {
    if (fastResponsePeriodsMs.some(([start, end]) => t >= start && t <= end)) correlatedCount++;
  }
  // Heuristic: >50% of triggers landing inside fast-response windows is suspicious.
  return correlatedCount / triggerIntervalsMs.length > 0.5;
}

/** CONF-HEM-SEC-HRS-01: D4 penalty for cumulative same-day sessions (3rd+ session of the day). */
export function d4DailySessionPenalty(sessionOrdinalToday: number, baseD4Score: number): number {
  if (sessionOrdinalToday < 3) return baseD4Score;
  const penaltyFactor = Math.max(0, 1 - 0.15 * (sessionOrdinalToday - 2)); // 3rd session -15%, 4th -30%, floor 0
  return Math.max(0, baseD4Score * penaltyFactor);
}

// ---------------------------------------------------------------------------
// §18.13 — Approval Fatigue Exploitation
// ---------------------------------------------------------------------------

/** CONF-HEM-SEC-FAT-01: >40% of driving escalations from one session in last 15 min → suspected attack, not genuine fatigue. */
export function isSuspectedInducedFatigue(
  drivingEscalations: Array<{ sessionId: string; atMs: number }>,
  nowMs: number,
): boolean {
  const windowMs = 15 * 60 * 1000;
  const recent = drivingEscalations.filter((e) => nowMs - e.atMs <= windowMs);
  if (recent.length === 0) return false;
  const bySession = new Map<string, number>();
  for (const e of recent) bySession.set(e.sessionId, (bySession.get(e.sessionId) ?? 0) + 1);
  const maxFromOneSession = Math.max(...bySession.values());
  return maxFromOneSession / recent.length > 0.4;
}

/** CONF-HEM-SEC-FAT-02: designation chain must have a secondary principal when HEM-FAT-1 is enabled. */
export function assertSecondaryPrincipalConfigured(designationChain: string[], hemFat1Enabled: boolean): void {
  if (hemFat1Enabled && designationChain.length < 2) {
    throw new HemError(
      "HEM_DECISION_INVALID",
      "CONF-HEM-SEC-FAT-02: designation chain requires a secondary principal when HEM-FAT-1 is enabled",
    );
  }
}

// ---------------------------------------------------------------------------
// §18.14 — Divergence Protocol Gaming
// ---------------------------------------------------------------------------

/** CONF-HEM-SEC-DIV-01: prior_idp_chain entries MUST all appear in the actual session Event Log. */
export function validateDeliberationRecordChain(record: DeliberationRecord, actualEventLogIdpIds: Set<string>): { valid: boolean; mismatchedIds: string[] } {
  const mismatched = record.prior_idp_chain.filter((id) => !actualEventLogIdpIds.has(id));
  return { valid: mismatched.length === 0, mismatchedIds: mismatched };
}

/** CONF-HEM-SEC-DIV-03: PLAN_B_ACTIVE divergence requires the PLAN_B path to have been declared before this session. */
export function assertPlanBDeclaredBeforeSession(divergenceType: string, planBDeclaredBeforeSession: boolean): void {
  if (divergenceType === "PLAN_B_ACTIVE" && !planBDeclaredBeforeSession) {
    throw new HemError(
      "HEM_DELIBERATION_CHAIN_MISMATCH",
      "CONF-HEM-SEC-DIV-03: UNDECLARED_PLAN_B — PLAN_B path was not declared before the current session",
    );
  }
}
