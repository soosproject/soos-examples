import { writeFileSync, mkdirSync } from "node:fs";
import { HemError } from "./types.js";
import { computeHrs, DEFAULT_HRS_WEIGHTS, bandHrs, validateHrsWeights, HRS_THRESHOLDS, type HrsWeights } from "./hrs.js";
import {
  evaluateFatigueSecondarySignals,
  shouldFireHemFat1,
  evaluateEmotionalSecondarySignals,
  shouldFireHemEmo1,
} from "./fatigue-signals.js";
import {
  shouldFireHemPre1,
  buildHemPre1Request,
  assertPre1ResubmissionAllowed,
  shouldFireHemPre2,
  buildHemPre2Request,
  assertIrreversibleActionGated,
  assertOptionsPresentationNeutral,
  shouldFireHemDs2,
  assertDs2PromptBudget,
  shouldFireHemLim1,
  Lim1SessionTracker,
  assertOutOfDistributionAcknowledged,
  buildDeliberationRecord,
  classifyDomainCategory,
  assertDecisionValidForHigh1,
  assertDrrPresentForCategoryA,
  shouldFireHemConsent,
  resolveConsentOnTimeout,
  assertDecisionValidForInteractionClass,
} from "./interaction-classes.js";
import { handleManipulationDetected, handlePerformedEmotionDetected, handleBiometricSignalInferenceDetected } from "./tier0a-interface.js";
import {
  classifyAndSubstituteFraming,
  detectHrsGaming,
  isSuspectedInducedFatigue,
  validateDeliberationRecordChain,
  assertPlanBDeclaredBeforeSession,
  assertSecondaryPrincipalConfigured,
} from "./security-defenses.js";
import { assertInformationComplete } from "./inv-hem-01.js";
import { emitAle030PreClarificationInitiated, emitAle032PreConfirmationInitiated, emitAle034, emitAle036, emitAle038DivergenceNoted, emitAle040 } from "./ale.js";

type SvlLog = {
  id: string; kind: "happy" | "edge"; scenario: string; conformance_refs: string[];
  outcome: "PASS" | "DENY"; deny_code?: string | undefined; detail: string;
};
const logs: SvlLog[] = [];
function log(entry: SvlLog) {
  logs.push(entry);
  console.log(`[${entry.kind.toUpperCase()}] ${entry.id} ${entry.outcome === "PASS" ? "PASS" : `DENY(${entry.deny_code})`} — ${entry.scenario}`);
}

console.log("=== SOOS Step 7 — HEM (draft-sato-soos-hem-05) ===\n");

// 1. HEM-PRE-1
{
  const fires = shouldFireHemPre1({ goalRequiresUnavailableInfo: false, confidenceLevel: 0.3, pre1ConfidenceThreshold: 0.5, isConsequentialDecision: true, requireClarificationAnnotation: false });
  const req = buildHemPre1Request({ sessionId: "sess-1", soId: "so-1", mandateId: "mnd-1", goalDescription: "Book a reservation for uncertain party size", triggerConditionCode: "LOW_CONFIDENCE_CONSEQUENTIAL" });
  const ale = emitAle030PreClarificationInitiated({ hem_id: req.hem_id, session_id: req.session_id, so_id: req.so_id!, mandate_id: req.mandate_id!, goal_description_hash: "abc", trigger_condition_code: "LOW_CONFIDENCE_CONSEQUENTIAL" });
  log({ id: "HP-HEM-01", kind: "happy", scenario: "HEM-PRE-1 fires on low confidence + consequential decision, ALE-030 emitted", conformance_refs: ["§7.2.1"], outcome: fires && ale.ale_id === "ALE-030" ? "PASS" : "DENY", detail: `fires=${fires}` });
}
// EDGE: CONF-HEM-PRE1-01 resubmission block
{
  try {
    assertPre1ResubmissionAllowed("hash-of-same-goal", "same goal"); // sha256Hex("same goal") won't equal "hash-of-same-goal" — use identical text path below instead
  } catch {}
  // Proper test: derive hash first via the same function path used internally.
  const crypto = await import("node:crypto");
  const goalHash = crypto.createHash("sha256").update("Book table for unknown party size").digest("hex");
  try {
    assertPre1ResubmissionAllowed(goalHash, "Book table for unknown party size");
    log({ id: "EDGE-HEM-01", kind: "edge", scenario: "CONF-HEM-PRE1-01: resubmission with identical goal_description after DENY", conformance_refs: ["CONF-HEM-PRE1-01"], outcome: "PASS", detail: "UNEXPECTED: resubmission allowed" });
  } catch (e) {
    if (e instanceof HemError) log({ id: "EDGE-HEM-01", kind: "edge", scenario: "CONF-HEM-PRE1-01: resubmission with identical goal_description after DENY blocked", conformance_refs: ["CONF-HEM-PRE1-01"], outcome: "DENY", deny_code: e.code, detail: e.message });
  }
}

// 2. HEM-PRE-2 + irreversibility gating
{
  const fires = shouldFireHemPre2({ confirmBeforeExecute: false, confirmationRequired: false, isIrreversible: true, irreversibilityRequiresConfirm: true, retryCount: 0, retryThreshold: 3 });
  const req = buildHemPre2Request({ sessionId: "sess-2", soId: "so-2", mandateId: "mnd-2", actionId: "act.delete_booking", triggerConditionCode: "IRREVERSIBLE", irreversible: true });
  const ale = emitAle032PreConfirmationInitiated({ hem_id: req.hem_id, session_id: req.session_id, so_id: req.so_id!, mandate_id: req.mandate_id!, action_id: "act.delete_booking", trigger_condition_code: "IRREVERSIBLE", irreversible_flag: true });
  log({ id: "HP-HEM-02", kind: "happy", scenario: "HEM-PRE-2 fires for irreversible action, ALE-032 emitted (this is the plan's flagged minimum scenario)", conformance_refs: ["§7.2.2", "CONF-HEM-PRE2-01"], outcome: fires && ale.ale_id === "ALE-032" ? "PASS" : "DENY", detail: `fires=${fires}` });
}
// EDGE: irreversible action executed without completed HEM-PRE-2
try {
  assertIrreversibleActionGated(false, true, true);
  log({ id: "EDGE-HEM-02", kind: "edge", scenario: "Irreversible action attempted without completed HEM-PRE-2 lifecycle", conformance_refs: ["CONF-HEM-PRE2-01"], outcome: "PASS", detail: "UNEXPECTED: not blocked" });
} catch (e) {
  if (e instanceof HemError) log({ id: "EDGE-HEM-02", kind: "edge", scenario: "Irreversible action attempted without completed HEM-PRE-2 lifecycle — blocked", conformance_refs: ["CONF-HEM-PRE2-01"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 3. HEM-DS-1 neutrality
{
  const goodOptions = {
    options: [
      { option_id: "a", option_label: "Cancel booking", option_description: "Cancel the booking entirely.", decision_type: "TERMINATE" as const, consequence_summary: "This action will delete the booking record.", reversible: false, gec_recommended: false },
      { option_id: "b", option_label: "Modify booking", option_description: "Change the booking dates.", decision_type: "REDIRECT" as const, consequence_summary: "This action will update the booking dates.", reversible: true, gec_recommended: false },
    ],
    neutrality_certificate: "cert-abc",
  };
  try {
    assertOptionsPresentationNeutral(goodOptions);
    log({ id: "HP-HEM-03", kind: "happy", scenario: "HEM-DS-1 options presentation passes neutrality checks", conformance_refs: ["§7.3.1", "CONF-HEM-DS1-01/02/03"], outcome: "PASS", detail: "2 options, alphabetical, no evaluative language, 0 recommended" });
  } catch (e) {
    if (e instanceof HemError) log({ id: "HP-HEM-03", kind: "happy", scenario: "HEM-DS-1 neutral options", conformance_refs: ["§7.3.1"], outcome: "DENY", deny_code: e.code, detail: e.message });
  }
}
// EDGE: biased framing in consequence_summary
{
  const biasedOptions = {
    options: [
      { option_id: "a", option_label: "Cancel", option_description: "x", decision_type: "TERMINATE" as const, consequence_summary: "Unfortunately, this will delete the booking record.", reversible: false, gec_recommended: false },
      { option_id: "b", option_label: "Keep", option_description: "y", decision_type: "APPROVE" as const, consequence_summary: "This keeps the booking.", reversible: true, gec_recommended: false },
    ],
    neutrality_certificate: "cert-xyz",
  };
  try {
    assertOptionsPresentationNeutral(biasedOptions);
    log({ id: "EDGE-HEM-03", kind: "edge", scenario: "HEM-DS-1 biased consequence_summary (\"Unfortunately...\") should be rejected", conformance_refs: ["CONF-HEM-DS1-02", "§18.10"], outcome: "PASS", detail: "UNEXPECTED: biased framing accepted" });
  } catch (e) {
    if (e instanceof HemError) log({ id: "EDGE-HEM-03", kind: "edge", scenario: "HEM-DS-1 biased consequence_summary rejected", conformance_refs: ["CONF-HEM-DS1-02", "§18.10"], outcome: "DENY", deny_code: e.code, detail: e.message });
  }
}

// 4. HEM-DS-2 continuation prompt + budget
{
  const nowMs = Date.now();
  const fires = shouldFireHemDs2({ promptsSent: 0, lastActivitySignalAt: nowMs - 301_000 }, nowMs);
  log({ id: "HP-HEM-04", kind: "happy", scenario: "HEM-DS-2 fires after prompt_interval_seconds elapsed with no activity", conformance_refs: ["§7.3.2"], outcome: fires ? "PASS" : "DENY", detail: `fires=${fires}` });
}
{
  const { promptsExhausted } = assertDs2PromptBudget(3);
  log({ id: "EDGE-HEM-04", kind: "edge", scenario: "CONF-HEM-DS2-01: 4th HEM-DS-2 prompt — timeout treated as exhausted instead", conformance_refs: ["CONF-HEM-DS2-01", "§14.3"], outcome: promptsExhausted ? "DENY" : "PASS", deny_code: promptsExhausted ? "HEM_TIMEOUT_DENY" : undefined, detail: `promptsExhausted=${promptsExhausted}` });
}

// 5. HEM-LIM-1
{
  const fires = shouldFireHemLim1({ reasoningModeOutOfDistribution: true, confidenceLevel: 0.9, confidenceFloor: 0.5, alreadySurfacedThisSession: false, explicitOutOfCompetenceDeclaration: false });
  const tracker = new Lim1SessionTracker();
  const first = tracker.fireOrAppend({ limitation_type: "OUT_OF_DISTRIBUTION", limitation_description: "Novel task pattern", idp_confidence_level: 0.9, competence_floor: 0.5 });
  const second = tracker.fireOrAppend({ limitation_type: "OUT_OF_DISTRIBUTION", limitation_description: "Same novel pattern again", idp_confidence_level: 0.9, competence_floor: 0.5 });
  log({ id: "HP-HEM-05", kind: "happy", scenario: "HEM-LIM-1 fires on OUT_OF_DISTRIBUTION; CONF-HEM-LIM1-01 dedupes same limitation_type within session", conformance_refs: ["§7.4.1", "CONF-HEM-LIM1-01"], outcome: fires && first.isNew && !second.isNew ? "PASS" : "DENY", detail: `fires=${fires}, first.isNew=${first.isNew}, second.isNew=${second.isNew}` });
}
try {
  assertOutOfDistributionAcknowledged(true, false);
  log({ id: "EDGE-HEM-05", kind: "edge", scenario: "Agent proceeds OUT_OF_DISTRIBUTION without acknowledged HEM-LIM-1", conformance_refs: ["CONF-HEM-LIM1-02", "INV-HEM-01(c)"], outcome: "PASS", detail: "UNEXPECTED: not blocked" });
} catch (e) {
  if (e instanceof HemError) log({ id: "EDGE-HEM-05", kind: "edge", scenario: "Agent proceeds OUT_OF_DISTRIBUTION without acknowledged HEM-LIM-1 — blocked", conformance_refs: ["CONF-HEM-LIM1-02", "INV-HEM-01(c)"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 6. HEM-DIV-1
{
  const record = buildDeliberationRecord({
    declaredAction: "act.confirm_reservation", attemptedAction: "act.cancel_reservation", divergenceType: "PLAN_B_ACTIVE",
    divergenceReason: "Primary venue unavailable", optionSetConsidered: [{ action_id: "act.confirm_reservation", considered: true, selected: false, rejection_reason: "venue closed" }, { action_id: "act.cancel_reservation", considered: true, selected: true }],
    priorIdpChain: ["idp-001", "idp-002"],
  });
  const ale = emitAle038DivergenceNoted({ hem_id: "hem-div-1", session_id: "sess-6", divergence_type: record.divergence_type, declared_action_hash: "h1", attempted_action_hash: "h2", deliberation_record_id: "dr-1" });
  const eventLogIds = new Set(["idp-001", "idp-002"]);
  const { valid } = validateDeliberationRecordChain(record, eventLogIds);
  log({ id: "HP-HEM-06", kind: "happy", scenario: "HEM-DIV-1 fires on PLAN_B_ACTIVE, Deliberation Record built, chain validates against Event Log, ALE-038 emitted", conformance_refs: ["§7.4.2", "CONF-HEM-SEC-DIV-01"], outcome: valid && ale.ale_id === "ALE-038" ? "PASS" : "DENY", detail: `chain_valid=${valid}` });
}
{
  const forgedRecord = buildDeliberationRecord({
    declaredAction: "act.confirm_reservation", attemptedAction: "act.cancel_reservation", divergenceType: "ACTION_MISMATCH",
    optionSetConsidered: [], priorIdpChain: ["idp-999-never-happened"],
  });
  const { valid, mismatchedIds } = validateDeliberationRecordChain(forgedRecord, new Set(["idp-001"]));
  log({ id: "EDGE-HEM-06", kind: "edge", scenario: "§18.14 Divergence Protocol Gaming: prior_idp_chain references an idp_id never in the Event Log", conformance_refs: ["CONF-HEM-SEC-DIV-01"], outcome: valid ? "PASS" : "DENY", deny_code: valid ? undefined : "HEM_DELIBERATION_CHAIN_MISMATCH", detail: `mismatchedIds=${JSON.stringify(mismatchedIds)}` });
}
try {
  assertPlanBDeclaredBeforeSession("PLAN_B_ACTIVE", false);
  log({ id: "EDGE-HEM-07", kind: "edge", scenario: "PLAN_B_ACTIVE divergence where PLAN_B was never declared before this session (UNDECLARED_PLAN_B)", conformance_refs: ["CONF-HEM-SEC-DIV-03"], outcome: "PASS", detail: "UNEXPECTED: not flagged" });
} catch (e) {
  if (e instanceof HemError) log({ id: "EDGE-HEM-07", kind: "edge", scenario: "UNDECLARED_PLAN_B correctly flagged", conformance_refs: ["CONF-HEM-SEC-DIV-03"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 7. HEM-HIGH-1 (plan's flagged minimum scenario: MEDICAL Category A + DRR)
{
  const category = classifyDomainCategory("MEDICAL", new Set());
  log({ id: "HP-HEM-07", kind: "happy", scenario: "HEM-HIGH-1: MEDICAL classified Category A (non-operator-configurable)", conformance_refs: ["§7.5.1"], outcome: category === "CATEGORY_A" ? "PASS" : "DENY", detail: `category=${category}` });
}
try {
  assertDrrPresentForCategoryA("CATEGORY_A", "APPROVE", false);
  log({ id: "EDGE-HEM-08", kind: "edge", scenario: "HEM-HIGH-1 Category A APPROVE without DRR", conformance_refs: ["§12.7", "HEM_DRR_REQUIRED"], outcome: "PASS", detail: "UNEXPECTED: accepted without DRR" });
} catch (e) {
  if (e instanceof HemError) log({ id: "EDGE-HEM-08", kind: "edge", scenario: "HEM-HIGH-1 Category A APPROVE without DRR — rejected", conformance_refs: ["§12.7", "HEM_DRR_REQUIRED"], outcome: "DENY", deny_code: e.code, detail: e.message });
}
try {
  assertDecisionValidForHigh1("APPROVE_WITH_PAYMENT");
  log({ id: "EDGE-HEM-09", kind: "edge", scenario: "APPROVE_WITH_PAYMENT submitted for HEM-HIGH-1 (invalid decision type for this class)", conformance_refs: ["CONF-HEM-HIGH1-02"], outcome: "PASS", detail: "UNEXPECTED: accepted" });
} catch (e) {
  if (e instanceof HemError) log({ id: "EDGE-HEM-09", kind: "edge", scenario: "APPROVE_WITH_PAYMENT correctly rejected for HEM-HIGH-1", conformance_refs: ["CONF-HEM-HIGH1-02"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 8. HEM-FAT-1 (plan's flagged minimum scenario: HRS 0.38 + secondary signals + 30-min rest)
{
  const weights: HrsWeights = DEFAULT_HRS_WEIGHTS;
  const hrs = computeHrs({
    currentLatencySeconds: 2.5, baselineLatencySeconds: 20, rubberStampFloorSeconds: 3,
    runLengthOfIdenticalDecisions: 8, drrRecommendedSlots: 10, drrSubmittedCount: 0,
    sessionElapsedMinutes: 90, maxSessionMinutes: 120,
    highResponseTimeVariance: false, negativeDrrSentiment: false, explicitSelfReport: false,
  }, weights);
  const secondary = evaluateFatigueSecondarySignals({ latencyDropFractionLast5: 0.65, threeConsecutiveFastApprovals: true, drrToApproveRatio: 0.05 });
  const fires = shouldFireHemFat1(hrs.hrs_value, HRS_THRESHOLDS.HRS_FATIGUE_FLOOR.default, secondary);
  const restSeconds = 1800; // default per §7.5.2
  const ale = emitAle034({ fatigue_flag: true, hem_id: "hem-fat-1", principal_id: "principal-1", hrs_score: hrs.hrs_value, hrs_fatigue_floor: HRS_THRESHOLDS.HRS_FATIGUE_FLOOR.default, secondary_signal_codes: secondary, mandatory_rest_seconds: restSeconds });
  log({
    id: "HP-HEM-08", kind: "happy",
    scenario: `HEM-FAT-1: HRS=${hrs.hrs_value.toFixed(2)} (below HRS_FATIGUE_FLOOR=0.40, per the plan's flagged minimum scenario) + secondary signals present, 1800s rest, ALE-034 fatigue_flag=true`,
    conformance_refs: ["§7.5.2", "CONF-HEM-HRS-04"], outcome: fires && ale.fields["fatigue_flag"] === true ? "PASS" : "DENY",
    detail: `hrs=${hrs.hrs_value.toFixed(3)}, secondary_signals=${JSON.stringify(secondary)}, fires=${fires}`,
  });
}
// EDGE: HRS below floor but NO secondary signals — must NOT fire (this is the resolved SDB-HEM-01 question in action)
{
  const hrs = computeHrs({
    currentLatencySeconds: 18, baselineLatencySeconds: 20, rubberStampFloorSeconds: 3,
    runLengthOfIdenticalDecisions: 1, drrRecommendedSlots: 10, drrSubmittedCount: 9,
    sessionElapsedMinutes: 115, maxSessionMinutes: 120,
    highResponseTimeVariance: false, negativeDrrSentiment: false, explicitSelfReport: false,
  });
  const secondary = evaluateFatigueSecondarySignals({ latencyDropFractionLast5: 0.1, threeConsecutiveFastApprovals: false, drrToApproveRatio: 0.9 });
  const fires = shouldFireHemFat1(hrs.hrs_value, HRS_THRESHOLDS.HRS_FATIGUE_FLOOR.default, secondary);
  log({ id: "EDGE-HEM-10", kind: "edge", scenario: "Low HRS (session-duration driven) but zero secondary signals present — HEM-FAT-1 MUST NOT fire per §7.5.2's conjunctive (AND) condition", conformance_refs: ["§7.5.2"], outcome: !fires ? "PASS" : "DENY", detail: `hrs=${hrs.hrs_value.toFixed(3)}, secondary_signals=${JSON.stringify(secondary)}, fires=${fires} (expected false)` });
}
// EDGE: weight config error
try {
  validateHrsWeights({ w1_latency_trend: 0.3, w2_decision_variance: 0.3, w3_drr_completion: 0.3, w4_session_duration: 0.3, w5_emotional_proxy: 0.3 });
  log({ id: "EDGE-HEM-11", kind: "edge", scenario: "HRS weights summing to 1.5 (not 1.0) should be rejected at load time", conformance_refs: ["CONF-HEM-HRS-01"], outcome: "PASS", detail: "UNEXPECTED: accepted" });
} catch (e) {
  if (e instanceof HemError) log({ id: "EDGE-HEM-11", kind: "edge", scenario: "HRS_WEIGHT_CONFIGURATION_ERROR correctly rejected", conformance_refs: ["CONF-HEM-HRS-01"], outcome: "DENY", deny_code: e.code, detail: e.message });
}
// EDGE: §18.13 induced-fatigue attack detection
{
  const now = Date.now();
  const drivingEscalations = Array.from({ length: 10 }, (_, i) => ({ sessionId: i < 5 ? "attacker-session" : `session-${i}`, atMs: now - i * 60_000 }));
  const suspected = isSuspectedInducedFatigue(drivingEscalations, now);
  log({ id: "EDGE-HEM-12", kind: "edge", scenario: "§18.13: >40% of driving escalations from one session in 15min window — FATIGUE_ATTACK_SUSPECTED instead of enforcing rest", conformance_refs: ["CONF-HEM-SEC-FAT-01"], outcome: suspected ? "DENY" : "PASS", deny_code: suspected ? "HEM_FATIGUE_BLOCKED" : undefined, detail: `suspected=${suspected}` });
}
try {
  assertSecondaryPrincipalConfigured(["principal-only"], true);
  log({ id: "EDGE-HEM-13", kind: "edge", scenario: "HEM-FAT-1 enabled with single-principal designation chain (no secondary)", conformance_refs: ["CONF-HEM-SEC-FAT-02"], outcome: "PASS", detail: "UNEXPECTED: accepted as conforming" });
} catch (e) {
  if (e instanceof HemError) log({ id: "EDGE-HEM-13", kind: "edge", scenario: "Single-principal chain with HEM-FAT-1 enabled correctly flagged non-conforming", conformance_refs: ["CONF-HEM-SEC-FAT-02"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 9. HEM-EMO-1 (advisory only)
{
  const secondary = evaluateEmotionalSecondarySignals({ responseTimeCoefficientOfVariation: 0.6, negativeDrrSentimentDetected: true, explicitSelfReport: false });
  const fires = shouldFireHemEmo1(0.3, HRS_THRESHOLDS.HRS_EMOTIONAL_ADVISORY_FLOOR.default, secondary);
  const ale = emitAle036({ advisory_type: "EMOTIONAL", hem_id: "hem-emo-1", session_id: "sess-9" });
  log({ id: "HP-HEM-09", kind: "happy", scenario: "HEM-EMO-1 fires (advisory only, no HEM_PENDING) — ALE-036 advisory_type=EMOTIONAL", conformance_refs: ["§7.6.1"], outcome: fires && ale.fields["advisory_type"] === "EMOTIONAL" ? "PASS" : "DENY", detail: `fires=${fires}` });
}

// 10. HEM-CONSENT (plan's flagged minimum scenario: APPI Article 17, fail-closed timeout)
{
  const fires = shouldFireHemConsent({ actionConsentGated: true, consentScopePresent: false, nowMs: Date.now(), requiredPurposeCode: "MARKETING_OUTREACH", presentPurposeCodes: [] });
  const ale = emitAle040({ ale_subtype: "CONSENT_INIT", hem_id: "hem-consent-1", session_id: "sess-10", consent_requirement: "APPI_ART17", purpose_codes_required: ["MARKETING_OUTREACH"], purpose_codes_present: [], consent_expiry: null });
  log({ id: "HP-HEM-10", kind: "happy", scenario: "HEM-CONSENT fires (no consent_scope), APPI_ART17 basis, ALE-040 ale_subtype=CONSENT_INIT — matches plan's flagged minimum scenario", conformance_refs: ["§7.6.2"], outcome: fires && ale.fields["ale_subtype"] === "CONSENT_INIT" ? "PASS" : "DENY", detail: `fires=${fires}` });
}
{
  const resolution = resolveConsentOnTimeout();
  log({ id: "EDGE-HEM-14", kind: "edge", scenario: "CONF-HEM-CONSENT-01: consent escalation times out — fail-closed TIMEOUT_DENY, never implicit consent", conformance_refs: ["CONF-HEM-CONSENT-01"], outcome: resolution.resolution_type === "TIMEOUT_DENY" && resolution.consent_basis === null ? "DENY" : "PASS", deny_code: "HEM_TIMEOUT_DENY", detail: JSON.stringify(resolution) });
}

// 11. SDB-HEM-02 — DENY decision type gap
try {
  assertDecisionValidForInteractionClass("HEM-HIGH-1", "DENY");
  log({ id: "EDGE-HEM-15", kind: "edge", scenario: "SDB-HEM-02: DENY decision submitted for an interaction class where it's not defined (HEM-HIGH-1)", conformance_refs: ["§12", "SDB-HEM-02"], outcome: "PASS", detail: "UNEXPECTED: accepted" });
} catch (e) {
  if (e instanceof HemError) log({ id: "EDGE-HEM-15", kind: "edge", scenario: "DENY correctly scoped to HEM-PRE-1/HEM-PRE-2 only, rejected elsewhere (SDB-HEM-02)", conformance_refs: ["§12", "SDB-HEM-02"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 12. Tier 0-A HEM interface
{
  const { event, newClass1Required } = handleManipulationDetected(null);
  log({ id: "HP-HEM-11", kind: "happy", scenario: "§9.2: MANIPULATION detected with nothing pending — initiates new Class 1 event, no HEM decision can authorize it", conformance_refs: ["§9.2(b)", "§9.2(d)"], outcome: newClass1Required && event.violation_class === "MANIPULATION" ? "PASS" : "DENY", detail: JSON.stringify(event) });
}
{
  const { event, mustTriggerHemConsent } = handleBiometricSignalInferenceDetected();
  log({ id: "HP-HEM-12", kind: "happy", scenario: "§9.4(d): BIOMETRIC_SIGNAL_INFERENCE violation must also trigger HEM-CONSENT", conformance_refs: ["§9.4(d)"], outcome: mustTriggerHemConsent && event.violation_class === "BIOMETRIC_SIGNAL_INFERENCE" ? "PASS" : "DENY", detail: JSON.stringify(event) });
}

// 13. §18.10 manipulation-via-framing substitution
{
  const result = classifyAndSubstituteFraming("Unfortunately, this will delete the booking record.", "This action will delete the booking record.");
  log({ id: "EDGE-HEM-16", kind: "edge", scenario: "§18.10: agent-generated consequence_summary with evaluative framing substituted with kernel-generated neutral text (HEM_FRAMING_SUBSTITUTED)", conformance_refs: ["CONF-HEM-SEC-MANIP-03"], outcome: result.substituted ? "DENY" : "PASS", deny_code: result.substituted ? "HEM_SUPPRESSION_DETECTED" : undefined, detail: JSON.stringify(result) });
}

// 14. §18.12 HRS gaming detection
{
  const now = Date.now();
  const triggers = [now - 1000, now - 2000, now - 3000];
  const fastWindows: Array<[number, number]> = [[now - 5000, now]];
  const gaming = detectHrsGaming(triggers, fastWindows);
  log({ id: "EDGE-HEM-17", kind: "edge", scenario: "§18.12: HEM trigger timing correlates with principal fast-response periods (HRS_GAMING_SUSPECTED)", conformance_refs: ["CONF-HEM-SEC-HRS-02"], outcome: gaming ? "DENY" : "PASS", deny_code: gaming ? "HEM_DECISION_INVALID" : undefined, detail: `gaming_suspected=${gaming}` });
}

// 15. INV-HEM-01 information completeness
try {
  assertInformationComplete({ hem_id: "hem-x", session_id: "sess-x", interaction_class: "HEM-LIM-1", initiated_at: new Date().toISOString() }); // missing limitation_declaration
  log({ id: "EDGE-HEM-18", kind: "edge", scenario: "INV-HEM-01(a): HEM-LIM-1 escalation missing required limitation_declaration field", conformance_refs: ["INV-HEM-01(a)"], outcome: "PASS", detail: "UNEXPECTED: accepted incomplete request" });
} catch (e) {
  if (e instanceof HemError) log({ id: "EDGE-HEM-18", kind: "edge", scenario: "INV-HEM-01(a) correctly caught missing required field", conformance_refs: ["INV-HEM-01(a)"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// ---------------------------------------------------------------------------
const happy = logs.filter((l) => l.kind === "happy").length;
const edge = logs.filter((l) => l.kind === "edge").length;
console.log(`\n${happy} happy-path + ${edge} edge/adversarial logs generated.`);
console.log("Covers all 10 interaction classes, HRS + fatigue/emotional secondary signals, Tier 0-A HEM interface,");
console.log("and the five §18.10-18.14 security defenses. Scoped corpus (not the full 20+21 pattern) — see chat response.");

mkdirSync("svl/corpus-b/hem", { recursive: true });
writeFileSync("svl/corpus-b/hem/logs.json", JSON.stringify(logs, null, 2));
console.log("Corpus written to svl/corpus-b/hem/logs.json");
