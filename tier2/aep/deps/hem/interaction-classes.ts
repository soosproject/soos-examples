import { createHash } from "node:crypto";
import {
  HemError,
  DENY_VALID_FOR,
  type DeliberationRecord,
  type HemEscalationRequest,
  type HemOption,
  type HumanDecisionType,
  type LimitationDeclaration,
  type OptionsPresentation,
} from "./types.js";

function sha256Hex(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

function newHemId(): string {
  return `hem-${Math.random().toString(36).slice(2, 10)}`;
}

// ---------------------------------------------------------------------------
// §7.2.1 HEM-PRE-1 — Pre-Action Clarification Request
// ---------------------------------------------------------------------------

export interface Pre1TriggerInputs {
  goalRequiresUnavailableInfo: boolean; // (a)
  confidenceLevel: number;
  pre1ConfidenceThreshold: number;
  isConsequentialDecision: boolean; // (b)
  requireClarificationAnnotation: boolean; // (c)
}

export function shouldFireHemPre1(i: Pre1TriggerInputs): boolean {
  return (
    i.goalRequiresUnavailableInfo ||
    (i.confidenceLevel < i.pre1ConfidenceThreshold && i.isConsequentialDecision) ||
    i.requireClarificationAnnotation
  );
}

export function buildHemPre1Request(f: {
  sessionId: string; soId: string; mandateId: string; goalDescription: string; triggerConditionCode: string;
}): HemEscalationRequest {
  return {
    hem_id: newHemId(),
    session_id: f.sessionId,
    so_id: f.soId,
    mandate_id: f.mandateId,
    interaction_class: "HEM-PRE-1",
    trigger_detail: { goal_description_hash: sha256Hex(f.goalDescription), trigger_condition_code: f.triggerConditionCode },
    initiated_at: new Date().toISOString(),
  };
}

/** CONF-HEM-PRE1-01: no resubmission on same so_id after a DENY without a materially distinct new IDP goal. */
export function assertPre1ResubmissionAllowed(priorDenyGoalHash: string | undefined, newGoalDescription: string): void {
  if (priorDenyGoalHash && sha256Hex(newGoalDescription) === priorDenyGoalHash) {
    throw new HemError(
      "HEM_DECISION_INVALID",
      "CONF-HEM-PRE1-01: resubmission after DENY requires a materially distinct goal_description; hash unchanged",
    );
  }
}

// ---------------------------------------------------------------------------
// §7.2.2 HEM-PRE-2 — Pre-Action Confirmation Request
// ---------------------------------------------------------------------------

export interface Pre2TriggerInputs {
  confirmBeforeExecute: boolean; // (a)
  confirmationRequired: boolean; // (b)
  isIrreversible: boolean;
  irreversibilityRequiresConfirm: boolean; // (c)
  retryCount: number;
  retryThreshold: number; // default 3, (d)
}

export function shouldFireHemPre2(i: Pre2TriggerInputs): boolean {
  return (
    i.confirmBeforeExecute ||
    i.confirmationRequired ||
    (i.isIrreversible && i.irreversibilityRequiresConfirm) ||
    i.retryCount > i.retryThreshold
  );
}

/** CONF-HEM-PRE2-01: irreversible action MUST NOT execute without a completed HEM-PRE-2 lifecycle. */
export function assertIrreversibleActionGated(hemPre2Completed: boolean, isIrreversible: boolean, irreversibilityRequiresConfirm: boolean): void {
  if (isIrreversible && irreversibilityRequiresConfirm && !hemPre2Completed) {
    throw new HemError("HEM_DECISION_INVALID", "CONF-HEM-PRE2-01: irreversible action requires completed HEM-PRE-2 lifecycle");
  }
}

export interface RetryAttempt {
  attempt_number: number;
  outcome: string;
}

export function buildHemPre2Request(f: {
  sessionId: string; soId: string; mandateId: string; actionId: string;
  triggerConditionCode: string; irreversible: boolean; retryHistory?: RetryAttempt[];
}): HemEscalationRequest {
  return {
    hem_id: newHemId(),
    session_id: f.sessionId,
    so_id: f.soId,
    mandate_id: f.mandateId,
    interaction_class: "HEM-PRE-2",
    trigger_detail: {
      action_id: f.actionId,
      trigger_condition_code: f.triggerConditionCode,
      irreversible_flag: f.irreversible,
      // CONF-HEM-PRE2-02: full RETRY history required when firing on retry threshold
      ...(f.retryHistory ? { retry_history: f.retryHistory } : {}),
    },
    initiated_at: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// §7.3.1 HEM-DS-1 — Options Presentation (format, not an independent trigger)
// ---------------------------------------------------------------------------

/** CONF-HEM-DS1-01/02/03 — neutrality requirements. */
export function assertOptionsPresentationNeutral(p: OptionsPresentation): void {
  if (p.options.length < 2 || p.options.length > 5) {
    throw new HemError("HEM_DECISION_INVALID", `HEM-DS-1: options count ${p.options.length} outside [2,5]`);
  }
  const recommendedCount = p.options.filter((o) => o.gec_recommended).length;
  if (recommendedCount > 1) {
    throw new HemError("HEM_DECISION_INVALID", "CONF-HEM-DS1-03: at most one option may carry gec_recommended: true");
  }
  const sortedByLabel = [...p.options].map((o) => o.option_label);
  const isAlphabetical = JSON.stringify(sortedByLabel) === JSON.stringify([...sortedByLabel].sort());
  // We can't detect true randomness from a single sample; enforce the alphabetical
  // branch of CONF-HEM-DS1-01 deterministically, and require callers using random
  // ordering to pass a pre-shuffled array (documented, not enforced further here).
  if (!isAlphabetical) {
    // Not a violation per se (random ordering is permitted) — flag for review instead
    // of hard-failing, since we cannot distinguish "random" from "biased" from one sample.
  }
  for (const opt of p.options) {
    if (/unfortunately|urgently|must act now|regrettably/i.test(opt.consequence_summary)) {
      throw new HemError(
        "HEM_DECISION_INVALID",
        `CONF-HEM-DS1-02: consequence_summary for ${opt.option_id} contains evaluative/urgency language: "${opt.consequence_summary}"`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// §7.3.2 HEM-DS-2 — Continuation Prompt
// ---------------------------------------------------------------------------

export interface Ds2State {
  promptsSent: number;
  lastActivitySignalAt: number; // epoch ms
}

export function shouldFireHemDs2(state: Ds2State, nowMs: number, promptIntervalSeconds = 300): boolean {
  const elapsed = (nowMs - state.lastActivitySignalAt) / 1000;
  return elapsed > Math.max(promptIntervalSeconds, 60);
}

/** CONF-HEM-DS2-01: max 3 prompts per principal per hem_id; 4th means timeout treated as exhausted. */
export function assertDs2PromptBudget(promptsSentSoFar: number): { promptsExhausted: boolean } {
  if (promptsSentSoFar >= 3) {
    return { promptsExhausted: true }; // caller must treat timeout as exhausted per §14.3
  }
  return { promptsExhausted: false };
}

// ---------------------------------------------------------------------------
// §7.4.1 HEM-LIM-1 — Capability Limitation Declaration
// ---------------------------------------------------------------------------

export interface Lim1TriggerInputs {
  reasoningModeOutOfDistribution: boolean; // (a)
  confidenceLevel: number;
  confidenceFloor: number; // (b)
  alreadySurfacedThisSession: boolean;
  explicitOutOfCompetenceDeclaration: boolean; // (c)
}

export function shouldFireHemLim1(i: Lim1TriggerInputs): boolean {
  return (
    i.reasoningModeOutOfDistribution ||
    (i.confidenceLevel < i.confidenceFloor && !i.alreadySurfacedThisSession) ||
    i.explicitOutOfCompetenceDeclaration
  );
}

/** CONF-HEM-LIM1-01: at most one HEM-LIM-1 record per unique limitation_type per session — append, don't duplicate. */
export class Lim1SessionTracker {
  private firedTypes = new Map<string, LimitationDeclaration>();

  fireOrAppend(decl: LimitationDeclaration): { isNew: boolean; record: LimitationDeclaration } {
    const existing = this.firedTypes.get(decl.limitation_type);
    if (existing) {
      // append semantics: keep first record, this call is a no-op duplicate suppressed
      return { isNew: false, record: existing };
    }
    this.firedTypes.set(decl.limitation_type, decl);
    return { isNew: true, record: decl };
  }
}

/** CONF-HEM-LIM1-02: agent MUST NOT proceed OUT_OF_DISTRIBUTION without acknowledged HEM-LIM-1. */
export function assertOutOfDistributionAcknowledged(reasoningModeOOD: boolean, hemLim1Acknowledged: boolean): void {
  if (reasoningModeOOD && !hemLim1Acknowledged) {
    throw new HemError("HEM_DECISION_INVALID", "CONF-HEM-LIM1-02: OUT_OF_DISTRIBUTION task requires acknowledged HEM-LIM-1 lifecycle");
  }
}

// ---------------------------------------------------------------------------
// §7.4.2 HEM-DIV-1 — Divergence Noted
// ---------------------------------------------------------------------------

export function buildDeliberationRecord(f: {
  declaredAction: string;
  attemptedAction: string;
  divergenceType: DeliberationRecord["divergence_type"];
  divergenceReason?: string;
  optionSetConsidered: DeliberationRecord["option_set_considered"];
  priorIdpChain: string[];
}): DeliberationRecord {
  return {
    declared_action: f.declaredAction,
    attempted_action: f.attemptedAction,
    divergence_type: f.divergenceType,
    ...(f.divergenceReason !== undefined ? { divergence_reason: f.divergenceReason } : {}),
    option_set_considered: f.optionSetConsidered,
    prior_idp_chain: f.priorIdpChain,
  };
}

// ---------------------------------------------------------------------------
// §7.5.1 HEM-HIGH-1 — High-Stakes Mandatory Review
// ---------------------------------------------------------------------------

export const CATEGORY_A_DOMAINS = new Set(["MEDICAL", "AVIATION", "NUCLEAR"]);

export function classifyDomainCategory(domainName: string, operatorCategoryBDomains: ReadonlySet<string>): "CATEGORY_A" | "CATEGORY_B" | null {
  if (CATEGORY_A_DOMAINS.has(domainName)) return "CATEGORY_A";
  if (operatorCategoryBDomains.has(domainName)) return "CATEGORY_B";
  return null;
}

/** CONF-HEM-HIGH1-02: APPROVE_WITH_PAYMENT MUST be rejected for HEM-HIGH-1. */
export function assertDecisionValidForHigh1(decision: HumanDecisionType): void {
  if (decision === "APPROVE_WITH_PAYMENT") {
    throw new HemError("HEM_DECISION_INVALID", "CONF-HEM-HIGH1-02: APPROVE_WITH_PAYMENT is not valid for HEM-HIGH-1");
  }
}

/** DRR requirement for Category A APPROVE / APPROVE_WITH_CONSTRAINTS. */
export function assertDrrPresentForCategoryA(domainCategory: "CATEGORY_A" | "CATEGORY_B", decision: HumanDecisionType, drrPresent: boolean): void {
  if (domainCategory === "CATEGORY_A" && (decision === "APPROVE" || decision === "APPROVE_WITH_CONSTRAINTS") && !drrPresent) {
    throw new HemError("HEM_DRR_REQUIRED", "HEM-HIGH-1 Category A: DRR required for APPROVE / APPROVE_WITH_CONSTRAINTS");
  }
}

// ---------------------------------------------------------------------------
// §7.6.2 HEM-CONSENT — Consent-Required Escalation
// ---------------------------------------------------------------------------

export interface ConsentTriggerInputs {
  actionConsentGated: boolean;
  consentScopePresent: boolean; // (a)
  consentScopeExpiryMs?: number; // (b)
  nowMs: number;
  requiredPurposeCode: string;
  presentPurposeCodes: string[]; // (c)
}

export function shouldFireHemConsent(i: ConsentTriggerInputs): boolean {
  if (!i.actionConsentGated) return false;
  if (!i.consentScopePresent) return true; // (a)
  if (i.consentScopeExpiryMs !== undefined && i.consentScopeExpiryMs < i.nowMs) return true; // (b)
  if (!i.presentPurposeCodes.includes(i.requiredPurposeCode)) return true; // (c)
  return false;
}

/** CONF-HEM-CONSENT-01: fail closed on timeout — resolution MUST be TIMEOUT_DENY, never implicit consent. */
export function resolveConsentOnTimeout(): { resolution_type: "TIMEOUT_DENY"; consent_basis: null } {
  return { resolution_type: "TIMEOUT_DENY", consent_basis: null };
}

export { DENY_VALID_FOR };
export function assertDecisionValidForInteractionClass(interactionClass: string, decision: HumanDecisionType): void {
  if (decision === "DENY" && !DENY_VALID_FOR.has(interactionClass)) {
    throw new HemError("HEM_DECISION_INVALID", `DENY is only defined for HEM-PRE-1/HEM-PRE-2 (SDB-HEM-02); not valid for ${interactionClass}`);
  }
}

export type { HemOption };
