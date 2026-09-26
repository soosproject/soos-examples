import type { HemEscalationRequest } from "./types.js";

export type Tier0AViolationClass = "MANIPULATION" | "PERFORMED_EMOTION" | "BIOMETRIC_SIGNAL_INFERENCE";

export interface ConstitutionalViolationEvent {
  tier: "TIER_0A";
  violation_class: Tier0AViolationClass;
  detected_at: string;
}

/**
 * §9.2 — MANIPULATION HEM interface.
 * (b) MUST NOT enter HEM_PENDING for MANIPULATION itself (no HEM decision
 * authorizes it — CEE-refused before the state machine engages).
 * (c) MUST flag any concurrently pending HEM event with manipulation_detected.
 * (d) If nothing pending, MUST initiate a Class 1 (HEM_CEDAR_ROUTED) event
 * routed to the highest-authority principal.
 */
export function handleManipulationDetected(
  pendingRequest: HemEscalationRequest | null,
): { event: ConstitutionalViolationEvent; updatedPending: HemEscalationRequest | null; newClass1Required: boolean } {
  const event: ConstitutionalViolationEvent = { tier: "TIER_0A", violation_class: "MANIPULATION", detected_at: new Date().toISOString() };
  if (pendingRequest) {
    return { event, updatedPending: { ...pendingRequest, manipulation_detected: true }, newClass1Required: false };
  }
  return { event, updatedPending: null, newClass1Required: true }; // (d)
}

/**
 * §9.3 — PERFORMED_EMOTION HEM interface.
 * (b) MUST NOT enter HEM_PENDING unless a co-occurring Class 1/2 trigger
 * is already active — this function just reports the violation; the caller
 * decides whether a Class 1/2 trigger is co-occurring.
 */
export function handlePerformedEmotionDetected(coOccurringClass1Or2Active: boolean): {
  event: ConstitutionalViolationEvent;
  shouldEnterHemPending: boolean;
} {
  return {
    event: { tier: "TIER_0A", violation_class: "PERFORMED_EMOTION", detected_at: new Date().toISOString() },
    shouldEnterHemPending: coOccurringClass1Or2Active,
  };
}

/**
 * §9.4 — BIOMETRIC_SIGNAL_INFERENCE HEM interface.
 * (d) generates a CONSTITUTIONAL_VIOLATION AND must also trigger HEM-CONSENT.
 */
export function handleBiometricSignalInferenceDetected(): {
  event: ConstitutionalViolationEvent;
  mustTriggerHemConsent: true;
} {
  return {
    event: { tier: "TIER_0A", violation_class: "BIOMETRIC_SIGNAL_INFERENCE", detected_at: new Date().toISOString() },
    mustTriggerHemConsent: true,
  };
}

/** §9.4(a) — HRS D5 must exclude biometric signals absent valid biometric_monitoring consent. */
export function d5MustExcludeBiometrics(biometricMonitoringConsentValid: boolean): boolean {
  return !biometricMonitoringConsentValid;
}
