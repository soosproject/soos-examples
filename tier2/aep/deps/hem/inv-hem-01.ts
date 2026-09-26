import { HemError, type HemEscalationRequest, type HemInteractionClass } from "./types.js";

/** §10 required-field sets per interaction class — informationcompleteness (a). */
const REQUIRED_FIELDS_BY_CLASS: Partial<Record<HemInteractionClass, (keyof HemEscalationRequest)[]>> = {
  "HEM-LIM-1": ["limitation_declaration"],
  "HEM-DIV-1": ["deliberation_record"],
  "HEM-CONSENT": ["consent_escalation"],
  "HEM-DS-1": ["options_presentation"],
};

/** §10(a) Information completeness. */
export function assertInformationComplete(request: HemEscalationRequest): void {
  const requiredFields = request.interaction_class ? REQUIRED_FIELDS_BY_CLASS[request.interaction_class] : undefined;
  if (!requiredFields) return;
  for (const field of requiredFields) {
    if (request[field] === undefined) {
      throw new HemError(
        "HEM_SUPPRESSION_DETECTED",
        `INV-HEM-01(a): required field '${String(field)}' missing for interaction_class ${request.interaction_class}`,
      );
    }
  }
}

/** §10(b) Concurrent violation surfacing — MUST NOT defer a Tier 0-A surface until the pending event resolves. */
export function assertConcurrentViolationSurfacedImmediately(surfacedImmediately: boolean): void {
  if (!surfacedImmediately) {
    throw new HemError("HEM_SUPPRESSION_DETECTED", "INV-HEM-01(b): concurrent Tier 0-A violation was not surfaced without delay");
  }
}

/** §10(d) Delivery intermediary MUST NOT modify/redact/summarize. */
export function assertRequestUnmodifiedByIntermediary(originalHash: string, deliveredHash: string): void {
  if (originalHash !== deliveredHash) {
    throw new HemError(
      "HEM_SUPPRESSION_DETECTED",
      "INV-HEM-01(d): delivery intermediary modified, redacted, or summarized the escalation request content",
    );
  }
}

export type SuppressionSource = "AGENT" | "OPERATOR" | "APPLICATION" | "DELIVERY_INTERMEDIARY";

export interface SuppressionDetectedEvent {
  hem_id: string;
  session_id: string;
  suppression_source: SuppressionSource;
  suppression_description: string;
  detected_at: string;
}

/** §15 INV_HEM_01_SUPPRESSION_DETECTED — CRITICAL Audit Alert record. */
export function buildSuppressionDetectedEvent(
  hemId: string,
  sessionId: string,
  source: SuppressionSource,
  description: string,
): SuppressionDetectedEvent {
  return { hem_id: hemId, session_id: sessionId, suppression_source: source, suppression_description: description, detected_at: new Date().toISOString() };
}
