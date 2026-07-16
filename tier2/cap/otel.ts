import { CapError } from "./types.js";

export interface CapOtelSpanAttributes {
  "soos.cap.cedar_policy_id": string;
  "soos.cap.cap_rrs_control_id": string;
  "soos.cap.authority_source_uri": string;
  "soos.cap.tier": "0-A" | "0-B" | "1" | "2";
  "soos.cap.conflict_detected": boolean;
}

/** CONF-CAP-OTEL-01: all five attributes MUST be emitted on every Cedar evaluation — partial emission is not conforming. */
export function assertAllFiveAttributesPresent(attrs: Partial<CapOtelSpanAttributes>): asserts attrs is CapOtelSpanAttributes {
  const required: (keyof CapOtelSpanAttributes)[] = [
    "soos.cap.cedar_policy_id",
    "soos.cap.cap_rrs_control_id",
    "soos.cap.authority_source_uri",
    "soos.cap.tier",
    "soos.cap.conflict_detected",
  ];
  const missing = required.filter((k) => attrs[k] === undefined);
  if (missing.length > 0) {
    throw new CapError("TRANSPARENCY_VIOLATION", `CONF-CAP-OTEL-01: partial OTel attribute emission — missing: ${missing.join(", ")}`);
  }
}

/** CONF-CAP-OTEL-02: authority_source_uri MUST be the same URI as the matched record's authority_ref — no substitution. */
export function assertAuthoritySourceUriMatches(emittedUri: string, matchedRecordAuthorityRef: string): void {
  if (emittedUri !== matchedRecordAuthorityRef) {
    throw new CapError("TRANSPARENCY_VIOLATION", `CONF-CAP-OTEL-02: emitted authority_source_uri "${emittedUri}" does not match matched record's authority_ref "${matchedRecordAuthorityRef}"`);
  }
}

export function emitCapOtelSpan(attrs: CapOtelSpanAttributes): CapOtelSpanAttributes {
  assertAllFiveAttributesPresent(attrs);
  return attrs;
}
