import { CapRrsError } from "./types.js";

/** §11.1 / §11.2 — both amendment and interpretation detection MUST poll at intervals not exceeding 24 hours. */
export const DETECTION_MAX_INTERVAL_HOURS = 24;

export function assertDetectionCadenceConforming(pollIntervalHours: number, kind: "amendment" | "interpretation"): void {
  if (pollIntervalHours > DETECTION_MAX_INTERVAL_HOURS) {
    throw new CapRrsError("LRI_REQUIREMENT_VIOLATION", `§11.${kind === "amendment" ? "1" : "2"}: ${kind} detection cadence ${pollIntervalHours}h exceeds the 24h maximum`);
  }
}

/** §11.3 — 30-day maximum suspension window, cross-references CAP-04 §8.9.4 (same 30-day maximum from the CAP perspective). */
export const MAX_SUSPENSION_WINDOW_DAYS = 30;

export function assertNoSilentSuspensionConversion(suspendedSinceMs: number, nowMs: number, operatorNotified: boolean, criticalAlertGenerated: boolean): { mustConvertToDeny: boolean } {
  const daysSuspended = (nowMs - suspendedSinceMs) / (1000 * 60 * 60 * 24);
  if (daysSuspended > MAX_SUSPENSION_WINDOW_DAYS) {
    if (!operatorNotified || !criticalAlertGenerated) {
      throw new CapRrsError("SUSPENSION_WINDOW_EXCEEDED_SILENT_DROP", "§11.3: 30-day maximum exceeded — GEC MUST notify operator + generate CRITICAL Audit Alert before converting SUSPENDED to DENY");
    }
    return { mustConvertToDeny: true };
  }
  return { mustConvertToDeny: false };
}

/** §11.4: authority_source_uri MUST equal the soos.cap.authority_source_uri OTel attribute emitted at Cedar evaluation time (CAP-04 §13.5); mismatch is a PTD inconsistency under CAP-04 §12a.6. */
export function assertAuthoritySourceUriMatchesOtel(regulationRecordUri: string, emittedOtelUri: string): void {
  if (regulationRecordUri !== emittedOtelUri) {
    throw new CapRrsError(
      "AUTHORITY_SOURCE_URI_MISMATCH",
      `§11.4: authority_source_uri "${regulationRecordUri}" does not match emitted soos.cap.authority_source_uri "${emittedOtelUri}" — PTD inconsistency per CAP-04 §12a.6`,
    );
  }
}
