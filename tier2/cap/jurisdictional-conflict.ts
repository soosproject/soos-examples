import { CapError, type JurisdictionalConflictRecord } from "./types.js";

export type ConflictResolutionMethod = "MOST_PROTECTIVE" | "PRIMARY_JURISDICTION" | "HEM";

/** §13.3 — HEM Class 5 decision type constraints: APPROVE and APPROVE_WITH_CONSTRAINTS are prohibited. */
const PROHIBITED_CLASS_5_DECISIONS = new Set(["APPROVE", "APPROVE_WITH_CONSTRAINTS"]);
const PERMITTED_CLASS_5_DECISIONS = new Set(["APPROVE_WITH_LEGAL_BASIS", "REDIRECT", "TERMINATE", "DEFER"]);

export function assertClass5DecisionValid(decisionType: string): void {
  if (PROHIBITED_CLASS_5_DECISIONS.has(decisionType)) {
    throw new CapError("APPROVE_WITH_LEGAL_BASIS_INVALID", `§13.3: decision type "${decisionType}" is prohibited for HEM_JURISDICTIONAL_CONFLICT (Class 5)`);
  }
  if (!PERMITTED_CLASS_5_DECISIONS.has(decisionType)) {
    throw new CapError("APPROVE_WITH_LEGAL_BASIS_INVALID", `§13.3: decision type "${decisionType}" is not among the permitted set for Class 5: ${[...PERMITTED_CLASS_5_DECISIONS].join(", ")}`);
  }
}

export function buildJurisdictionalConflictRecord(f: Omit<JurisdictionalConflictRecord, "timestamp">): JurisdictionalConflictRecord {
  return { ...f, timestamp: new Date().toISOString() };
}
