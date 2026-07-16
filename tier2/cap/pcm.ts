import { CapError, UNCLEARABLE_CLASSES, type ProhibitionClearanceRecord } from "./types.js";

/** §11.2: a PCR naming any of the five unclearable classes MUST be rejected at load time. */
export function assertPcrClassClearable(pcr: ProhibitionClearanceRecord): void {
  if (UNCLEARABLE_CLASSES.has(pcr.prohibition_class)) {
    throw new CapError(
      "PCR_REJECTED_UNCLEARABLE_CLASS",
      `§11.2: prohibition_class "${pcr.prohibition_class}" MUST NOT be cleared by any PCR under any circumstances`,
    );
  }
  if (!pcr.expiry_date) {
    throw new CapError("PCR_REJECTED_UNCLEARABLE_CLASS", "§11.6: expiry_date is REQUIRED — permanent clearances are not permitted");
  }
}

/** §11.4: Mode 2 requires the regulatory signature in addition to operator + audit principal. */
export function assertMode2HasRegulatorySignature(pcr: ProhibitionClearanceRecord, mode: "MODE_1" | "MODE_2"): void {
  if (mode === "MODE_2" && !pcr.regulatory_signature) {
    throw new CapError("PCR_REJECTED_UNCLEARABLE_CLASS", "§11.4: Mode 2 (Regulatory Clearance Record) REQUIRES a regulatory_signature");
  }
}

/** §11.7 — Clearance Registry: in-memory index, rebuilt from GEC Manifest on restart. */
export class ClearanceRegistry {
  private pcrs: Map<string, ProhibitionClearanceRecord> = new Map();

  register(pcr: ProhibitionClearanceRecord, mode: "MODE_1" | "MODE_2"): void {
    assertPcrClassClearable(pcr);
    assertMode2HasRegulatorySignature(pcr, mode);
    this.pcrs.set(pcr.pcr_id, pcr);
  }

  /** §11.7 — an expired PCR MUST NOT be applied; the GEC MUST generate a PCR_EXPIRED Audit Alert. */
  findActive(prohibitionClass: string, nowMs: number): { pcr: ProhibitionClearanceRecord | null; expiredAlert: boolean } {
    const candidate = [...this.pcrs.values()].find((p) => p.prohibition_class === prohibitionClass);
    if (!candidate) return { pcr: null, expiredAlert: false };
    const expired = Date.parse(candidate.expiry_date) <= nowMs;
    return { pcr: expired ? null : candidate, expiredAlert: expired };
  }

  rebuildFromManifest(pcrs: ProhibitionClearanceRecord[]): void {
    this.pcrs.clear();
    for (const p of pcrs) this.pcrs.set(p.pcr_id, p);
  }
}
