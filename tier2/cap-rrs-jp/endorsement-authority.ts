import { CapRrsError, type ResolutionBasis } from "../cap-rrs/types.js";

export type JpLawType = "Constitution" | "Act" | "CabinetOrder" | "Ministerial" | "Misc";

/** §5.1 Table 1 — LawType to designated endorser mapping. */
export const LAWTYPE_ENDORSER_TABLE: Record<JpLawType, { authorityId: string; label: string }> = {
  Constitution: { authorityId: "https://www.clb.go.jp/authority", label: "内閣法制局" },
  Act: { authorityId: "https://www.clb.go.jp/authority", label: "内閣法制局" },
  CabinetOrder: { authorityId: "https://www.clb.go.jp/authority", label: "内閣法制局" },
  Ministerial: { authorityId: "https://www.digital.go.jp/authority", label: "所管省庁 法令担当部局 (example: Ministry of Digital Affairs)" },
  Misc: { authorityId: "https://[prefecture-code].pref.jp/authority", label: "都道府県法務・法制担当部局 (or 市区町村法務担当 with prefecture-level co-endorsement)" },
};

export const CABINET_LEGAL_AFFAIRS_BUREAU_URI = "https://www.clb.go.jp/authority";

/**
 * §5.2 Elevated Authority Requirements — the designated endorser per Table 1
 * is NOT sufficient for internal_conflict_resolution, regardless of LawType.
 * 内閣法制局 endorsement is required unconditionally for that resolution_basis.
 */
export function requiredEndorserForResolutionBasis(lawType: JpLawType, resolutionBasis: ResolutionBasis): { authorityId: string; label: string; reason: string } {
  if (resolutionBasis === "internal_conflict_resolution") {
    return { authorityId: CABINET_LEGAL_AFFAIRS_BUREAU_URI, label: "内閣法制局", reason: "§5.2: internal_conflict_resolution always requires 内閣法制局 endorsement, overriding the standard LawType-based endorser regardless of LawType" };
  }
  const standard = LAWTYPE_ENDORSER_TABLE[lawType];
  return { authorityId: standard.authorityId, label: standard.label, reason: `§5.1 Table 1: standard LawType-based endorser for ${lawType}` };
}

/** §5.2: resolution_instrument_id MUST be populated + findable via interpretation_endpoint when resolution_basis is interpretive_ruling. */
export function assertInterpretiveRulingInstrumentPresent(resolutionInstrumentId: string | undefined): void {
  if (!resolutionInstrumentId) {
    throw new CapRrsError("LRI_REQUIREMENT_VIOLATION", "§5.2: resolution_instrument_id MUST be populated when resolution_basis is interpretive_ruling");
  }
}

// ---------------------------------------------------------------------------
// §5.3 — Co-Endorsement in Japan Context
// ---------------------------------------------------------------------------

export interface JpCoEndorser {
  authority_id: string;
  authority_role: string;
  endorsed_at: string;
  endorsement_claim: string;
}

/** §5.3: co_endorsement_quorum MUST be "all" for cross_statute_coordination in Japan deployments (stricter than the generic CAP-RRS default of allowing primary_only elsewhere). */
export function assertJpCrossStatuteQuorumIsAll(resolutionBasis: ResolutionBasis, quorum: string | undefined): void {
  if (resolutionBasis === "cross_statute_coordination" && quorum !== "all") {
    throw new CapRrsError("LRI_REQUIREMENT_VIOLATION", '§5.3: co_endorsement_quorum MUST be "all" for cross_statute_coordination in Japan deployments');
  }
}
