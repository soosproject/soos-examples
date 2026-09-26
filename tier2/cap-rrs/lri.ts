import { CapRrsError, type AuthoritySource } from "./types.js";

/** §9.6: interpretation_endpoint field REQUIRED (even if null) when resolution_basis MAY be interpretive_ruling. */
export function assertInterpretationEndpointPresent(source: AuthoritySource): void {
  if (source.endorsement.resolution_basis === "interpretive_ruling" && source.interpretation_endpoint === undefined) {
    throw new CapRrsError("INTERPRETATION_ENDPOINT_REQUIRED", "§9.6: interpretation_endpoint is REQUIRED (even if null) when resolution_basis is interpretive_ruling");
  }
  if (source.endorsement.resolution_basis === "interpretive_ruling" && !source.endorsement.resolution_instrument_id) {
    throw new CapRrsError("LRI_REQUIREMENT_VIOLATION", "§9.4 Table 1: resolution_instrument_id MUST be populated when resolution_basis is interpretive_ruling");
  }
}

/** §9.4 Table 1: cross_statute_coordination REQUIRES co_endorsement_required true and quorum "all". */
export function assertCrossStatuteCoordinationRequirements(source: AuthoritySource): void {
  if (source.endorsement.resolution_basis === "cross_statute_coordination") {
    if (!source.endorsement.co_endorsement_required) {
      throw new CapRrsError("LRI_REQUIREMENT_VIOLATION", "§9.4 Table 1: cross_statute_coordination REQUIRES co_endorsement_required: true");
    }
    if (source.endorsement.co_endorsement_quorum !== "all") {
      throw new CapRrsError("LRI_REQUIREMENT_VIOLATION", '§9.4 Table 1: cross_statute_coordination REQUIRES co_endorsement_quorum: "all"');
    }
  }
}

/** §9.3 LRI-1 through LRI-5 — structural presence check (an LRI Profile MUST define all five). */
export interface LriProfileDefinition {
  law_id_scheme_defined: boolean; // LRI-1
  article_ref_resolvable: boolean; // LRI-2
  version_identifier_derivable: boolean; // LRI-3
  amendment_detection_since_param_supported: boolean; // LRI-4
  authority_id_endorser_table_defined: boolean; // LRI-5
}

export function assertLriProfileComplete(profile: LriProfileDefinition): void {
  const missing = Object.entries(profile).filter(([, v]) => !v).map(([k]) => k);
  if (missing.length > 0) {
    throw new CapRrsError("LRI_REQUIREMENT_VIOLATION", `§9.3: LRI Profile missing normative requirement(s): ${missing.join(", ")}`);
  }
}
