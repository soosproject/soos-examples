import { CapError, type Ptd, type PtdActiveProhibitionEntry } from "./types.js";

/** §12a.3 — permitted disclosure_level values by tier. */
const ALLOWED_DISCLOSURE_LEVELS: Record<PtdActiveProhibitionEntry["tier"], ReadonlyArray<PtdActiveProhibitionEntry["disclosure_level"]>> = {
  TIER_0A: ["FULL"],
  TIER_0B: ["FULL"],
  TIER_1: ["FULL", "REDACTED"],
  TIER_2: ["FULL", "REDACTED", "COUNT_ONLY"],
  TIER_3: ["COUNT_ONLY"],
};

export function assertDisclosureLevelValid(entry: PtdActiveProhibitionEntry): void {
  const allowed = ALLOWED_DISCLOSURE_LEVELS[entry.tier];
  if (!allowed.includes(entry.disclosure_level)) {
    throw new CapError(
      "TRANSPARENCY_VIOLATION",
      `§12a.3: ${entry.tier} record ${entry.record_id} has disclosure_level "${entry.disclosure_level}", only ${allowed.join("/")} permitted`,
    );
  }
}

/** §12a.5: operators MUST NOT refuse valid regulatory-authority PTD queries, MUST NOT redact Tier 0. */
export function assertRegulatoryQueryNotRefused(requesterHasValidRegulatoryCredentials: boolean, wasRefused: boolean): void {
  if (requesterHasValidRegulatoryCredentials && wasRefused) {
    throw new CapError("TRANSPARENCY_VIOLATION", "§12a.5: PTD queries from regulatory authorities with valid credentials MUST NOT be refused");
  }
}

/** §12a.6 — CAP_TRANSPARENCY_VIOLATION triggers, (a)-(d). */
export function detectTransparencyViolations(
  ptd: Ptd,
  liveCedarPolicyHash: string,
  allTier0RecordIds: string[],
  regulatoryQueryRefused: boolean,
): string[] {
  const violations: string[] = [];

  if (ptd.cedar_policy_hash !== liveCedarPolicyHash) {
    violations.push("(a) PTD cedar_policy_hash does not match GEC Manifest at query time");
  }

  const disclosedTier0Ids = new Set(ptd.active_prohibitions.filter((p) => p.tier === "TIER_0A" || p.tier === "TIER_0B").map((p) => p.record_id));
  for (const id of allTier0RecordIds) {
    if (!disclosedTier0Ids.has(id)) violations.push(`(b) Tier 0 record ${id} is missing from the PTD`);
  }

  for (const entry of ptd.active_prohibitions) {
    if ((entry.tier === "TIER_0A" || entry.tier === "TIER_0B") && entry.disclosure_level !== "FULL") {
      violations.push(`(c) Tier 0 record ${entry.record_id} present with disclosure_level "${entry.disclosure_level}"`);
    }
  }

  if (regulatoryQueryRefused) violations.push("(d) a PTD query from a valid regulatory authority was refused");

  return violations;
}

/** §12a.4 — PTD_QUERIED Event Log entry on every query. */
export function buildPtdQueriedLogEntry(requesterId: string, ptd: Ptd): { requester_id: string; timestamp: string; ptd_version: string; cedar_policy_hash: string } {
  return { requester_id: requesterId, timestamp: new Date().toISOString(), ptd_version: ptd.ptd_version, cedar_policy_hash: ptd.cedar_policy_hash };
}

/** CONF-CAP-OSCAL-01: a GEC MUST NOT declare Tier 0-A classes not present in the published OSCAL reference catalog. */
export function assertTier0AClassInOscalCatalog(declaredClass: string, oscalCatalogClasses: ReadonlySet<string>): void {
  if (!oscalCatalogClasses.has(declaredClass)) {
    throw new CapError("TRANSPARENCY_VIOLATION", `CONF-CAP-OSCAL-01: Tier 0-A class "${declaredClass}" is not present in the published Tier 0 OSCAL reference catalog at the cited version`);
  }
}
