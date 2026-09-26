// SOOS Step 10.5 — Japan e-LAWS LRI Profile for CAP-RRS
// Built against draft-sato-soos-cap-rrs-jp-00, which extends CAP-RRS
// (draft-sato-soos-cap-rrs-02 §9) with Japan-specific bindings.
// This is a profile, not a new protocol mechanism — it reuses cap-rrs's
// AuthoritySource/ResolutionBasis types and validators directly.

import { CapRrsError, type AuthoritySource } from "../cap-rrs/types.js";

export const JP_LRI_PROFILE_URI = "https://laws.e-gov.go.jp/lri/v1";

// ---------------------------------------------------------------------------
// §4.1 — law_id binding: e-LAWS 法令ID, 15-char alphanumeric, stable across amendments
// ---------------------------------------------------------------------------

const LAW_ID_PATTERN = /^[0-9A-Z]{15}$/;

export function assertValidLawId(lawId: string): void {
  if (!LAW_ID_PATTERN.test(lawId)) {
    throw new CapRrsError("LRI_REQUIREMENT_VIOLATION", `§4.1: law_id "${lawId}" is not a valid 15-character e-LAWS 法令ID`);
  }
}

export function lawDataApiUrl(lawId: string): string {
  return `https://laws.e-gov.go.jp/api/2/lawdata/${lawId}`;
}

// ---------------------------------------------------------------------------
// §4.2 — article_ref binding: XPath 1.0, Arabic numerals only
// ---------------------------------------------------------------------------

/**
 * §4.2 "Critical constraint": @Num attributes ALWAYS use Arabic numerals.
 * A query using Japanese numeral form (三十二, not 32) will fail to match
 * anything in the XML schema — this is the single most-repeated warning
 * across both the CAP-RRS-02 and CAP-RRS-JP-00 drafts, so it gets its own
 * assertion rather than being folded into a generic XPath validity check.
 */
const JAPANESE_NUMERAL_PATTERN = /[一二三四五六七八九十百千]/;

export function assertArabicNumeralXPath(xpath: string): void {
  if (JAPANESE_NUMERAL_PATTERN.test(xpath)) {
    throw new CapRrsError("LRI_REQUIREMENT_VIOLATION", `§4.2: article_ref "${xpath}" uses Japanese numeral form — @Num attributes MUST use Arabic numerals, this XPath will match nothing`);
  }
}

export function buildArticleXPath(articleNum: string, opts?: { chapterNum?: string; paragraphNum?: string; itemNum?: string; supplementary?: boolean }): string {
  const base = opts?.supplementary ? "/Law/LawBody/SupplProvision" : "/Law/LawBody/MainProvision";
  const chapter = opts?.chapterNum ? `/Chapter[@Num='${opts.chapterNum}']` : "";
  let xpath = `${base}${chapter}/Article[@Num='${articleNum}']`;
  if (opts?.paragraphNum) xpath += `/Paragraph[@Num='${opts.paragraphNum}']`;
  if (opts?.itemNum) xpath += `/Item[@Num='${opts.itemNum}']`;
  assertArabicNumeralXPath(xpath);
  return xpath;
}

// ---------------------------------------------------------------------------
// §4.3 — version_identifier: ISO8601 date of most recent EnforcementDate
// ---------------------------------------------------------------------------

export function extractVersionIdentifier(lawDataApiResponse: { amendmentInfoList: Array<{ enforcementDate: string }> }): string {
  if (lawDataApiResponse.amendmentInfoList.length === 0) {
    throw new CapRrsError("LRI_REQUIREMENT_VIOLATION", "§4.3: no AmendmentInfo entries found — cannot derive version_identifier");
  }
  return lawDataApiResponse.amendmentInfoList.reduce((latest, a) => (Date.parse(a.enforcementDate) > Date.parse(latest.enforcementDate) ? a : latest)).enforcementDate;
}

// ---------------------------------------------------------------------------
// §4.4 — amendment_detection_endpoint (fixed for all Japan-profile laws)
// ---------------------------------------------------------------------------

export const JP_AMENDMENT_DETECTION_ENDPOINT_TEMPLATE = "https://laws.e-gov.go.jp/api/2/updatelawlists/{date}";

export function buildAmendmentDetectionUrl(sinceDate: string): string {
  return JP_AMENDMENT_DETECTION_ENDPOINT_TEMPLATE.replace("{date}", sinceDate);
}

// ---------------------------------------------------------------------------
// §4.5 — interpretation_endpoint (provisional SOOS-operated registry)
// ---------------------------------------------------------------------------

export function buildInterpretationEndpointUrl(lawId: string, articleRef: string): string {
  const safeArticleRef = articleRef.replace(/\//g, "_").replace(/[[\]']/g, "");
  return `https://clawed.soosproject.com/jp/interpretations/${lawId}/${safeArticleRef}`;
}

/** §4.5: provisional registry scope is 官報 (Official Gazette) instruments only — 通達 (administrative circulars) excluded pending JP-OQ-03. */
export const JP_INTERPRETATION_REGISTRY_SCOPE = {
  included: ["cabinet_order", "ministerial_guidance", "court_judgment"] as const,
  excludedPendingJpOq03: ["administrative_circular_通達"] as const,
};

// ---------------------------------------------------------------------------
// Full authority_source builder for the Japan profile
// ---------------------------------------------------------------------------

export function buildJpAuthoritySource(f: {
  lawId: string;
  articleXPath: string;
  versionIdentifier: string;
  retrievedAt: string;
  endorsement: AuthoritySource["endorsement"];
}): AuthoritySource {
  assertValidLawId(f.lawId);
  assertArabicNumeralXPath(f.articleXPath);
  return {
    lri_version: "1.0",
    profile: JP_LRI_PROFILE_URI,
    law_id: f.lawId,
    article_ref: f.articleXPath,
    version_identifier: f.versionIdentifier,
    retrieved_at: f.retrievedAt,
    amendment_detection_endpoint: JP_AMENDMENT_DETECTION_ENDPOINT_TEMPLATE,
    interpretation_endpoint: buildInterpretationEndpointUrl(f.lawId, f.articleXPath),
    endorsement: f.endorsement,
  };
}
