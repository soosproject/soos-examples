import { writeFileSync, mkdirSync } from "node:fs";
import { CapRrsError } from "../cap-rrs/types.js";
import { assertLriProfileComplete } from "../cap-rrs/lri.js";
import { assertCoEndorsementQuorumMet, type CoEndorserStatus } from "../cap-rrs/co-endorsement.js";
import { assertValidLawId, assertArabicNumeralXPath, buildArticleXPath, buildAmendmentDetectionUrl, buildInterpretationEndpointUrl, JP_LRI_PROFILE_URI } from "./jp-lri-profile.js";
import { requiredEndorserForResolutionBasis, assertJpCrossStatuteQuorumIsAll, CABINET_LEGAL_AFFAIRS_BUREAU_URI, LAWTYPE_ENDORSER_TABLE } from "./endorsement-authority.js";
import { buildAppiArticle17WorkedExample, APPI_LAW_ID } from "./appi-worked-example.js";

type SvlLog = { id: string; kind: "happy" | "edge"; scenario: string; conformance_refs: string[]; outcome: "PASS" | "DENY"; deny_code?: string | undefined; detail: string };
const logs: SvlLog[] = [];
function log(entry: SvlLog) {
  logs.push(entry);
  console.log(`[${entry.kind.toUpperCase()}] ${entry.id} ${entry.outcome === "PASS" ? "PASS" : `DENY(${entry.deny_code})`} — ${entry.scenario}`);
}

console.log("=== SOOS Step 10.5 — CAP-RRS-JP (draft-sato-soos-cap-rrs-jp-00) ===\n");
console.log("NOTE: draft-sato-soos-cap-rrs-01 was supplied this session, resolving SDB-CAPRRS-01 as a source-\n");
console.log("availability gap. This module imports cap-rrs's real AuthoritySource/LRI types directly — no stubs.\n");

// 1. HP: JP LRI Profile registered, five normative requirements satisfied
{
  try {
    assertLriProfileComplete({ law_id_scheme_defined: true, article_ref_resolvable: true, version_identifier_derivable: true, amendment_detection_since_param_supported: true, authority_id_endorser_table_defined: true });
    log({ id: "HP-CAPRRSJP-01", kind: "happy", scenario: `Japan LRI Profile (${JP_LRI_PROFILE_URI}) satisfies all five CAP-RRS §9.3 normative requirements`, conformance_refs: ["CAP-RRS-JP §3", "CAP-RRS §9.3"], outcome: "PASS", detail: "complete" });
  } catch (e) {
    if (e instanceof CapRrsError) log({ id: "HP-CAPRRSJP-01", kind: "happy", scenario: "LRI profile completeness", conformance_refs: ["§9.3"], outcome: "DENY", deny_code: e.code, detail: e.message });
  }
}

// 2. HP: law_id validation
{
  try {
    assertValidLawId(APPI_LAW_ID);
    log({ id: "HP-CAPRRSJP-02", kind: "happy", scenario: `APPI law_id "${APPI_LAW_ID}" validates as a 15-char e-LAWS 法令ID`, conformance_refs: ["§4.1"], outcome: "PASS", detail: APPI_LAW_ID });
  } catch (e) {
    if (e instanceof CapRrsError) log({ id: "HP-CAPRRSJP-02", kind: "happy", scenario: "law_id validation", conformance_refs: ["§4.1"], outcome: "DENY", deny_code: e.code, detail: e.message });
  }
}
try {
  assertValidLawId("not-a-real-id");
  log({ id: "EDGE-CAPRRSJP-01", kind: "edge", scenario: "Malformed law_id (not 15-char alphanumeric) accepted", conformance_refs: ["§4.1"], outcome: "PASS", detail: "UNEXPECTED: accepted" });
} catch (e) {
  if (e instanceof CapRrsError) log({ id: "EDGE-CAPRRSJP-01", kind: "edge", scenario: "Malformed law_id correctly rejected", conformance_refs: ["§4.1"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 3. HP + EDGE: Arabic vs Japanese numeral XPath — the most-repeated warning across both drafts
{
  const xpath = buildArticleXPath("17", { chapterNum: "4", paragraphNum: "1" });
  log({ id: "HP-CAPRRSJP-03", kind: "happy", scenario: `Article 17 XPath built with Arabic numerals: ${xpath}`, conformance_refs: ["§4.2"], outcome: "PASS", detail: xpath });
}
try {
  assertArabicNumeralXPath("/Law/LawBody/MainProvision/Article[@Num='十七']"); // 十七 = "17" in Japanese numerals
  log({ id: "EDGE-CAPRRSJP-02", kind: "edge", scenario: "XPath using Japanese numeral form (十七, not 17) accepted — this XPath would match nothing in the real schema", conformance_refs: ["§4.2 Critical constraint"], outcome: "PASS", detail: "UNEXPECTED: accepted" });
} catch (e) {
  if (e instanceof CapRrsError) log({ id: "EDGE-CAPRRSJP-02", kind: "edge", scenario: "Japanese-numeral XPath correctly rejected — @Num MUST use Arabic numerals", conformance_refs: ["§4.2 Critical constraint"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 4. HP: endpoint URL builders
{
  const amendUrl = buildAmendmentDetectionUrl("2022-04-01");
  const interpUrl = buildInterpretationEndpointUrl(APPI_LAW_ID, "/Law/LawBody/MainProvision/Chapter[@Num='4']/Article[@Num='17']/Paragraph[@Num='1']");
  log({ id: "HP-CAPRRSJP-04", kind: "happy", scenario: "amendment_detection_endpoint and interpretation_endpoint URLs built per §4.4/§4.5", conformance_refs: ["§4.4", "§4.5"], outcome: amendUrl.includes("2022-04-01") && interpUrl.includes(APPI_LAW_ID) ? "PASS" : "DENY", detail: JSON.stringify({ amendUrl, interpUrl }) });
}

// 5. HP: LawType endorser table — Act (法律) -> 内閣法制局
{
  const endorser = requiredEndorserForResolutionBasis("Act", "statute_clear");
  log({ id: "HP-CAPRRSJP-05", kind: "happy", scenario: "APPI (Act/法律) with statute_clear basis — standard endorser is 内閣法制局 per Table 1", conformance_refs: ["§5.1"], outcome: endorser.authorityId === CABINET_LEGAL_AFFAIRS_BUREAU_URI ? "PASS" : "DENY", detail: JSON.stringify(endorser) });
}

// 6. EDGE: internal_conflict_resolution overrides LawType-based endorser — Appendix B.1 disaster scenario (§49の11 internal contradiction)
{
  // Ministerial LawType would normally route to 所管省庁, but internal_conflict_resolution always elevates regardless.
  const endorser = requiredEndorserForResolutionBasis("Ministerial", "internal_conflict_resolution");
  log({
    id: "EDGE-CAPRRSJP-03",
    kind: "edge",
    scenario: "Appendix B.1: 災害対策基本法 §49の11②③ internal contradiction (名簿 sharing vs. consent confirmation) — Ministerial LawType would normally route to 所管省庁, but internal_conflict_resolution unconditionally elevates to 内閣法制局",
    conformance_refs: ["§5.2", "Appendix B.1 (OQ-BOSAI-001)"],
    outcome: endorser.authorityId === CABINET_LEGAL_AFFAIRS_BUREAU_URI ? "DENY" : "PASS",
    deny_code: endorser.authorityId === CABINET_LEGAL_AFFAIRS_BUREAU_URI ? "LRI_REQUIREMENT_VIOLATION" : undefined,
    detail: `elevated_to=${endorser.label}, reason=${endorser.reason}`,
  });
}

// 7. HP + EDGE: cross_statute_coordination co-endorsement — Appendix B.2 dual command authority (防災庁 + 都道府県知事)
{
  assertJpCrossStatuteQuorumIsAll("cross_statute_coordination", "all"); // should not throw
  const coEndorsers: CoEndorserStatus[] = [
    { authority_id: "https://cao.go.jp/bosaicho/authority", endorsement_claim_valid: true },
    { authority_id: "https://cao.go.jp/authority/chiji-coordination", endorsement_claim_valid: true },
  ];
  const source = {
    lri_version: "1.0" as const,
    profile: "https://laws.e-gov.go.jp/lri/v1",
    law_id: "00000000000BOSAI",
    article_ref: "/Law/LawBody/MainProvision/Article[@Num='12']",
    version_identifier: "2026-01-01",
    retrieved_at: new Date().toISOString(),
    amendment_detection_endpoint: "https://laws.e-gov.go.jp/api/2/updatelawlists/{date}",
    interpretation_endpoint: null,
    endorsement: {
      authority_id: "https://cao.go.jp/bosaicho/authority",
      endorsed_at: new Date().toISOString(),
      endorsement_scope: "full_article" as const,
      resolution_basis: "cross_statute_coordination" as const,
      co_endorsement_required: true,
      co_endorsement_quorum: "all" as const,
      co_endorsers: ["https://cao.go.jp/bosaicho/authority", "https://cao.go.jp/authority/chiji-coordination"],
      endorsement_claim: "<signed JWT>",
    },
  };
  try {
    assertCoEndorsementQuorumMet(source, coEndorsers);
    log({ id: "HP-CAPRRSJP-06", kind: "happy", scenario: "Appendix B.2: 防災庁 勧告権 + 都道府県知事 evacuation authority dual-command coordination — both co-endorsers present, quorum 'all' met", conformance_refs: ["§5.3", "Appendix B.2 (OQ-BOSAI-002)"], outcome: "PASS", detail: "quorum met" });
  } catch (e) {
    if (e instanceof CapRrsError) log({ id: "HP-CAPRRSJP-06", kind: "happy", scenario: "dual-command co-endorsement", conformance_refs: ["§5.3"], outcome: "DENY", deny_code: e.code, detail: e.message });
  }
}
try {
  assertJpCrossStatuteQuorumIsAll("cross_statute_coordination", "primary_only");
  log({ id: "EDGE-CAPRRSJP-04", kind: "edge", scenario: "cross_statute_coordination with quorum 'primary_only' (generic CAP-RRS allows this elsewhere, Japan profile does not)", conformance_refs: ["§5.3"], outcome: "PASS", detail: "UNEXPECTED: accepted" });
} catch (e) {
  if (e instanceof CapRrsError) log({ id: "EDGE-CAPRRSJP-04", kind: "edge", scenario: "Japan profile correctly requires quorum 'all' for cross_statute_coordination, stricter than the generic default", conformance_refs: ["§5.3"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 8. HP: full APPI Article 17 worked example, built and validated end-to-end
{
  const source = buildAppiArticle17WorkedExample(new Date().toISOString(), new Date().toISOString());
  log({ id: "HP-CAPRRSJP-07", kind: "happy", scenario: "APPI Article 17 worked example built as a real AuthoritySource, reusing CAP-RRS's type directly (no JP-specific type duplication)", conformance_refs: ["§6.2"], outcome: source.law_id === APPI_LAW_ID && source.article_ref.includes("Chapter[@Num='4']") ? "PASS" : "DENY", detail: JSON.stringify(source.endorsement) });
}

// ---------------------------------------------------------------------------
const happy = logs.filter((l) => l.kind === "happy").length;
const edge = logs.filter((l) => l.kind === "edge").length;
console.log(`\n${happy} happy-path + ${edge} edge/adversarial logs generated.`);
console.log("Covers §4 (field bindings), §5 (endorsement authority table incl. elevated-authority override");
console.log("and Japan-specific co-endorsement quorum), and the §6.2 APPI Article 17 worked example.");
console.log("Not built: §6.3/6.4 (名簿/個別避難計画 worked examples), §7 (e-Gov publication workflow),");
console.log("§8 (INTERPRETATION_SUPERSEDED Japan-context detail) — scoped out for this pass, not a gap per se.");

mkdirSync("svl/corpus-b/cap-rrs-jp", { recursive: true });
writeFileSync("svl/corpus-b/cap-rrs-jp/logs.json", JSON.stringify(logs, null, 2));
console.log("Corpus written to svl/corpus-b/cap-rrs-jp/logs.json");
