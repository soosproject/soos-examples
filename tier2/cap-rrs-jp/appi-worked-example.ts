import type { AuthoritySource } from "../cap-rrs/types.js";
import { buildJpAuthoritySource, buildArticleXPath } from "./jp-lri-profile.js";

export const APPI_LAW_ID = "325AC0000000089";
export const APPI_CHAPTER_IV_XPATH_PREFIX = "/Law/LawBody/MainProvision/Chapter[@Num='4']";

/** §6.2 Worked Example 1 — APPI Article 17(1), prohibition on improper acquisition of personal information. */
export function buildAppiArticle17WorkedExample(retrievedAt: string, endorsedAt: string): AuthoritySource {
  const articleXPath = buildArticleXPath("17", { chapterNum: "4", paragraphNum: "1" });
  return buildJpAuthoritySource({
    lawId: APPI_LAW_ID,
    articleXPath,
    versionIdentifier: "2022-04-01", // APPI as amended by the 2022 revision
    retrievedAt,
    endorsement: {
      authority_id: "https://www.clb.go.jp/authority", // Act -> 内閣法制局 per Table 1
      endorsed_at: endorsedAt,
      endorsement_scope: "prohibition_predicate_only",
      resolution_basis: "statute_clear",
      co_endorsement_required: false,
      co_endorsement_quorum: "primary_only",
      co_endorsers: [],
      endorsement_claim: "<signed JWT>",
    },
  });
}

/** Agent-side Cedar condition shape for the worked example, per §6.2's Regulation Record. */
export const APPI_ARTICLE_17_AGENT_CHECK = {
  condition: "action.type == PersonalInformationAcquisition",
  prohibition: "action.acquisition_method == ImproperMeans",
  disposition: "DENY" as const,
};
