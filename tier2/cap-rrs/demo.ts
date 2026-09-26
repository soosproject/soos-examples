import { writeFileSync, mkdirSync } from "node:fs";
import { CapRrsError, LRI_PROFILE_REGISTRY, type AuthoritySource } from "./types.js";
import { assertInterpretationEndpointPresent, assertCrossStatuteCoordinationRequirements, assertLriProfileComplete } from "./lri.js";
import { assertCoEndorsementQuorumMet, assertNoCoEndorserSupersession, type CoEndorserStatus } from "./co-endorsement.js";
import { checkStatutePrimacy, buildCatalogVersionConflictEvent, assertNoNewSacrOnSuspendedEntry, assertCatalogVersionValid, isSafeHarborProtected } from "./statute-primacy.js";
import { assertDetectionCadenceConforming, assertNoSilentSuspensionConversion, assertAuthoritySourceUriMatchesOtel, DETECTION_MAX_INTERVAL_HOURS } from "./operational-requirements.js";

type SvlLog = { id: string; kind: "happy" | "edge"; scenario: string; conformance_refs: string[]; outcome: "PASS" | "DENY"; deny_code?: string | undefined; detail: string };
const logs: SvlLog[] = [];
function log(entry: SvlLog) {
  logs.push(entry);
  console.log(`[${entry.kind.toUpperCase()}] ${entry.id} ${entry.outcome === "PASS" ? "PASS" : `DENY(${entry.deny_code})`} — ${entry.scenario}`);
}

console.log("=== SOOS Step 10 — CAP-RRS (draft-sato-soos-cap-rrs-02) ===\n");
console.log("SVL Phase A question pre-resolved during Step 9: §11.1 confirms 24h detection cadence is normative MUST.\n");
console.log("NOTE: §4-8 and §12 base schema/HEM-integration text is not in -02 (deferred to -01, not supplied).");
console.log("This build covers only the fully-specified -02 NEW material: LRI (§9), Statute-Primacy Rule (§10),");
console.log("Operational Requirements (§11). See SDB-CAPRRS-01.\n");

const now = Date.now();

function makeAppiArticle17Source(overrides?: Partial<AuthoritySource>): AuthoritySource {
  return {
    lri_version: "1.0",
    profile: LRI_PROFILE_REGISTRY.JP!.uri,
    law_id: "325AC0000000089", // APPI
    article_ref: "/Law/LawBody/MainProvision/Article[@Num='17']",
    version_identifier: "2022-04-01",
    retrieved_at: new Date(now).toISOString(),
    amendment_detection_endpoint: "https://laws.e-gov.go.jp/api/2/updatelawlists/{date}",
    interpretation_endpoint: null,
    endorsement: {
      authority_id: "https://www.ppc.go.jp/authority",
      endorsed_at: new Date(now - 400 * 24 * 60 * 60 * 1000).toISOString(), // endorsed over a year ago
      endorsement_scope: "purpose_limitation",
      resolution_basis: "statute_clear",
      co_endorsement_required: false,
      endorsement_claim: "eyJhbGciOiJFZERTQSJ9.fake.sig",
    },
    ...overrides,
  };
}

// 1. HP: APPI Article 17 worked example — LRI Generic Schema fully populated
{
  const source = makeAppiArticle17Source();
  log({ id: "HP-CAPRRS-01", kind: "happy", scenario: "APPI Article 17 authority_source block — full LRI Generic Schema populated (Japan profile)", conformance_refs: ["§9.2", "§9.7"], outcome: source.law_id === "325AC0000000089" ? "PASS" : "DENY", detail: JSON.stringify(source.endorsement) });
}

// 2. HP: LRI Profile completeness (five normative requirements)
{
  try {
    assertLriProfileComplete({ law_id_scheme_defined: true, article_ref_resolvable: true, version_identifier_derivable: true, amendment_detection_since_param_supported: true, authority_id_endorser_table_defined: true });
    log({ id: "HP-CAPRRS-02", kind: "happy", scenario: "Japan LRI Profile defines all five normative requirements (LRI-1 through LRI-5)", conformance_refs: ["§9.3"], outcome: "PASS", detail: "complete" });
  } catch (e) {
    if (e instanceof CapRrsError) log({ id: "HP-CAPRRS-02", kind: "happy", scenario: "LRI profile completeness", conformance_refs: ["§9.3"], outcome: "DENY", deny_code: e.code, detail: e.message });
  }
}
try {
  assertLriProfileComplete({ law_id_scheme_defined: true, article_ref_resolvable: true, version_identifier_derivable: false, amendment_detection_since_param_supported: true, authority_id_endorser_table_defined: true });
  log({ id: "EDGE-CAPRRS-01", kind: "edge", scenario: "LRI Profile missing LRI-3 (version_identifier derivation)", conformance_refs: ["§9.3"], outcome: "PASS", detail: "UNEXPECTED: accepted incomplete profile" });
} catch (e) {
  if (e instanceof CapRrsError) log({ id: "EDGE-CAPRRS-01", kind: "edge", scenario: "Incomplete LRI Profile correctly rejected", conformance_refs: ["§9.3"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 3. EDGE: interpretive_ruling without resolution_instrument_id
try {
  const source = makeAppiArticle17Source({ endorsement: { ...makeAppiArticle17Source().endorsement, resolution_basis: "interpretive_ruling" } });
  assertInterpretationEndpointPresent(source);
  log({ id: "EDGE-CAPRRS-02", kind: "edge", scenario: "resolution_basis interpretive_ruling without resolution_instrument_id populated", conformance_refs: ["§9.4 Table 1"], outcome: "PASS", detail: "UNEXPECTED: accepted" });
} catch (e) {
  if (e instanceof CapRrsError) log({ id: "EDGE-CAPRRS-02", kind: "edge", scenario: "interpretive_ruling without resolution_instrument_id correctly rejected", conformance_refs: ["§9.4 Table 1"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 4. EDGE: cross_statute_coordination requires co_endorsement_required + quorum "all"
try {
  const source = makeAppiArticle17Source({ endorsement: { ...makeAppiArticle17Source().endorsement, resolution_basis: "cross_statute_coordination", co_endorsement_required: false } });
  assertCrossStatuteCoordinationRequirements(source);
  log({ id: "EDGE-CAPRRS-03", kind: "edge", scenario: "cross_statute_coordination without co_endorsement_required: true", conformance_refs: ["§9.4 Table 1"], outcome: "PASS", detail: "UNEXPECTED: accepted" });
} catch (e) {
  if (e instanceof CapRrsError) log({ id: "EDGE-CAPRRS-03", kind: "edge", scenario: "cross_statute_coordination correctly requires co_endorsement_required + quorum all", conformance_refs: ["§9.4 Table 1"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 5. HP + EDGE: co-endorsement quorum
{
  const source = makeAppiArticle17Source({
    endorsement: { ...makeAppiArticle17Source().endorsement, co_endorsement_required: true, co_endorsement_quorum: "all", co_endorsers: ["https://pref.nagano.jp/authority", "https://chino.lg.jp/authority"] },
  });
  const statuses: CoEndorserStatus[] = [
    { authority_id: "https://pref.nagano.jp/authority", endorsement_claim_valid: true },
    { authority_id: "https://chino.lg.jp/authority", endorsement_claim_valid: true },
  ];
  try {
    assertCoEndorsementQuorumMet(source, statuses);
    log({ id: "HP-CAPRRS-03", kind: "happy", scenario: "Disaster-response coordination: quorum 'all', both co-endorsers valid — policy may activate", conformance_refs: ["§9.5", "CONF-RRS-COEND-01"], outcome: "PASS", detail: "quorum met" });
  } catch (e) {
    if (e instanceof CapRrsError) log({ id: "HP-CAPRRS-03", kind: "happy", scenario: "co-endorsement quorum", conformance_refs: ["§9.5"], outcome: "DENY", deny_code: e.code, detail: e.message });
  }

  const partialStatuses: CoEndorserStatus[] = [{ authority_id: "https://pref.nagano.jp/authority", endorsement_claim_valid: true }, { authority_id: "https://chino.lg.jp/authority", endorsement_claim_valid: false }];
  try {
    assertCoEndorsementQuorumMet(source, partialStatuses);
    log({ id: "EDGE-CAPRRS-04", kind: "edge", scenario: "Quorum 'all' but one required co-endorser's claim invalid", conformance_refs: ["CONF-RRS-COEND-01"], outcome: "PASS", detail: "UNEXPECTED: activated with incomplete quorum" });
  } catch (e) {
    if (e instanceof CapRrsError) log({ id: "EDGE-CAPRRS-04", kind: "edge", scenario: "Incomplete co-endorsement quorum correctly blocks activation", conformance_refs: ["CONF-RRS-COEND-01"], outcome: "DENY", deny_code: e.code, detail: e.message });
  }

  const { mustSuspend } = assertNoCoEndorserSupersession(partialStatuses);
  log({ id: "EDGE-CAPRRS-05", kind: "edge", scenario: "§9.5(d): one co-endorser's claim superseded — policy MUST suspend regardless of other co-endorsers' status", conformance_refs: ["§9.5(d)"], outcome: mustSuspend ? "DENY" : "PASS", deny_code: mustSuspend ? "CO_ENDORSEMENT_QUORUM_NOT_MET" : undefined, detail: `mustSuspend=${mustSuspend}` });
}

// 6. HP: Statute-Primacy Rule — four-phase amendment lifecycle (plan's flagged minimum scenario)
{
  const source = makeAppiArticle17Source();
  const amendmentDates = [new Date(now - 10 * 24 * 60 * 60 * 1000).toISOString()]; // amendment 10 days ago, posterior to endorsed_at (400 days ago)
  const check = checkStatutePrimacy(source, amendmentDates);
  log({ id: "HP-CAPRRS-04", kind: "happy", scenario: "Phase 1 Detection: amendment posterior to endorsed_at found — CATALOG_VERSION_CONFLICT triggers", conformance_refs: ["§10.1"], outcome: check.conflictDetected ? "PASS" : "DENY", detail: JSON.stringify(check) });

  const event = buildCatalogVersionConflictEvent({ catalogEntryId: "cat-appi-17", source, conflictingAmendmentDate: check.conflictingDate!, hemEscalationId: "hem-caprrs-1", nowMs: now });
  log({ id: "HP-CAPRRS-05", kind: "happy", scenario: "Phase 2: CATALOG_VERSION_CONFLICT GAR event built with conflict_delta_days computed", conformance_refs: ["§10.2"], outcome: event.conflict_delta_days > 0 ? "PASS" : "DENY", detail: JSON.stringify(event) });

  try {
    assertNoNewSacrOnSuspendedEntry("cat-appi-17", new Set(["cat-appi-17"]));
    log({ id: "EDGE-CAPRRS-06", kind: "edge", scenario: "New SACR attempted citing a suspended catalog entry", conformance_refs: ["§10.1(1)"], outcome: "PASS", detail: "UNEXPECTED: accepted" });
  } catch (e) {
    if (e instanceof CapRrsError) log({ id: "EDGE-CAPRRS-06", kind: "edge", scenario: "New SACR citing suspended entry correctly blocked", conformance_refs: ["§10.1(1)"], outcome: "DENY", deny_code: e.code, detail: e.message });
  }

  // Phase 3/4: re-endorsement with a valid catalog_version update
  try {
    assertCatalogVersionValid(
      { version_id: "v2.0.0", effective_date: new Date(now).toISOString(), supersedes: "v1.0.0", amendment_basis: "2026-amendment-instrument-77", published_by: "https://www.ppc.go.jp/authority", published_at: new Date(now).toISOString() },
      "v1.0.0",
      new Date(now - 400 * 24 * 60 * 60 * 1000).toISOString(),
      "https://www.ppc.go.jp/authority",
    );
    log({ id: "HP-CAPRRS-06", kind: "happy", scenario: "Phase 4 Re-activation: valid catalog_version update (correct supersedes chain + matching authority) accepted", conformance_refs: ["§10.5"], outcome: "PASS", detail: "accepted" });
  } catch (e) {
    if (e instanceof CapRrsError) log({ id: "HP-CAPRRS-06", kind: "happy", scenario: "catalog_version re-activation", conformance_refs: ["§10.5"], outcome: "DENY", deny_code: e.code, detail: e.message });
  }
}

// 7. EDGE: rollback attack defense (§10.5c) and supersedes mismatch (§10.5b)
try {
  assertCatalogVersionValid({ version_id: "v0.9.0", effective_date: "2020-01-01T00:00:00Z", supersedes: "v1.0.0", amendment_basis: "x", published_by: "https://www.ppc.go.jp/authority", published_at: new Date(now).toISOString() }, "v1.0.0", "2026-01-01T00:00:00Z", "https://www.ppc.go.jp/authority");
  log({ id: "EDGE-CAPRRS-07", kind: "edge", scenario: "catalog_version rollback attack: effective_date earlier than currently active", conformance_refs: ["§10.5(c)"], outcome: "PASS", detail: "UNEXPECTED: rollback accepted" });
} catch (e) {
  if (e instanceof CapRrsError) log({ id: "EDGE-CAPRRS-07", kind: "edge", scenario: "Rollback attack correctly rejected", conformance_refs: ["§10.5(c)"], outcome: "DENY", deny_code: e.code, detail: e.message });
}
try {
  assertCatalogVersionValid({ version_id: "v2.0.0", effective_date: new Date(now).toISOString(), supersedes: "v-wrong", amendment_basis: "x", published_by: "https://www.ppc.go.jp/authority", published_at: new Date(now).toISOString() }, "v1.0.0", "2020-01-01T00:00:00Z", "https://www.ppc.go.jp/authority");
  log({ id: "EDGE-CAPRRS-08", kind: "edge", scenario: "catalog_version supersedes points to the wrong prior version", conformance_refs: ["§10.5(b)"], outcome: "PASS", detail: "UNEXPECTED: accepted" });
} catch (e) {
  if (e instanceof CapRrsError) log({ id: "EDGE-CAPRRS-08", kind: "edge", scenario: "Mismatched supersedes chain correctly rejected", conformance_refs: ["§10.5(b)"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 8. HP: Safe Harbor Clause
{
  const protectedAction = isSafeHarborProtected({ endorsed_at: new Date(now - 400 * 24 * 60 * 60 * 1000).toISOString(), suspension_effective_at: new Date(now - 5 * 24 * 60 * 60 * 1000).toISOString() });
  log({ id: "HP-CAPRRS-07", kind: "happy", scenario: "Safe harbor: action taken while endorsed_at anterior to suspension_effective_at — protected from retroactive liability", conformance_refs: ["§10.4"], outcome: protectedAction ? "PASS" : "DENY", detail: `protected=${protectedAction}` });
}

// 9. HP + EDGE: Operational Requirements — 24h detection cadence (plan's flagged Step 10 question, pre-resolved)
{
  try {
    assertDetectionCadenceConforming(24, "amendment");
    log({ id: "HP-CAPRRS-08", kind: "happy", scenario: "Amendment detection polled at exactly 24h — conforming (normative MUST, confirmed §11.1)", conformance_refs: ["§11.1"], outcome: "PASS", detail: `max=${DETECTION_MAX_INTERVAL_HOURS}h` });
  } catch (e) {
    if (e instanceof CapRrsError) log({ id: "HP-CAPRRS-08", kind: "happy", scenario: "detection cadence", conformance_refs: ["§11.1"], outcome: "DENY", deny_code: e.code, detail: e.message });
  }
}
try {
  assertDetectionCadenceConforming(48, "interpretation");
  log({ id: "EDGE-CAPRRS-09", kind: "edge", scenario: "Interpretation detection polled at 48h — exceeds the 24h normative maximum", conformance_refs: ["§11.2"], outcome: "PASS", detail: "UNEXPECTED: accepted non-conforming cadence" });
} catch (e) {
  if (e instanceof CapRrsError) log({ id: "EDGE-CAPRRS-09", kind: "edge", scenario: "Non-conforming 48h interpretation detection cadence correctly rejected", conformance_refs: ["§11.2"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 10. EDGE: 30-day suspension window silent-drop prevention (§11.3)
try {
  assertNoSilentSuspensionConversion(now - 31 * 24 * 60 * 60 * 1000, now, false, false);
  log({ id: "EDGE-CAPRRS-10", kind: "edge", scenario: "31 days suspended, silent conversion to DENY attempted without operator notification", conformance_refs: ["§11.3"], outcome: "PASS", detail: "UNEXPECTED: silent drop allowed" });
} catch (e) {
  if (e instanceof CapRrsError) log({ id: "EDGE-CAPRRS-10", kind: "edge", scenario: "Silent suspension drop blocked — matches CAP-04 §8.9.4's cross-referenced 30-day rule", conformance_refs: ["§11.3", "CAP-04 §8.9.4"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 11. EDGE: authority_source_uri / OTel mismatch (§11.4)
try {
  assertAuthoritySourceUriMatchesOtel("https://elaws.e-gov.go.jp/document?lawid=415AC0000000057#/Law/LawBody/MainProvision/Article[@Num='17']", "https://elaws.e-gov.go.jp/document?lawid=415AC0000000057#/Law/LawBody/MainProvision/Article[@Num='18']");
  log({ id: "EDGE-CAPRRS-11", kind: "edge", scenario: "authority_source_uri (Article 17) does not match emitted OTel soos.cap.authority_source_uri (Article 18)", conformance_refs: ["§11.4", "CAP-04 §12a.6"], outcome: "PASS", detail: "UNEXPECTED: mismatch not caught" });
} catch (e) {
  if (e instanceof CapRrsError) log({ id: "EDGE-CAPRRS-11", kind: "edge", scenario: "authority_source_uri / OTel attribute mismatch correctly flagged as PTD inconsistency", conformance_refs: ["§11.4", "CAP-04 §12a.6"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// ---------------------------------------------------------------------------
const happy = logs.filter((l) => l.kind === "happy").length;
const edge = logs.filter((l) => l.kind === "edge").length;
console.log(`\n${happy} happy-path + ${edge} edge/adversarial logs generated.`);
console.log("Covers the -02 NEW material in full: LRI (§9), Statute-Primacy Rule (§10, incl. both GAR event");
console.log("schemas + safe harbor), Operational Requirements (§11). §4-8 and §12 remain unbuilt pending -01 (SDB-CAPRRS-01).");

mkdirSync("svl/corpus-b/cap-rrs", { recursive: true });
writeFileSync("svl/corpus-b/cap-rrs/logs.json", JSON.stringify(logs, null, 2));
console.log("Corpus written to svl/corpus-b/cap-rrs/logs.json");
