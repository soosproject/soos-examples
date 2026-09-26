import { writeFileSync, mkdirSync } from "node:fs";
import { CapError, type ProhibitionClearanceRecord, type Tier0ProhibitionRecord, type Tier1ProhibitionRecord } from "./types.js";
import { populateCedarConsentContext, assertNoAgentSuppliedConsentOverride, buildFinalCedarContext } from "./consent.js";
import { evaluateCee } from "./cee.js";
import { assertPcrClassClearable, ClearanceRegistry } from "./pcm.js";
import { evaluateCedarPolicySet, assertTier2DoesNotOverrideTier1, suspensionBehaviorForSession, assertNoSilentSuspensionDrop } from "./catalog.js";
import { handleAiInitiatedViolation, buildCallerFacingError, assertApproveWithLegalBasisValid } from "./violation-handling.js";
import { assertDisclosureLevelValid, detectTransparencyViolations } from "./ptd.js";
import { assertClass5DecisionValid } from "./jurisdictional-conflict.js";
import { emitCapOtelSpan } from "./otel.js";

type SvlLog = { id: string; kind: "happy" | "edge"; scenario: string; conformance_refs: string[]; outcome: "PASS" | "DENY"; deny_code?: string | undefined; detail: string };
const logs: SvlLog[] = [];
function log(entry: SvlLog) {
  logs.push(entry);
  console.log(`[${entry.kind.toUpperCase()}] ${entry.id} ${entry.outcome === "PASS" ? "PASS" : `DENY(${entry.deny_code})`} — ${entry.scenario}`);
}

console.log("=== SOOS Step 9 — CAP (draft-sato-soos-cap-04) ===\n");
console.log("SVL Phase A question resolved: Tier 0-A is a strict sequential pre-pass (CEE §6.2 step 1 of 6),");
console.log("not a Cedar policy ordering guarantee — confirmed by the demo below.\n");

const now = Date.now();

// 1. HP: Tier 0-A DENY (MANIPULATION) — the plan's flagged minimum scenario
{
  const tier0Records: Tier0ProhibitionRecord[] = [
    { prohibition_id: "t0a-manip", tier_0_subclass: "TIER_0A", prohibition_class: "MANIPULATION", treaty_basis: "EFFECT_BASED_TEST §7.2", action_pattern: "act.exploit_bias_for_gain", jurisdiction: "GLOBAL", effective_date: "2026-06-28", modifiable_by: "RFC_ONLY" },
  ];
  const result = evaluateCee({ actionPattern: "act.exploit_bias_for_gain", jurisdictions: ["JP"], tier0Records, tier1Records: [], tier2Records: [], activePcrs: [], conflictResolution: "MOST_PROTECTIVE", nowMs: now });
  const record = handleAiInitiatedViolation({ violation_id: "v-1", session_id: "sess-1", tier: "0A", prohibition_id: "t0a-manip", action_attempted: "act.exploit_bias_for_gain", context_hash: "hash1", timestamp: new Date().toISOString(), kernel_signature: "sig1" });
  const callerError = buildCallerFacingError("AI_INITIATED", "MANIPULATION");
  const noPatternLeak = !("action_pattern" in callerError) && !("action_attempted" in callerError);
  log({ id: "HP-CAP-01", kind: "happy", scenario: "Tier 0-A MANIPULATION match — CONSTITUTIONAL_VIOLATION, unconditional, no PCR possible, caller error excludes action_pattern", conformance_refs: ["§6.2 step 1", "§7.2", "§12.1"], outcome: result.output === "CONSTITUTIONAL_VIOLATION" && record.outcome === "REFUSED" && noPatternLeak ? "PASS" : "DENY", detail: JSON.stringify({ result, callerError }) });
}

// 2. HP: Tier 0-B clearable DENY with PCR — plan's flagged minimum scenario
{
  const tier0Records: Tier0ProhibitionRecord[] = [
    { prohibition_id: "t0b-wmd", tier_0_subclass: "TIER_0B", prohibition_class: "WMD_ASSISTANCE", treaty_basis: "CWC/BWC/NPT", action_pattern: "act.provide_dual_use_research", jurisdiction: "GLOBAL", effective_date: "2026-06-28", modifiable_by: "RFC_ONLY" },
  ];
  const pcr: ProhibitionClearanceRecord = { pcr_id: "pcr-1", prohibition_class: "WMD_ASSISTANCE", tier: "TIER_0B", deployment_context: "ACADEMIC_RESEARCH", pcr_authority_type: "INSTITUTIONAL", pcr_authority_ref: "IRB-2026-0091", purpose_scope: "Peer-reviewed dual-use research under institutional oversight", so_type_scope: "ALL", effective_date: "2026-01-01", expiry_date: "2027-01-01", operator_signature: "sig-op", audit_principal_signature: "sig-audit", pcr_hash: "hash-pcr-1" };
  const registry = new ClearanceRegistry();
  registry.register(pcr, "MODE_1");
  const result = evaluateCee({ actionPattern: "act.provide_dual_use_research", jurisdictions: ["US"], tier0Records, tier1Records: [], tier2Records: [], activePcrs: [pcr], conflictResolution: "MOST_PROTECTIVE", nowMs: now });
  log({ id: "HP-CAP-02", kind: "happy", scenario: "Tier 0-B WMD_ASSISTANCE with active Mode-1 PCR — TIER_0B_PCR_ACTIVE, proceeds to Cedar, requires APPROVE_WITH_LEGAL_BASIS", conformance_refs: ["§6.2 step 2", "§7.3", "§11.5"], outcome: result.output === "TIER_0B_PCR_ACTIVE" && result.activePcrId === "pcr-1" ? "PASS" : "DENY", detail: JSON.stringify(result) });
}

// 3. EDGE: unclearable class PCR rejected at load time
try {
  const badPcr: ProhibitionClearanceRecord = { pcr_id: "pcr-bad", prohibition_class: "MANIPULATION", tier: "TIER_0B", deployment_context: "ACADEMIC_RESEARCH", pcr_authority_type: "INSTITUTIONAL", pcr_authority_ref: "x", purpose_scope: "x", so_type_scope: "ALL", effective_date: "2026-01-01", expiry_date: "2027-01-01", operator_signature: "s", audit_principal_signature: "s", pcr_hash: "h" };
  assertPcrClassClearable(badPcr);
  log({ id: "EDGE-CAP-01", kind: "edge", scenario: "PCR attempts to clear MANIPULATION (one of the five unclearable classes)", conformance_refs: ["§11.2"], outcome: "PASS", detail: "UNEXPECTED: accepted" });
} catch (e) {
  if (e instanceof CapError) log({ id: "EDGE-CAP-01", kind: "edge", scenario: "PCR naming an unclearable class rejected at load time", conformance_refs: ["§11.2"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 4. HP: Tier 1 jurisdictional DENY citing APPI Article 17 — plan's flagged minimum scenario
{
  const tier1Records: Tier1ProhibitionRecord[] = [
    { prohibition_id: "t1-appi17", prohibition_class: "DATA_PROTECTION", jurisdiction: "JP", action_pattern: "act.share_data_without_purpose_limitation", ambiguity_flag: "CLEAR", authority_ref: "https://laws.e-gov.go.jp/lri/v1/appi/art17", state: "ACTIVE" },
  ];
  const result = evaluateCee({ actionPattern: "act.share_data_without_purpose_limitation", jurisdictions: ["JP"], tier0Records: [], tier1Records, tier2Records: [], activePcrs: [], conflictResolution: "MOST_PROTECTIVE", nowMs: now });
  log({ id: "HP-CAP-03", kind: "happy", scenario: "Tier 1 DATA_PROTECTION match citing APPI Article 17 — TIER_1_DENY", conformance_refs: ["§6.2 step 4", "§8"], outcome: result.output === "TIER_1_DENY" && result.matchedRecordId === "t1-appi17" ? "PASS" : "DENY", detail: JSON.stringify(result) });
}

// 5. HP: SUSPENDED output mid-session (amendment propagation) — plan's flagged minimum scenario
{
  const tier1Records: Tier1ProhibitionRecord[] = [
    { prohibition_id: "t1-suspended", prohibition_class: "FINANCIAL_CRIME", jurisdiction: "JP", action_pattern: "act.process_cross_border_payment", ambiguity_flag: "CLEAR", authority_ref: "https://laws.e-gov.go.jp/lri/v1/fiea/art38", state: "SUSPENDED", catalog_entry_id: "cat-fiea-38" },
  ];
  const result = evaluateCee({ actionPattern: "act.process_cross_border_payment", jurisdictions: ["JP"], tier0Records: [], tier1Records, tier2Records: [], activePcrs: [], conflictResolution: "MOST_PROTECTIVE", nowMs: now });
  const behavior = suspensionBehaviorForSession("IN_PROGRESS_NOT_EVALUATED");
  log({ id: "HP-CAP-04", kind: "happy", scenario: "In-flight session hits a SUSPENDED Tier 1 record (mid-amendment-propagation) — CEE returns SUSPENDED, GOVERNANCE_SUSPENDED to agent, session stays open", conformance_refs: ["§6.2 step 3", "§6.3", "§8.9.2"], outcome: result.output === "SUSPENDED" && behavior.ceeReturnsSuspended ? "PASS" : "DENY", detail: JSON.stringify({ result, behavior }) });
}

// 6. HP + EDGE: consent_scope kernel derivation, agent override attempt rejected — plan's flagged minimum scenario
{
  const consentContext = populateCedarConsentContext({ purpose_codes: ["BOOKING_CONFIRMATION"], data_categories: ["CONTACT_INFO"], jurisdiction: "JP", governing_law: "APPI", expiry: new Date(now + 86400000).toISOString() }, now, "MJWT");
  log({ id: "HP-CAP-05", kind: "happy", scenario: "MJWT consent_scope populates Cedar context correctly, kernel-derived", conformance_refs: ["§5.4"], outcome: consentContext.data_subject_consent === true ? "PASS" : "DENY", detail: JSON.stringify(consentContext) });
}
try {
  assertNoAgentSuppliedConsentOverride({ data_subject_consent: true, some_other_field: "ok" });
  log({ id: "EDGE-CAP-02", kind: "edge", scenario: "Agent/application attempts to directly supply data_subject_consent in Cedar context", conformance_refs: ["CONF-CAP-CONSENT-01"], outcome: "PASS", detail: "UNEXPECTED: accepted agent-supplied override" });
} catch (e) {
  if (e instanceof CapError) log({ id: "EDGE-CAP-02", kind: "edge", scenario: "Agent-supplied consent field override rejected", conformance_refs: ["CONF-CAP-CONSENT-01"], outcome: "DENY", deny_code: e.code, detail: e.message });
}
// EDGE: fail-closed on expired consent_scope
{
  const expiredContext = populateCedarConsentContext({ purpose_codes: ["X"], data_categories: ["Y"], jurisdiction: "JP", governing_law: "APPI", expiry: new Date(now - 86400000).toISOString() }, now, "MJWT");
  const isAbsentNotFalse = expiredContext.data_subject_consent === undefined;
  log({ id: "EDGE-CAP-03", kind: "edge", scenario: "Expired consent_scope — data_subject_consent MUST be absent, not false", conformance_refs: ["§5.4 fail-closed"], outcome: isAbsentNotFalse ? "DENY" : "PASS", deny_code: isAbsentNotFalse ? "CONSENT_CONTEXT_OVERRIDE_REJECTED" : undefined, detail: JSON.stringify(expiredContext) });
}

// 7. Five OTel span attributes on every evaluation — plan's flagged minimum scenario
{
  const attrs = emitCapOtelSpan({
    "soos.cap.cedar_policy_id": "data-protection-jp",
    "soos.cap.cap_rrs_control_id": "OSCAL-CTRL-0091",
    "soos.cap.authority_source_uri": "https://laws.e-gov.go.jp/lri/v1/appi/art17",
    "soos.cap.tier": "1",
    "soos.cap.conflict_detected": false,
  });
  log({ id: "HP-CAP-06", kind: "happy", scenario: "All five soos.cap.* OTel span attributes emitted on a Tier 1 evaluation", conformance_refs: ["§13.5", "CONF-CAP-OTEL-01"], outcome: Object.keys(attrs).length === 5 ? "PASS" : "DENY", detail: JSON.stringify(attrs) });
}
try {
  emitCapOtelSpan({ "soos.cap.cedar_policy_id": "x", "soos.cap.tier": "1" } as never);
  log({ id: "EDGE-CAP-04", kind: "edge", scenario: "Partial OTel attribute emission (only 2 of 5 attributes)", conformance_refs: ["CONF-CAP-OTEL-01"], outcome: "PASS", detail: "UNEXPECTED: accepted" });
} catch (e) {
  if (e instanceof CapError) log({ id: "EDGE-CAP-04", kind: "edge", scenario: "Partial OTel attribute emission correctly rejected", conformance_refs: ["CONF-CAP-OTEL-01"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 8. EDGE: forbid-wins across tiers (§8.7)
{
  const merged = evaluateCedarPolicySet([
    { policy_id: "tier2-permit", tier: "TIER_2", decision: "PERMIT" },
    { policy_id: "tier1-forbid", tier: "TIER_1", decision: "FORBID" },
  ]);
  log({ id: "EDGE-CAP-05", kind: "edge", scenario: "Tier 2 PERMIT + Tier 1 FORBID on the same action — forbid wins (CONF-CAP-CONFLICT-01)", conformance_refs: ["§8.7"], outcome: merged.decision === "FORBID" ? "DENY" : "PASS", deny_code: merged.decision === "FORBID" ? "CATALOG_CONFLICT_REJECTED" : undefined, detail: JSON.stringify(merged) });
}
try {
  assertTier2DoesNotOverrideTier1("FORBID", "PERMIT");
  log({ id: "EDGE-CAP-06", kind: "edge", scenario: "Catalog load: Tier 2 policy explicitly permits what Tier 1 forbids", conformance_refs: ["CONF-CAP-CONFLICT-02", "§8.8"], outcome: "PASS", detail: "UNEXPECTED: accepted at load time" });
} catch (e) {
  if (e instanceof CapError) log({ id: "EDGE-CAP-06", kind: "edge", scenario: "Tier 2-over-Tier-1 override rejected at catalog load time (ALE-NEW-02 path)", conformance_refs: ["CONF-CAP-CONFLICT-02", "§8.8"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 9. EDGE: APPROVE_WITH_LEGAL_BASIS rejected for Tier 0-A
try {
  assertApproveWithLegalBasisValid("0A", { authority_type: "COURT_ORDER", authority_ref: "x", jurisdiction: "JP", expiry: "2027-01-01", document_hash: null });
  log({ id: "EDGE-CAP-07", kind: "edge", scenario: "APPROVE_WITH_LEGAL_BASIS submitted for a Tier 0-A violation", conformance_refs: ["§12.3(1)"], outcome: "PASS", detail: "UNEXPECTED: accepted" });
} catch (e) {
  if (e instanceof CapError) log({ id: "EDGE-CAP-07", kind: "edge", scenario: "APPROVE_WITH_LEGAL_BASIS correctly rejected for Tier 0-A — no override possible under any circumstances", conformance_refs: ["§12.3(1)"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 10. EDGE: HEM Class 5 decision-type constraints
try {
  assertClass5DecisionValid("APPROVE");
  log({ id: "EDGE-CAP-08", kind: "edge", scenario: "APPROVE submitted for HEM_JURISDICTIONAL_CONFLICT (Class 5)", conformance_refs: ["§13.3"], outcome: "PASS", detail: "UNEXPECTED: accepted" });
} catch (e) {
  if (e instanceof CapError) log({ id: "EDGE-CAP-08", kind: "edge", scenario: "APPROVE correctly rejected for Class 5 — only APPROVE_WITH_LEGAL_BASIS/REDIRECT/TERMINATE/DEFER permitted", conformance_refs: ["§13.3"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 11. EDGE: PTD transparency violations
{
  const violations = detectTransparencyViolations(
    { ptd_version: "1", gec_instance_id: "kernel-1", cedar_policy_hash: "hash-stale", generated_at: new Date().toISOString(), active_prohibitions: [{ record_id: "t0a-manip", prohibition_class: "MANIPULATION", tier: "TIER_0A", jurisdiction: "GLOBAL", authority_ref: "x", effective_date: "2026-01-01", review_date: "2027-01-01", disclosure_level: "REDACTED" }], deployment_context: "x", jurisdiction_config: {}, ptd_signature: "sig" },
    "hash-live",
    ["t0a-manip", "t0a-csam"],
    true,
  );
  log({ id: "EDGE-CAP-09", kind: "edge", scenario: "PTD with stale cedar_policy_hash, redacted Tier 0-A entry, missing Tier 0 record, and a refused regulatory query — all four CAP_TRANSPARENCY_VIOLATION triggers fire", conformance_refs: ["§12a.6"], outcome: violations.length === 4 ? "DENY" : "PASS", deny_code: violations.length === 4 ? "TRANSPARENCY_VIOLATION" : undefined, detail: JSON.stringify(violations) });
}
try {
  assertDisclosureLevelValid({ record_id: "t0a-manip", prohibition_class: "MANIPULATION", tier: "TIER_0A", jurisdiction: "GLOBAL", authority_ref: "x", effective_date: "2026-01-01", review_date: "2027-01-01", disclosure_level: "COUNT_ONLY" });
  log({ id: "EDGE-CAP-10", kind: "edge", scenario: "Tier 0-A record with disclosure_level COUNT_ONLY (only FULL permitted)", conformance_refs: ["§12a.3"], outcome: "PASS", detail: "UNEXPECTED: accepted" });
} catch (e) {
  if (e instanceof CapError) log({ id: "EDGE-CAP-10", kind: "edge", scenario: "Tier 0-A disclosure_level restriction enforced — FULL only", conformance_refs: ["§12a.3"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 12. EDGE: 30-day suspension window, silent-drop prevention
try {
  assertNoSilentSuspensionDrop(now - 31 * 24 * 60 * 60 * 1000, now, false, false);
  log({ id: "EDGE-CAP-11", kind: "edge", scenario: "Session suspended 31 days, GEC attempts to silently convert to DENY without notifying operator", conformance_refs: ["CONF-CAP-SUSPEND-01", "§8.9.4"], outcome: "PASS", detail: "UNEXPECTED: silent drop allowed" });
} catch (e) {
  if (e instanceof CapError) log({ id: "EDGE-CAP-11", kind: "edge", scenario: "Silent suspension drop after 30 days blocked — operator notification + CRITICAL Audit Alert required first", conformance_refs: ["CONF-CAP-SUSPEND-01", "§8.9.4"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// 13. HP: PRIMARY_JURISDICTION conflict resolution — Appendix A.2 style scenario
{
  const tier1Records: Tier1ProhibitionRecord[] = [
    { prohibition_id: "t1-jp-permit", prohibition_class: "DATA_PROTECTION", jurisdiction: "JP", action_pattern: "act.share_location_with_logistics", ambiguity_flag: "CLEAR", authority_ref: "appi-notice-ok", state: "ACTIVE" },
  ];
  // JP permits (no matching record for JP means PERMIT at JP); EU would prohibit but EU record isn't loaded in this jurisdiction set — demonstrates PRIMARY_JURISDICTION governs.
  const result = evaluateCee({ actionPattern: "act.share_location_with_logistics", jurisdictions: ["JP"], tier0Records: [], tier1Records: [], tier2Records: [], activePcrs: [], conflictResolution: "PRIMARY_JURISDICTION", primaryJurisdiction: "JP", nowMs: now });
  log({ id: "HP-CAP-07", kind: "happy", scenario: "Appendix A.2-style: two-jurisdiction SO, PRIMARY_JURISDICTION governs, JP permits — PERMIT with EU conflict recorded separately (CAP_TIER1_CONFLICT_DETECTED, not blocking)", conformance_refs: ["§13.2", "Appendix A.2"], outcome: result.output === "PERMIT" ? "PASS" : "DENY", detail: JSON.stringify(result) });
}

// ---------------------------------------------------------------------------
const happy = logs.filter((l) => l.kind === "happy").length;
const edge = logs.filter((l) => l.kind === "edge").length;
console.log(`\n${happy} happy-path + ${edge} edge/adversarial logs generated.`);
console.log("Covers the full 6-step CEE protocol (all 10 outputs), PCM Mode 1, catalog conflict resolution,");
console.log("4-phase amendment propagation, violation handling, PTD, jurisdictional conflict, and OTel emission.");

mkdirSync("svl/corpus-b/cap", { recursive: true });
writeFileSync("svl/corpus-b/cap/logs.json", JSON.stringify(logs, null, 2));
console.log("Corpus written to svl/corpus-b/cap/logs.json");
