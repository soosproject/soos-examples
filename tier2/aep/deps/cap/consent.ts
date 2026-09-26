import { CapError, type CedarConsentContext, type ConsentScope } from "./types.js";

/**
 * §5.4 Table 1 — kernel populates Cedar context from MJWT consent_scope.
 * Fail-closed: if consent_scope is absent or expired, data_subject_consent
 * MUST be absent entirely (not false) — an absent field, not a false one,
 * is what makes Cedar's consent exception conditions evaluate false.
 */
export function populateCedarConsentContext(consentScope: ConsentScope | undefined, nowMs: number, source: NonNullable<CedarConsentContext["consent_source"]>): CedarConsentContext {
  if (!consentScope) return {};
  const expired = Date.parse(consentScope.expiry) < nowMs;
  if (expired) return {}; // fail-closed: absent, not false

  return {
    data_subject_consent: true,
    consent_purpose_codes: consentScope.purpose_codes,
    consent_data_categories: consentScope.data_categories,
    consent_jurisdiction: consentScope.jurisdiction,
    consent_governing_law: consentScope.governing_law,
    consent_expiry: consentScope.expiry,
    consent_source: source,
  };
}

/**
 * CONF-CAP-CONSENT-01: the GEC MUST NOT accept a client-supplied Cedar
 * context field that overrides the consent_scope-derived fields. These
 * fields are kernel-derived and MUST NOT be settable by the agent or
 * application layer.
 */
const KERNEL_DERIVED_CONSENT_FIELDS: ReadonlySet<string> = new Set([
  "data_subject_consent",
  "consent_purpose_codes",
  "consent_data_categories",
  "consent_jurisdiction",
  "consent_governing_law",
  "consent_expiry",
  "consent_source",
]);

export function assertNoAgentSuppliedConsentOverride(agentSuppliedContext: Record<string, unknown>): void {
  const offending = Object.keys(agentSuppliedContext).filter((k) => KERNEL_DERIVED_CONSENT_FIELDS.has(k));
  if (offending.length > 0) {
    throw new CapError(
      "CONSENT_CONTEXT_OVERRIDE_REJECTED",
      `CONF-CAP-CONSENT-01: agent/application supplied kernel-derived consent field(s): ${offending.join(", ")} — rejected`,
    );
  }
}

/** Merges kernel-derived consent context with the rest of the agent-supplied Cedar context, kernel fields always winning. */
export function buildFinalCedarContext(agentSuppliedContext: Record<string, unknown>, kernelConsentContext: CedarConsentContext): Record<string, unknown> {
  assertNoAgentSuppliedConsentOverride(agentSuppliedContext);
  return { ...agentSuppliedContext, ...kernelConsentContext };
}
