/**
 * GAR ALE Type Registry additions, §21.3 — ALE-030 through ALE-041.
 * Three ALE IDs are deliberately multiplexed across two event categories
 * each, per the registry's own explanatory notes:
 *   ALE-034/035 — DS options presentation vs. fatigue detection, disambiguated
 *                 by `fatigue_flag`.
 *   ALE-036     — capability limitation vs. emotional advisory, disambiguated
 *                 by `advisory_type`.
 *   ALE-040     — high-stakes review resolution vs. consent escalation
 *                 initiation, disambiguated by `ale_subtype`.
 * This is confirmed intentional ("to conserve the ALE range"), not a spec
 * bug — the §7.5.1/§7.6.2 inline text under-specifies the disambiguation
 * field for ALE-040, but the §21.3 table is unambiguous and is what this
 * module implements against.
 */

export interface AleRecord {
  ale_id: string;
  ale_name: string;
  fields: Record<string, unknown>;
  emitted_at: string;
}

function ale(ale_id: string, ale_name: string, fields: Record<string, unknown>): AleRecord {
  return { ale_id, ale_name, fields, emitted_at: new Date().toISOString() };
}

export const emitAle030PreClarificationInitiated = (f: {
  hem_id: string; session_id: string; so_id: string; mandate_id: string;
  goal_description_hash: string; trigger_condition_code: string;
}) => ale("ALE-030", "HEM_PRE_CLARIFICATION_INITIATED", { ...f, initiated_at: new Date().toISOString() });

export const emitAle031PreClarificationResolved = (f: {
  hem_id: string; decision_type: string; drr_id?: string;
}) => ale("ALE-031", "HEM_PRE_CLARIFICATION_RESOLVED", { ...f, resolution_at: new Date().toISOString() });

export const emitAle032PreConfirmationInitiated = (f: {
  hem_id: string; session_id: string; so_id: string; mandate_id: string;
  action_id: string; trigger_condition_code: string; irreversible_flag: boolean;
}) => ale("ALE-032", "HEM_PRE_CONFIRMATION_INITIATED", { ...f, initiated_at: new Date().toISOString() });

export const emitAle033PreConfirmationResolved = (f: {
  hem_id: string; decision_type: string; approve_with_constraints_flag: boolean; drr_id?: string;
}) => ale("ALE-033", "HEM_PRE_CONFIRMATION_RESOLVED", { ...f, resolution_at: new Date().toISOString() });

/** ALE-034 — options presentation (fatigue_flag: false) OR fatigue detection (fatigue_flag: true). */
export const emitAle034 = (
  f:
    | { fatigue_flag: false; hem_id: string; options_count: number; recommended_option_id: string | null; neutrality_certificate_hash: string }
    | { fatigue_flag: true; hem_id: string; principal_id: string; hrs_score: number; hrs_fatigue_floor: number; secondary_signal_codes: string[]; mandatory_rest_seconds: number },
) => ale("ALE-034", f.fatigue_flag ? "HEM_FATIGUE_DETECTED" : "HEM_DS_OPTIONS_PRESENTED", { ...f, presented_at: new Date().toISOString() });

/** ALE-035 — options resolved (fatigue_flag: false) OR fatigue rest complete (fatigue_flag: true). */
export const emitAle035 = (
  f:
    | { fatigue_flag: false; hem_id: string; selected_option_id: string; decision_type: string }
    | { fatigue_flag: true; hem_id: string; principal_id: string; rest_elapsed_seconds: number },
) => ale("ALE-035", f.fatigue_flag ? "HEM_FATIGUE_REST_COMPLETE" : "HEM_DS_OPTIONS_RESOLVED", { ...f, resolved_at: new Date().toISOString() });

/** ALE-036 — limitation declared (advisory_type: "LIMITATION") OR emotional advisory (advisory_type: "EMOTIONAL"). */
export const emitAle036 = (
  f:
    | { advisory_type: "LIMITATION"; hem_id: string; session_id: string; limitation_type: string; idp_confidence_level: number; competence_floor: number }
    | { advisory_type: "EMOTIONAL"; hem_id: string; session_id: string },
) => ale("ALE-036", f.advisory_type === "LIMITATION" ? "HEM_LIMITATION_DECLARED" : "HEM_EMO1_ADVISORY", { ...f, declared_at: new Date().toISOString() });

export const emitAle037LimitationAcknowledged = (f: { hem_id: string; decision_type: string }) =>
  ale("ALE-037", "HEM_LIMITATION_ACKNOWLEDGED", { ...f, acknowledged_at: new Date().toISOString() });

export const emitAle038DivergenceNoted = (f: {
  hem_id: string; session_id: string; divergence_type: string; declared_action_hash: string;
  attempted_action_hash: string; deliberation_record_id: string;
}) => ale("ALE-038", "HEM_DIVERGENCE_NOTED", { ...f, noted_at: new Date().toISOString() });

export const emitAle039DivergenceResolved = (f: { hem_id: string; decision_type: string; divergent_path_approved: boolean }) =>
  ale("ALE-039", "HEM_DIVERGENCE_RESOLVED", { ...f, resolved_at: new Date().toISOString() });

/** ALE-040 — high-stakes review resolved OR consent escalation initiated, disambiguated by ale_subtype. */
export const emitAle040 = (
  f:
    | { ale_subtype: "HIGH_STAKES_RESOLVED"; hem_id: string; domain_category: string; domain_name: string; decision_type: string; drr_id?: string }
    | { ale_subtype: "CONSENT_INIT"; hem_id: string; session_id: string; consent_requirement: string; purpose_codes_required: string[]; purpose_codes_present: string[]; consent_expiry: string | null },
) => ale("ALE-040", f.ale_subtype === "HIGH_STAKES_RESOLVED" ? "HEM_HIGH_STAKES_REVIEW_RESOLVED" : "HEM_CONSENT_ESCALATION_INITIATED", {
  ...f,
  ...(f.ale_subtype === "HIGH_STAKES_RESOLVED" ? { resolved_at: new Date().toISOString() } : { initiated_at: new Date().toISOString() }),
});

export const emitAle041ConsentEscalationResolved = (f: {
  hem_id: string; resolution_type: "CONSENT_OBTAINED" | "TIMEOUT_DENY" | "TERMINATED"; consent_basis: string | null;
}) => ale("ALE-041", "HEM_CONSENT_ESCALATION_RESOLVED", { ...f, resolved_at: new Date().toISOString() });
