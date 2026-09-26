export type CedarDecision = "PERMIT" | "FORBID";

export interface CedarPolicyResult {
  policy_id: string;
  tier: "TIER_1" | "TIER_2";
  decision: CedarDecision;
}

/**
 * CONF-CAP-CONFLICT-01: when Cedar policies from different tiers conflict,
 * the most restrictive result governs — a forbid from ANY tier MUST take
 * precedence over a permit from any other tier. Explicit normative
 * statement of "forbid wins", not just reliance on Cedar's default.
 */
export function evaluateCedarPolicySet(results: CedarPolicyResult[]): { decision: CedarDecision; forbiddingPolicyId: string | null } {
  const forbid = results.find((r) => r.decision === "FORBID");
  if (forbid) return { decision: "FORBID", forbiddingPolicyId: forbid.policy_id };
  return { decision: "PERMIT", forbiddingPolicyId: null };
}
