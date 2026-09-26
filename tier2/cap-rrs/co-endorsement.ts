import { CapRrsError, type AuthoritySource } from "./types.js";

export interface CoEndorserStatus {
  authority_id: string;
  endorsement_claim_valid: boolean;
}

/** CONF-RRS-COEND-01: a GEC MUST NOT activate a Cedar policy with co_endorsement_required unless all required endorsements (per quorum) are present and valid. */
export function assertCoEndorsementQuorumMet(source: AuthoritySource, coEndorserStatuses: CoEndorserStatus[]): void {
  if (!source.endorsement.co_endorsement_required) return;

  const required = source.endorsement.co_endorsers ?? [];
  const quorum = source.endorsement.co_endorsement_quorum;

  if (quorum === "primary_only") return; // primary authority endorsement alone is sufficient

  // quorum === "all": every required co-endorser must have a valid endorsement_claim
  for (const reqId of required) {
    const status = coEndorserStatuses.find((s) => s.authority_id === reqId);
    if (!status || !status.endorsement_claim_valid) {
      throw new CapRrsError("CO_ENDORSEMENT_QUORUM_NOT_MET", `CONF-RRS-COEND-01: co-endorser ${reqId} has no valid endorsement_claim — quorum "all" not met, policy MUST NOT activate`);
    }
  }
}

/** §9.5(d): if any co-endorser's claim is superseded/expired/revoked, the policy MUST be suspended regardless of other co-endorsers' status. */
export function assertNoCoEndorserSupersession(coEndorserStatuses: CoEndorserStatus[]): { mustSuspend: boolean } {
  const anyInvalid = coEndorserStatuses.some((s) => !s.endorsement_claim_valid);
  return { mustSuspend: anyInvalid };
}
