// MAD-03 §6.1 — Sub-Agent XPID Derivation.
//
// sub_agent_xpid = UUID5(KIA_XPID_NAMESPACE, parent_xpid + ":" + sacr_id)
//
// This is explicitly a DIFFERENT formula from KIA §6.2's own
// deriveXpid(operatorIdentity, partyRegistryEntryHash) in
// ../deps/kia/xpid.ts (v2.0: operatorIdentity, not kernelKeypairFingerprint —
// see that file), which is for a *root* agent's XPID. MAD-03 §6.1
// says the sub-agent formula "extends the KIA-03 derivation to the
// delegation tree case" — it reuses the same namespace constant and the
// same UUID5 primitive, not the same two input fields. Both are
// imported/reused verbatim from the real Step 6 module rather than
// reimplemented, per CONF-MAD-XPID-01/03/04/05's emphasis on
// verifiability against the originating GEC's signed records.

import { v5 as uuidv5 } from '../deps/kia/uuid5.js';
import { XPID_NAMESPACE as KIA_XPID_NAMESPACE } from '../deps/kia/xpid.js';
import type { Uuid } from './types.js';

export { KIA_XPID_NAMESPACE };

/** §6.1 derivation procedure — deterministic, traceable, non-forgeable without the SACR chain. */
export function deriveSubAgentXpid(parentXpid: Uuid, sacrId: Uuid): Uuid {
  const name = `${parentXpid}:${sacrId}`;
  return uuidv5(name, KIA_XPID_NAMESPACE);
}

/**
 * §6.2 Cross-Cluster XPID Verification — receiving-side recompute-and-compare,
 * same non-trust-on-receipt pattern as KIA-03's verifyXpidCrossInstance()
 * (CONF-KIA-21 precedent, reapplied here per CONF-MAD-XPID-02/03/04).
 */
export function verifySubAgentXpid(
  presentedXpid: Uuid,
  parentXpid: Uuid,
  sacrId: Uuid,
): { recomputedXpid: Uuid; matches: boolean } {
  const recomputedXpid = deriveSubAgentXpid(parentXpid, sacrId);
  return { recomputedXpid, matches: recomputedXpid === presentedXpid };
}
