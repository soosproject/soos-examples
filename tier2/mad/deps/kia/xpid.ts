import { v5 as uuidv5 } from "./uuid5.js";
import { sha256Hex } from "./canon.js";
import { KiaError, type Sha256Hex, type Xpid } from "./types.js";

/** §6.2(a) — the standard DNS UUID namespace, used as a stable domain. */
export const XPID_NAMESPACE = "6ba7b814-9dad-11d1-80b4-00c04fd430c8";

/**
 * §6.2 derivation procedure, version 2.0 (REVISED, kernel design restart).
 * XPID = UUID5(namespace, operator_identity + ":" + party_registry_entry_hash)
 *
 * Anchor moved from kernel_keypair_fingerprint (versions 1.0/1.1) to
 * operator_identity: the old anchor meant every routine GEC keypair
 * rotation, FROST cluster membership change, or R-8 recovery
 * re-attestation silently re-derived a new XPID for every governed agent,
 * and meant two GEC instances sharing one operator could never converge
 * on the same XPID for the same agent. operator_identity is untouched by
 * all three events and is already present in every GEC Manifest, so this
 * is a substitution of derivation input, not a new field.
 */
export function deriveXpid(
  operatorIdentity: Sha256Hex,
  partyRegistryEntryHash: Sha256Hex,
): Xpid {
  const name = `${operatorIdentity}:${partyRegistryEntryHash}`;
  return uuidv5(name, XPID_NAMESPACE);
}

/** §6.2 — party_registry_entry_hash: SHA-256 of the canonical Party Registry entry. */
export function partyRegistryEntryHash(canonicalPartyRegistryEntryJson: string): Sha256Hex {
  return sha256Hex(canonicalPartyRegistryEntryJson);
}

/**
 * §6.3 Cross-Instance Trust Model — receiving-side verification.
 * CONF-KIA-21: a client-supplied XPID MUST NOT be accepted as authoritative;
 * this function only ever returns a value it recomputed itself, never the
 * presented one, forcing callers to compare rather than trust-on-receipt.
 */
export function verifyXpidCrossInstance(
  presentedXpid: Xpid,
  presentingOperatorIdentity: Sha256Hex,
  agentPartyRegistryEntryHash: Sha256Hex,
): { recomputedXpid: Xpid; matches: boolean } {
  const recomputedXpid = deriveXpid(
    presentingOperatorIdentity,
    agentPartyRegistryEntryHash,
  );
  return { recomputedXpid, matches: recomputedXpid === presentedXpid };
}

/**
 * §6.3(d) + CONF-KIA-21 combined check for use at ingestion time.
 * Throws KIA_XPID_VERIFICATION_FAILED — caller logs XPID_VERIFICATION_FAILED
 * to its own Event Log per §6.3(d).
 */
export function assertXpidVerified(
  presentedXpid: Xpid,
  presentingOperatorIdentity: Sha256Hex,
  agentPartyRegistryEntryHash: Sha256Hex,
): void {
  const { matches, recomputedXpid } = verifyXpidCrossInstance(
    presentedXpid,
    presentingOperatorIdentity,
    agentPartyRegistryEntryHash,
  );
  if (!matches) {
    throw new KiaError(
      "KIA_XPID_VERIFICATION_FAILED",
      `presented XPID ${presentedXpid} does not match recomputed ${recomputedXpid}`,
    );
  }
}
