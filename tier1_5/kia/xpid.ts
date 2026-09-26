import { v5 as uuidv5 } from "./uuid5.js";
import { sha256Hex } from "./canon.js";
import { KiaError, type Sha256Hex, type Xpid } from "./types.js";

/** §6.2(a) — the standard DNS UUID namespace, used as a stable domain. */
export const XPID_NAMESPACE = "6ba7b814-9dad-11d1-80b4-00c04fd430c8";

/**
 * §6.2 derivation procedure.
 * XPID = UUID5(namespace, kernel_keypair_fingerprint + ":" + party_registry_entry_hash)
 */
export function deriveXpid(
  kernelKeypairFingerprint: Sha256Hex,
  partyRegistryEntryHash: Sha256Hex,
): Xpid {
  const name = `${kernelKeypairFingerprint}:${partyRegistryEntryHash}`;
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
  presentingKernelKeypairFingerprint: Sha256Hex,
  agentPartyRegistryEntryHash: Sha256Hex,
): { recomputedXpid: Xpid; matches: boolean } {
  const recomputedXpid = deriveXpid(
    presentingKernelKeypairFingerprint,
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
  presentingKernelKeypairFingerprint: Sha256Hex,
  agentPartyRegistryEntryHash: Sha256Hex,
): void {
  const { matches, recomputedXpid } = verifyXpidCrossInstance(
    presentedXpid,
    presentingKernelKeypairFingerprint,
    agentPartyRegistryEntryHash,
  );
  if (!matches) {
    throw new KiaError(
      "KIA_XPID_VERIFICATION_FAILED",
      `presented XPID ${presentedXpid} does not match recomputed ${recomputedXpid}`,
    );
  }
}
