import nacl from "tweetnacl";
import { KiaError } from "./types.js";
import { canonicalJson, toB64 } from "./canon.js";

/**
 * NOT a real FROST implementation. draft-irtf-cfrg-frost threshold Schnorr
 * signing requires a proper round-optimized ceremony (commitment exchange,
 * binding-factor computation, aggregation) that a stub cannot honestly
 * approximate — unlike Ed25519 itself, faking FROST's math would be
 * misleading rather than merely simplified. This stand-in instead simulates
 * the OPERATIONAL invariants KIA-03 makes normative: quorum enforcement
 * (CONF-KIA-18/19/20) and nonce-reuse rejection (CONF-KIA-16/17, §15.8) —
 * using a single underlying Ed25519 keypair to represent "the threshold
 * public key" and per-participant nonce tracking to model the attack surface.
 * A production KIA implementation MUST use a real FROST library.
 */

export interface FrostParticipant {
  id: string;
  /** Nonces already consumed by this participant — used to detect reuse. */
  usedNonces: Set<string>;
}

export class FrostSigningCluster {
  private participants: Map<string, FrostParticipant> = new Map();
  private readonly thresholdKeypair = nacl.sign.keyPair();

  constructor(
    public readonly threshold: number,
    participantIds: string[],
  ) {
    if (participantIds.length < threshold) {
      throw new Error("participant count below threshold at construction");
    }
    for (const id of participantIds) {
      this.participants.set(id, { id, usedNonces: new Set() });
    }
  }

  get thresholdPublicKey(): Uint8Array {
    return this.thresholdKeypair.publicKey;
  }

  /** CONF-KIA-16/17: fresh nonce per operation, no caching/reuse. */
  private freshNonce(): string {
    return toB64(nacl.randomBytes(24));
  }

  /**
   * Sign with a simulated quorum of `respondingIds`.
   * CONF-KIA-18: refuses below threshold, MUST NOT degrade to single-signer.
   * CONF-KIA-19: caller should emit KERNEL_AUDIT_ANOMALY on the thrown error.
   */
  sign(value: unknown, respondingIds: string[], opts?: { forceNonceReuse?: string }): string {
    const responders = respondingIds.filter((id) => this.participants.has(id));
    if (responders.length < this.threshold) {
      throw new KiaError(
        "KIA_QUORUM_FAILURE",
        `FROST quorum failure: ${responders.length}/${this.threshold} required participants responded`,
      );
    }

    for (const id of responders) {
      const participant = this.participants.get(id)!;
      const nonce = opts?.forceNonceReuse ?? this.freshNonce();
      if (participant.usedNonces.has(nonce)) {
        // §15.8 attack vector realized: same participant, same nonce, two ops.
        throw new KiaError(
          "KIA_NONCE_REUSE_DETECTED",
          `Nonce reuse detected for participant ${id} — secret share exposure risk`,
        );
      }
      participant.usedNonces.add(nonce);
    }

    // Threshold public key stands in for the aggregated signature's verifying
    // key; the underlying signature is produced with the cluster's simulated
    // threshold secret key, external verifiers cannot tell FROST from single-key
    // (per §4.1(d): "External verifiers are not required to know whether the
    // deployment is FROST or single-key").
    const bytes = new TextEncoder().encode(canonicalJson(value));
    return toB64(nacl.sign.detached(bytes, this.thresholdKeypair.secretKey));
  }

  verify(value: unknown, signatureB64: string): boolean {
    const bytes = new TextEncoder().encode(canonicalJson(value));
    return nacl.sign.detached.verify(
      bytes,
      Buffer.from(signatureB64, "base64"),
      this.thresholdPublicKey,
    );
  }
}
