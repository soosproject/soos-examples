import { sha256Hex, signCanonical, verifyCanonical } from "./canon.js";
import {
  KiaError,
  type EventLogEntry,
  type RevocationEntry,
  type Sha256Hex,
  type SignedEventLogEntry,
} from "./types.js";

/**
 * §7 Event Log Signing (INV-9). Carried forward from -02 unmodified in -03;
 * this implementation reuses the same canonical-JSON + Ed25519 signing
 * primitives as the GEC Manifest (canon.ts), consistent with the -04
 * proposal's manifest_signature description, which assumes the same
 * canonical form is shared across KIA artifacts.
 */
export function signEventLogEntry(
  entry: EventLogEntry,
  kernelSecretKey: Uint8Array,
  kernelKeypairFingerprint: Sha256Hex,
): SignedEventLogEntry {
  return {
    entry,
    kernel_keypair_fingerprint: kernelKeypairFingerprint,
    kernel_signature: signCanonical(kernelSecretKey, entry),
  };
}

export function verifyEventLogEntry(
  signed: SignedEventLogEntry,
  kernelPublicKey: Uint8Array,
): boolean {
  const fingerprintMatches =
    sha256Hex(kernelPublicKey) === signed.kernel_keypair_fingerprint;
  return (
    fingerprintMatches &&
    verifyCanonical(kernelPublicKey, signed.entry, signed.kernel_signature)
  );
}

/**
 * [NEW post-session] Assert-style counterpart to verifyEventLogEntry, mirroring
 * manifest.ts's assertManifestSignatureValid. Previously, callers had no
 * throwing form and demo.ts hand-rolled a deny code by reusing
 * KIA_MANIFEST_SIGNATURE_INVALID for an Event Log failure — a naming
 * mismatch that could mislead a consumer keying alerts off deny-code names.
 * Uses the dedicated KIA_EVENT_LOG_SIGNATURE_INVALID code instead.
 */
export function assertEventLogEntryValid(
  signed: SignedEventLogEntry,
  kernelPublicKey: Uint8Array,
): void {
  if (!verifyEventLogEntry(signed, kernelPublicKey)) {
    throw new KiaError(
      "KIA_EVENT_LOG_SIGNATURE_INVALID",
      "Event Log entry signature does not verify",
    );
  }
}

// ---------------------------------------------------------------------------
// §8 Revocation Registry (INV-11)
// ---------------------------------------------------------------------------

/**
 * §8.2 Rebuild on Restart: the registry is rebuildable from the signed Event
 * Log's revocation events — modeled here as a plain in-memory index over an
 * append-only entry list, matching the KernelSpec "sample code does not
 * teach persistence" caveat (real deployments use an append-only event
 * store, not this Map).
 */
export class RevocationRegistry {
  private entries = new Map<string, RevocationEntry>();

  revoke(entry: RevocationEntry): void {
    this.entries.set(entry.jti, entry);
  }

  isRevoked(jti: string): boolean {
    return this.entries.has(jti);
  }

  get(jti: string): RevocationEntry | undefined {
    return this.entries.get(jti);
  }

  /**
   * §6.4(a) / CONF-KIA-23 — the mandatory interim mitigation for
   * OQ-S-XPID-REV: federated kernels MUST check jti against the local
   * registry independently of XPID verification, since XPID revocation
   * propagation is not yet normative (§6.4, §15.9).
   */
  assertNotRevoked(jti: string): void {
    if (this.isRevoked(jti)) {
      const entry = this.get(jti)!;
      throw new KiaError(
        "KIA_JTI_REVOKED",
        `mandate jti ${jti} is revoked (scope=${entry.revocation_scope}, at=${entry.revoked_at})`,
      );
    }
  }

  rebuildFromEventLog(revocationEvents: RevocationEntry[]): void {
    this.entries.clear();
    for (const e of revocationEvents) this.revoke(e);
  }
}
