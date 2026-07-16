import { sha256Hex, signCanonical, verifyCanonical } from "./canon.js";
import {
  KiaError,
  type Ed25519KeyPair,
  type GecManifest,
  type GecManifestFields,
  type Iso8601Date,
  type Sha256Hex,
} from "./types.js";

/** §5.4 recommended maximum staleness, seconds. */
export const MANIFEST_STALENESS_LIMIT_SECONDS = 86400;

export interface IssueManifestInput {
  kernelKeypair: Ed25519KeyPair;
  operatorIdentity: Sha256Hex;
  hardwareBacked: boolean;
  ptdEndpoint: string;
  ptdCurrentVersion: string;
  kernelVersion: string;
  loadedPolicyIds: string[];
  cedarPolicyHash: Sha256Hex;
  deploymentConstraints: string[];
  implementsXpid: boolean;

  // -04 PROPOSED fields (CONF-KIA-24/25). REQUIRED per the proposal even
  // though -04 is unmerged, since we're building ahead of it.
  /**
   * -04: release date of kernel_version, NOT the compile-machine clock.
   * CONF-KIA-24: deterministic per kernel_version — same value for every
   * conforming build of the same version. Caller supplies it; this function
   * does not derive it from `new Date()`, precisely to avoid the violation
   * the -04 text warns against.
   */
  kernelVersionDate: Iso8601Date;
  /**
   * -04: implementer/vendor identifier, distinct from operatorIdentity.
   * CONF-KIA-25: MUST be populated even when equal to operatorIdentity for
   * self-implemented deployments (per the proposal's dual-path format:
   * keypair fingerprint if the implementer signs releases, else a URI).
   */
  kernelImplementerId: string;
}

export function issueGecManifest(input: IssueManifestInput): GecManifest {
  const kernel_keypair_fingerprint = sha256Hex(input.kernelKeypair.publicKey);
  const now = new Date().toISOString();

  const fields: GecManifestFields = {
    kernel_keypair_fingerprint,
    operator_identity: input.operatorIdentity,
    deployment_timestamp: now,
    hardware_backed: input.hardwareBacked,
    ptd_endpoint: input.ptdEndpoint,
    ptd_current_version: input.ptdCurrentVersion,
    kernel_version: input.kernelVersion,
    loaded_policy_ids: input.loadedPolicyIds,
    cedar_policy_hash: input.cedarPolicyHash,
    attestation_timestamp: now,
    deployment_constraints: input.deploymentConstraints,
    xpid_derivation_version: input.implementsXpid ? "1.0" : "none",
    kernel_version_date: input.kernelVersionDate,
    kernel_implementer_id: input.kernelImplementerId,
  };

  const manifest_signature = signCanonical(input.kernelKeypair.secretKey, fields);

  return { fields, manifest_signature };
}

export function verifyManifestSignature(
  manifest: GecManifest,
  kernelPublicKey: Uint8Array,
): boolean {
  return verifyCanonical(kernelPublicKey, manifest.fields, manifest.manifest_signature);
}

/** §5.4 Staleness — receiving-side check, also gates federation per §6.4(c). */
export function assertManifestFresh(
  manifest: GecManifest,
  nowMs: number = Date.now(),
  limitSeconds: number = MANIFEST_STALENESS_LIMIT_SECONDS,
): void {
  const issuedMs = Date.parse(manifest.fields.attestation_timestamp);
  const ageSeconds = (nowMs - issuedMs) / 1000;
  if (ageSeconds > limitSeconds) {
    throw new KiaError(
      "KIA_MANIFEST_STALE",
      `GEC Manifest age ${ageSeconds.toFixed(0)}s exceeds staleness limit ${limitSeconds}s`,
    );
  }
}

export function assertManifestSignatureValid(
  manifest: GecManifest,
  kernelPublicKey: Uint8Array,
): void {
  if (!verifyManifestSignature(manifest, kernelPublicKey)) {
    throw new KiaError("KIA_MANIFEST_SIGNATURE_INVALID", "GEC Manifest signature does not verify");
  }
}
