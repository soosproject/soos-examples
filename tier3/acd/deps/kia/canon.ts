import { createHash } from "node:crypto";
import nacl from "tweetnacl";

/**
 * Canonical JSON per §7.2's canonical form (same rule reused for GEC Manifest
 * signing per the -04 proposal's manifest_signature field description):
 * object keys sorted lexicographically, recursively, no whitespace.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      out[k] = sortKeys((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
}

export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

export function toB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export function fromB64(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

/**
 * Sample-code stand-in for the GEC keypair signing operation.
 * §4.1(b): private key material MUST NOT leave the secure element in a real
 * deployment. This in-process Ed25519 signing is a stub — see the KernelSpec
 * "What Sample Code Does Not Teach" table: cryptographic correctness here is
 * "standard library or stub", not HSM/TEE-backed.
 */
export function signCanonical(secretKey: Uint8Array, value: unknown): string {
  const bytes = new TextEncoder().encode(canonicalJson(value));
  return toB64(nacl.sign.detached(bytes, secretKey));
}

export function verifyCanonical(
  publicKey: Uint8Array,
  value: unknown,
  signatureB64: string,
): boolean {
  const bytes = new TextEncoder().encode(canonicalJson(value));
  return nacl.sign.detached.verify(bytes, fromB64(signatureB64), publicKey);
}
