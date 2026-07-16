# KIA — Kernel Identity and Attestation

Sample TypeScript implementation of `draft-sato-soos-kia-03` (Tier 1.5),
with three proposed `-04` GEC Manifest field additions integrated ahead of
that revision's finalization — see **Known gaps** below before assuming
any `-04`-only behavior is settled.

KIA anchors a GEC's identity to hardware-backed keys, issues and verifies
the GEC Manifest, simulates FROST threshold signing for multi-party
signing clusters, derives and cross-verifies the XPID cross-principal
identifier, and signs/verifies the Event Log with the interim revocation
mitigation for the documented XPID revocation-propagation gap.

## Files

| File | Purpose |
|---|---|
| `types.ts` | Core types — `Sha256Hex`, `Ed25519SigB64`, `Xpid`, `EventLogEntry`, `KiaError` — and the module-level note on `-04`'s unmerged status |
| `canon.ts` | Canonical JSON serialization, SHA-256 hashing, and Ed25519 sign/verify (via `tweetnacl`) — the crypto primitives every other file builds on |
| `uuid5.ts` | UUID v5, implemented from scratch, used for XPID derivation |
| `manifest.ts` | GEC Manifest issuance and verification (§5.2) — `issueGecManifest`, `verifyManifestSignature`, `assertManifestFresh`, `assertManifestSignatureValid` — including the two proposed `-04` fields |
| `frost.ts` | `FrostSigningCluster` — quorum enforcement (refuses below threshold, never silently degrades to a single signer) and nonce-reuse detection. **Not real FROST threshold cryptography** — see Known gaps |
| `xpid.ts` | XPID derivation and cross-instance verification (§6.2–6.3) — `deriveXpid`, `partyRegistryEntryHash`, `assertXpidVerified`, `verifyXpidCrossInstance` |
| `event-log.ts` | Event Log signing/verification (§7, INV-9) and `RevocationRegistry` — including the §6.4(a)/`CONF-KIA-23` interim mitigation for the XPID revocation-propagation gap |
| `demo.ts` | End-to-end walkthrough: manifest issuance → FROST cluster signing → XPID derivation → event log signing → revocation check → manifest freshness (both a fresh and a deliberately stale manifest) |

## Quick start

```bash
npm install
npm run demo
```

## Known gaps

This module is intentionally built against `-03` as the normative text,
with three fields from the proposed, **not-yet-merged** `-04` GEC Manifest
changes integrated ahead of finalization. All three are open items in the
`-04` proposal itself, not implementation bugs:

- **`SDB-KIA-01`** — §5.4 manifest currency check. Open and separate from
  the `-04` items below; tracked as planned follow-up work (Step 6a), not
  yet reflected in this module's code.
- **`SDB-KIA-04-01`** — `kernel_implementer_id` format: built supporting
  *both* keypair-fingerprint and URI paths, per the proposal's dual-path
  design. Not confirmed as final.
- **`SDB-KIA-04-02`** — no separate Security Considerations caveat added
  for `kernel_implementer_id`, matching the proposal's stated default.
  Not confirmed.
- **`SDB-KIA-04-03`** — §15.12 numbering is a doc-only question; doesn't
  affect this code.

Stated directly in the source (`types.ts`): *"If -04 lands differently,
this module's manifest fields are the blast radius."*

Scope note, stated honestly rather than padded: this module ships 7 happy-path
and 8 edge-case logs — not the fuller 20+21 corpus pattern used elsewhere in
the sample-code sprint. KIA's real complexity (FROST, XPID, federation,
revocation) is covered, but this pass didn't stretch to a full adversarial
corpus to match that precedent.

## What this sample code does NOT give you

- **Not real FROST threshold cryptography.** `FrostSigningCluster` is stated
  directly in its own source as explicitly not implementing real FROST math —
  a cryptographic stub here would be actively misleading about what threshold
  signing actually guarantees. It models the *operational* invariants only
  (quorum enforcement, nonce-reuse detection), not the underlying threshold
  scheme.
- **Not wired to GAR's signer.** This release's GAR module still uses its own
  local `KIAStubSigner` (see GAR's README) rather than this module's real
  Ed25519 signing. The two are not integrated with each other in this release
  — each demonstrates its own layer in isolation. Wiring KIA's real signer
  into GAR's Session Block signing is a natural next step, not yet done here.
- No durable storage, no real hardware-backed key provisioning, no production
  federation across real GEC instances, and no performance characteristics
  representative of a production deployment.
