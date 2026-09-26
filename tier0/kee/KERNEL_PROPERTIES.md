# KERNEL_PROPERTIES.md
## KEE-1 Quick Reference — Canonical Property Model for Sample Code (Steps 1–18)

| Field | Value |
|---|---|
| **Source draft** | draft-sato-soos-kee-01 (confirmed identical to -00 except header) |
| **Canonical basis** | §4 (Generation 3 property model), per DR-KEE-02 |
| **Resolution applied** | DR-KEE-02 Option A — Kernel Instance Isolation folded into P1 |
| **Status** | FINAL for sample code purposes. Draft-text sweep (§1.1, §3.3, §5.1, §9.7) still pending -02 — see DR-KEE-02 §6. |
| **Purpose** | Reference card for every stub decision in Steps 1–18 of Sample Code Plan v4 |

---

## Why this document exists

`draft-sato-soos-kee-01` currently contains two generations of its own property model mixed together (see DR-KEE-02 for full history). This document extracts the **single canonical version** — Generation 3, as defined normatively in §4 and already relied upon by `draft-sato-soos-dist-00` (KEE-2) — so that every TypeScript stub written in Steps 1–18 is built against one consistent set of eight properties, not the stale fragments still present in the draft's front matter.

If you are implementing a stub and the draft's §1.1, §3.3, §5.1, or §9.7 seems to say something different from this table, **this document wins** — those sections are known-stale pending the -02 sweep.

---

## The Eight Properties (canonical)

| # | Property | One-line concern | Primary normative output |
|---|---|---|---|
| **P1** | Cedar Policy Cluster **+ Kernel Instance Isolation** (DR-KEE-02 Option A) | Synchronous, atomic, isolated Cedar evaluation; no cross-instance state bleed | PERMIT/DENY before ACT; no instance bleed |
| **P2** | FROST Threshold Signing | (t,n) threshold KIA signing, default (2,3); standard Ed25519 for non-FROST | Valid KIA signature, no single point of key compromise |
| **P3** | ACD Four-Check Sequence | Manifest validity → policy currency → KIA attestation → revocation status, in order | Validated ACD Record or refusal + ALE-059 |
| **P4** | Catalog Authority | 2-of-3 publisher key required for CAP Profile updates, checked before conflict detection | Accepted or rejected catalog update |
| **P5** | GEC Manifest Immutability | Hash-locked at init; any change requires new deployment, not runtime update | Tamper-evident manifest integrity |
| **P6** | OTel Emission | Mandatory `soos.governance.*` spans at 100% sampling at 5 defined emission points | Observability spans (non-authoritative) |
| **P7** | WAL Tamper Evidence | `prev_span_hash` chain + Session Block Merkle root + KIA signature | Tamper-evident GAR stream (authoritative record) |
| **P8** | Revocation Propagation | CAEP/SSF subscription, 30s propagation timeout, CLEAN/PARTIAL/UNKNOWN states | Revocation signal honored fleet-wide |

**All eight properties are REQUIRED.** A deployment satisfying P1–P7 but not P8 is not KEE-1-compliant (§3.3).

**Fail-Closed Invariant** is not its own numbered property in Generation 3 — it's a cross-cutting rule referenced from P1 (Cedar unavailable → CEDAR_DENY) and P8 (revocation status uncertain → deny). Treat it as a behavior every stub must implement at its own failure boundary, not a separate class to build.

---

## P1 — Cedar Policy Cluster + Kernel Instance Isolation

**Cedar requirements (§4.1):**
1. Synchronous with agent action authorization — no action executes before Cedar returns PERMIT
2. Loaded from active CAP Profile at kernel startup
3. Atomic updates — old policy set stays active until new set fully loaded/validated; no evaluation gap
4. Read-only from outside kernel boundary; updates only via internal channel
5. Cluster deployments: Raft consensus + etcd; all nodes hold same `cap_profile_hash`
6. Hot-reload without kernel restart

**Failure behavior:** Cedar unavailable → ALL requests get CEDAR_DENY. Never ungoverned operation.

**Isolation requirements (folded in per DR-KEE-02 Option A):**
- No cross-instance Cedar policy state access
- No cross-instance GAR write stream interleaving
- No cross-instance KIA private key access
- No cross-instance MJWT mandate scope access

**Linux reference:** Rust `cedar-policy` crate in-process; `tokio::sync::RwLock` hot-swap; one Docker/containerd container per kernel instance, one network namespace per instance.

**TypeScript stub approach:** A single-process, single-instance stub naturally satisfies isolation (nothing to isolate from in a demo). Implement the Cedar evaluation call as synchronous-by-contract (`await` before any mutating action proceeds) and stub "CEDAR_DENY on failure" as a hard-coded catch-all in the evaluation wrapper. No real Raft/etcd cluster needed at sample-code scale — comment `// Cluster consensus (Raft/etcd) is KEE-2/SOOS-DIST scope, not implemented here`.

---

## P2 — FROST Threshold Signing

- Default threshold (t,n) = (2,3); non-FROST deployments use standard Ed25519 single keypair
- Ed25519 required underlying scheme (FROST-Ed25519 variant)
- Each signer generates its own nonce via CSPRNG immediately before signing — **never** centrally generated, cached, or reused
- Threshold `t` must never be reduced below initial value; if signers drop below `t`, suspend signing (P8 fail-closed applies)
- Signer instances must be on physically separate hardware
- Threshold public key declared in GEC Manifest, must match active config

**TypeScript stub approach (per Step 1 KIA stub decision already made):** Generate a local Ed25519 keypair for Session Block signing. Comment: `// KIA stub — replace with real KIA Governance Identity Keypair when Step 6 completes`. FROST threshold logic itself is out of scope for the GAR stub — GAR only needs *a* valid signature over the Merkle root, not a real threshold ceremony.

---

## P3 — ACD Four-Check Sequence

Checks MUST run **in this order**; failure at any check → refuse ACD Record + log ALE-059 with `failed_layer` = check number (1–4):

1. **Manifest Validity** — `gec_manifest_ref` points to a current, unrevoked GEC Manifest (within staleness window)
2. **Policy Currency** — `cedar_policy_hash` = fresh SHA-256 of the *currently active* Cedar Policy Set, computed immediately before signing (never precomputed/stale)
3. **KIA Attestation** — kernel's KIA signing key not in Revocation Registry
4. **Revocation Status** — agent's XPID not revoked / no CAEP revocation signal received

Success logs ALE-057 (`ACD_RECORD_ISSUED`); initiation logs ALE-056 (`ACD_QUERY_RECEIVED`).

**TypeScript stub approach:** Implement as four discrete, independently-testable functions run in sequence with early-exit on first failure, each returning a typed result carrying the check number for `failed_layer`. This is a natural fit for SVL edge-case generation (Step 1c style) — one adversarial log per check failure.

---

## P4 — Catalog Authority

1. Three authorized publisher public keys configured at kernel init
2. CAP Profile update needs signatures from **at least 2 of 3** — single-publisher updates rejected regardless of who signed
3. Publisher keys declared in GEC Manifest; key changes require new manifest
4. Publisher key validation happens **before** catalog conflict detection (separate check) — a validation failure never reaches conflict detection
5. Passes publisher validation but fails conflict detection → reject + log ALE-NEW-02 (`CAP_CATALOG_CONFLICT_DETECTED`)

**Government Deployment Profile note:** the three publisher roles are National Digital Authority, National Cybersecurity Authority, and the operator (§8.2).

**TypeScript stub approach:** Stub as a function taking an array of ≤3 signatures and validating count ≥2 against known public keys; conflict detection can be a separate, later-called function per requirement 4's strict ordering. Not needed until Step 9 (CAP) — flagged in Sample Code Plan as OQ-SC-02 (Cedar dependency) territory, not GAR's concern.

---

## P5 — GEC Manifest Immutability

1. Produced at kernel init; never updated during operation
2. Any change to CAP Profile hash, publisher keys, FROST config, or kernel version → new deployment, not runtime update
3. Hash-locked at init (SHA-256 of manifest JSON); recomputed and verified at every access; mismatch → fail-closed
4. No new GEC Manifest during an active AEP session

**TypeScript stub approach:** A `GECManifest` object frozen (`Object.freeze`) after construction, with a stored `manifestHash` computed once and a `verifyIntegrity()` method that recomputes and compares. Simple to stub; the interesting behavior is the fail-closed trigger on mismatch, which is worth exercising in SVL edge cases.

---

## P6 — OTel Emission

Mandatory `soos.governance.*` spans, **100% sampling always** (no sampling permitted for governance spans), at five points:

1. Cedar evaluation — `kernel_id`, `session_id`, `cap_profile_id`, `policy_ids_evaluated`, `decision`, `tier`
2. GAR write — `ale_type`, `ale_seq`, `prev_span_hash`
3. HEM escalation — `hem_class`, `hem_resolution`
4. ACD handshake — `session_id`, `check_seq` (the four-check result)
5. KIA signing — `kia_key_id`, (FROST only) `frost_threshold_config`

**Critical distinction:** OTel is explicitly **untrusted/non-authoritative**. The GAR WAL is the authoritative audit record. The GAR Processor *derives* GAR from OTel spans — OTel spans are not themselves accepted as the record.

**TypeScript stub approach (per Step 1 OTel stub decision already made):** `GARProcessor` class collects `soos.governance.*` attributes in-memory and prints to console rather than emitting to a real OTel backend. Model the five emission points as five typed helper methods so the mapping to real `@opentelemetry/api` spans is a drop-in swap later, not a rewrite.

---

## P7 — WAL Tamper Evidence

1. Every GAR ALE write carries `prev_span_hash` (SHA-256 of immediately preceding ALE); first ALE in session has `prev_span_hash: null`
2. Chain verified by GAR Processor at Session Block construction; a break → flag session block tampered + GAR alert
3. At Session Block close: compute Merkle root over all ALEs in block, produce KIA signature over `(block_id, Merkle_root, block_close_timestamp)`
4. `block_id` **must equal** the OTel `trace_id` for the session's governance span set — this is the verifiable OTel↔GAR link
5. GAR Processor verifies Merkle root at every audit read; failure → tamper alert

**This is GAR's core normative content** — Step 1's `computePrevSpanHash()`, `verifyChain()`, `SessionBlock` class, and `tamperDetect()` all implement this property directly.

**Pre-flight question still open per Sample Code Plan Step 1a:** which fields are included in `prev_span_hash` computation and in what order — check GAR §4 before generating any logs (SDB-GAR-01).

---

## P8 — Revocation Propagation

1. Local Revocation Registry maintained, rebuilt from GAR on restart
2. Subscribe to CAEP over Shared Signals Framework (RFC 9672) for federated deployments
3. On CAEP signal: add to registry within **30-second** propagation timeout
4. Track completion state per revocation event:
   - **CLEAN** — all instances acknowledged within timeout
   - **PARTIAL** — some unacknowledged; originating kernel retries
   - **UNKNOWN** — affected instance set can't be determined (unenumerated federated context) → escalate to operator + GAR alert
5. **Fail-closed applies:** if CAEP/SSF unavailable, deny any action whose revocation status can't be confirmed

**TypeScript stub approach:** A simple registry (`Set<string>` or `Map`) with a stubbed CAEP receiver function; the three completion states are a natural enum. The fail-closed behavior here is the same interrupt-and-deny pattern as P1's Cedar failure — worth implementing as a shared helper rather than duplicating logic.

---

## XPID Derivation Function (§10 — not one of P1–P8, but load-bearing)

```typescript
import { v5 as uuidv5 } from 'uuid';

const SOOS_NAMESPACE = 'bcab38fe-febf-4632-8fc9-2a23cb9e4ee3'; // IANA-registered, §14.3

function deriveXPID(
  initiatingKIAId: string,
  respondingKIAId: string,
  initiatedAt: string,
  initiatingNonce: string,
  respondingNonce: string
): string {
  const name = [
    initiatingKIAId,
    respondingKIAId,
    initiatedAt,
    initiatingNonce,
    respondingNonce
  ].join('|');
  return uuidv5(name, SOOS_NAMESPACE);
}
```

Requirements: deterministic, side-effect-free (no logging, no network calls, no state changes), nonces must be CSPRNG-generated immediately before the call, never cached/reused. **Not used for sub-agent XPIDs** — those derive from parent XPID + session nonce per KIA-03 §6.2, a different function.

This is straight from the draft's own TypeScript reference implementation (§10) — usable close to verbatim in the sample code.

---

## Conformance Levels (§5) — affects which stub tier applies

| Level | Context | Key protection | GAR storage | Notes |
|---|---|---|---|---|
| **L1 Software** | Dev/PoC — **this is the sample code target** | OS keystore | SQLite WAL | No TEE; not for production, regulated, or government use |
| **L2 Sidecar** | Enterprise production | TEE (Intel TDX/AMD SEV/ARM TrustZone) | PostgreSQL WAL | FROST optional but recommended |
| **L3 TEE/Hardware** | Government/regulated | TEE + hardware attestation chain | PostgreSQL WAL | FROST required for multi-instance; PTP clock required; 2-of-3 publisher key required |

All sample code in Steps 1–18 targets **L1** per the "What Sample Code Teaches — and What It Does Not" table in the Sample Code Plan: crypto is stubbed, persistence is in-memory, TEE/attestation is stubbed.

---

## Known Open Issues Carried Forward

| ID | Item | Status |
|---|---|---|
| DR-KEE-02 | P1 numbering conflict in draft front matter (§1.1, §3.3, §5.1, §9.7 still stale) | Resolved for sample-code purposes (Option A, this document); draft text sweep still pending -02 |
| OQ-KEE-07 | Hard real-time scheduling for FIEA-governed deployments — would be new P9 or L4 if required | Open, KEE-2 scope |
| OQ-KEE-08 | KEE-1/KEE-2 scale threshold — candidate 1,000 concurrent sessions | Open, needs benchmark data |
| SDB-GAR-01 | `prev_span_hash` field inclusion/order for GAR — resolve before Step 1a log generation | Open — check GAR §4 |
| Minor erratum | §9.1's Base Platform table tags clock sync as "Satisfies P3 Check 1, P5 (clock)" — the "P5" reference is itself a stray Generation-1/2 fragment (old P7=Clock Authority); under this document's canonical model clock sync only relates to P3 Check 1 | Noted, not blocking — fold into -02 sweep |

---

*KERNEL_PROPERTIES.md*
*MyAuberge K.K. / SOOS Project*
*Generated: July 4, 2026, Step 0.5 of Sample Code Plan v4*
*Canonical basis: draft-sato-soos-kee-01 §4, reconciled per DR-KEE-02 Option A*
*Next: Step 1a — GAR SVL Phase A (resolve SDB-GAR-01 first, per plan)*
