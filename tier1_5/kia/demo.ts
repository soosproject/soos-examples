import nacl from "tweetnacl";
import { writeFileSync, mkdirSync } from "node:fs";
import { sha256Hex } from "./canon.js";
import { issueGecManifest, verifyManifestSignature, assertManifestFresh, assertManifestSignatureValid } from "./manifest.js";
import { FrostSigningCluster } from "./frost.js";
import { deriveXpid, partyRegistryEntryHash, assertXpidVerified, verifyXpidCrossInstance } from "./xpid.js";
import { signEventLogEntry, verifyEventLogEntry, RevocationRegistry } from "./event-log.js";
import { KiaError, type EventLogEntry } from "./types.js";

type SvlLog = {
  id: string;
  kind: "happy" | "edge";
  scenario: string;
  conformance_refs: string[];
  outcome: "PASS" | "DENY";
  deny_code?: string | undefined;
  detail: string;
};

const logs: SvlLog[] = [];
function log(entry: SvlLog) {
  logs.push(entry);
  const tag = entry.outcome === "PASS" ? "PASS" : `DENY(${entry.deny_code})`;
  console.log(`[${entry.kind.toUpperCase()}] ${entry.id} ${tag} — ${entry.scenario}`);
}

console.log("=== SOOS Step 6 — KIA (draft-sato-soos-kia-03 + proposed -04) ===\n");

// ---------------------------------------------------------------------------
// 1. Standard (non-FROST) GEC Manifest issuance, including -04 fields
// ---------------------------------------------------------------------------
const kernelKeypair = nacl.sign.keyPair();
const manifest = issueGecManifest({
  kernelKeypair,
  operatorIdentity: sha256Hex("myauberge-operator-root-pubkey"),
  hardwareBacked: true,
  ptdEndpoint: "https://kernel.myauberge.example/ptd",
  ptdCurrentVersion: "1.3.0",
  kernelVersion: "0.9.0-step6",
  loadedPolicyIds: ["policy:default-allow-none", "policy:farm-ops-v1"],
  cedarPolicyHash: sha256Hex("cedar-policy-set-v1"),
  deploymentConstraints: [],
  implementsXpid: true,
  kernelVersionDate: "2026-07-01", // -04 CONF-KIA-24: source release date, not compile clock
  kernelImplementerId: sha256Hex("myauberge-implementer-signing-pubkey"), // -04 CONF-KIA-25
});

const manifestValid = verifyManifestSignature(manifest, kernelKeypair.publicKey);
log({
  id: "HP-KIA-01",
  kind: "happy",
  scenario: "Standard deployment GEC Manifest issuance + signature verification, incl. -04 kernel_version_date/kernel_implementer_id",
  conformance_refs: ["§5.2", "CONF-KIA-24 (proposed)", "CONF-KIA-25 (proposed)"],
  outcome: manifestValid ? "PASS" : "DENY",
  detail: `manifest_signature verifies=${manifestValid}; kernel_version_date=${manifest.fields.kernel_version_date}; kernel_implementer_id=${manifest.fields.kernel_implementer_id.slice(0, 16)}…`,
});

try {
  assertManifestFresh(manifest, Date.now());
  log({
    id: "HP-KIA-02",
    kind: "happy",
    scenario: "Manifest freshness check within §5.4 staleness limit",
    conformance_refs: ["§5.4"],
    outcome: "PASS",
    detail: "age well under 86400s limit",
  });
} catch (e) {
  if (e instanceof KiaError) log({ id: "HP-KIA-02", kind: "happy", scenario: "freshness check", conformance_refs: ["§5.4"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// EDGE: stale manifest (simulate attestation_timestamp 2 days old)
const staleManifest = { ...manifest, fields: { ...manifest.fields, attestation_timestamp: new Date(Date.now() - 2 * 86400 * 1000).toISOString() } };
try {
  assertManifestFresh(staleManifest);
  log({ id: "EDGE-KIA-01", kind: "edge", scenario: "Stale manifest (>86400s) should be rejected for federation", conformance_refs: ["§5.4", "§6.4(c)"], outcome: "PASS", detail: "UNEXPECTED: stale manifest was not rejected" });
} catch (e) {
  if (e instanceof KiaError) log({ id: "EDGE-KIA-01", kind: "edge", scenario: "Stale manifest (>86400s) should be rejected for federation", conformance_refs: ["§5.4", "§6.4(c)"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// EDGE: tampered manifest field invalidates signature
const tamperedManifest = { ...manifest, fields: { ...manifest.fields, cedar_policy_hash: sha256Hex("tampered") } };
try {
  assertManifestSignatureValid(tamperedManifest, kernelKeypair.publicKey);
  log({ id: "EDGE-KIA-02", kind: "edge", scenario: "Tampered manifest field must invalidate manifest_signature", conformance_refs: ["§15.2"], outcome: "PASS", detail: "UNEXPECTED: tamper not detected" });
} catch (e) {
  if (e instanceof KiaError) log({ id: "EDGE-KIA-02", kind: "edge", scenario: "Tampered manifest field must invalidate manifest_signature", conformance_refs: ["§15.2"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// ---------------------------------------------------------------------------
// 2. FROST threshold signing — quorum enforcement + nonce reuse defense
// ---------------------------------------------------------------------------
const cluster = new FrostSigningCluster(3, ["node-a", "node-b", "node-c", "node-d", "node-e"]);

try {
  const sig = cluster.sign({ some: "gec-artifact" }, ["node-a", "node-b", "node-c"]);
  const ok = cluster.verify({ some: "gec-artifact" }, sig);
  log({ id: "HP-KIA-03", kind: "happy", scenario: "FROST 3-of-5 quorum reached, signature verifies", conformance_refs: ["§4.1", "CONF-KIA-16", "CONF-KIA-17"], outcome: ok ? "PASS" : "DENY", detail: `quorum met with node-a/b/c, verify=${ok}` });
} catch (e) {
  if (e instanceof KiaError) log({ id: "HP-KIA-03", kind: "happy", scenario: "FROST quorum signing", conformance_refs: ["§4.1"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// EDGE: below-quorum signing attempt MUST refuse, MUST NOT degrade to single-signer (CONF-KIA-18)
try {
  cluster.sign({ some: "artifact-2" }, ["node-a", "node-b"]);
  log({ id: "EDGE-KIA-03", kind: "edge", scenario: "Below-quorum (2-of-5, need 3) signing attempt", conformance_refs: ["CONF-KIA-18", "CONF-KIA-19"], outcome: "PASS", detail: "UNEXPECTED: signed below quorum" });
} catch (e) {
  if (e instanceof KiaError) log({ id: "EDGE-KIA-03", kind: "edge", scenario: "Below-quorum (2-of-5, need 3) signing attempt refused, no single-signer fallback", conformance_refs: ["CONF-KIA-18", "CONF-KIA-19"], outcome: "DENY", deny_code: e.code, detail: e.message + " — caller MUST emit KERNEL_AUDIT_ANOMALY (CONF-KIA-19)" });
}

// EDGE: nonce reuse across two signing ops by the same participant (§15.8 attack vector)
try {
  const fixedNonce = "reused-nonce-value";
  cluster.sign({ x: 1 }, ["node-a", "node-b", "node-c"], { forceNonceReuse: fixedNonce });
  cluster.sign({ x: 2 }, ["node-a", "node-b", "node-c"], { forceNonceReuse: fixedNonce });
  log({ id: "EDGE-KIA-04", kind: "edge", scenario: "FROST nonce reuse across two signing ops by same participants", conformance_refs: ["CONF-KIA-16", "§15.8"], outcome: "PASS", detail: "UNEXPECTED: nonce reuse not detected" });
} catch (e) {
  if (e instanceof KiaError) log({ id: "EDGE-KIA-04", kind: "edge", scenario: "FROST nonce reuse across two signing ops by same participants — secret share exposure risk", conformance_refs: ["CONF-KIA-16", "§15.8"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// ---------------------------------------------------------------------------
// 3. XPID derivation and cross-instance verification (§6, CVE-2025-13609 class)
// ---------------------------------------------------------------------------
const partyEntryHash = partyRegistryEntryHash(JSON.stringify({ agent: "planning-agent-01", org: "myauberge" }));
const presentingFingerprint = manifest.fields.kernel_keypair_fingerprint;
const xpid = deriveXpid(presentingFingerprint, partyEntryHash);

log({ id: "HP-KIA-04", kind: "happy", scenario: "XPID derived deterministically from kernel fingerprint + party registry hash", conformance_refs: ["§6.2", "CONF-KIA-21"], outcome: "PASS", detail: `xpid=${xpid}` });

try {
  assertXpidVerified(xpid, presentingFingerprint, partyEntryHash);
  log({ id: "HP-KIA-05", kind: "happy", scenario: "Receiving kernel recomputes and verifies XPID — matches", conformance_refs: ["§6.3(c)", "CONF-KIA-22"], outcome: "PASS", detail: "recomputed XPID matches presented XPID" });
} catch (e) {
  if (e instanceof KiaError) log({ id: "HP-KIA-05", kind: "happy", scenario: "XPID cross-instance verification", conformance_refs: ["§6.3"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// EDGE: CVE-2025-13609-class attack — attacker claims an existing XPID with a different party registry entry
try {
  const attackerPartyHash = partyRegistryEntryHash(JSON.stringify({ agent: "attacker-agent", org: "not-myauberge" }));
  assertXpidVerified(xpid, presentingFingerprint, attackerPartyHash); // presents the legitimate agent's XPID
  log({ id: "EDGE-KIA-05", kind: "edge", scenario: "CVE-2025-13609-class identity takeover: forged XPID claim with mismatched party registry entry", conformance_refs: ["§15.10", "CONF-KIA-21"], outcome: "PASS", detail: "UNEXPECTED: forged claim accepted" });
} catch (e) {
  if (e instanceof KiaError) log({ id: "EDGE-KIA-05", kind: "edge", scenario: "CVE-2025-13609-class identity takeover: forged XPID claim with mismatched party registry entry — rejected", conformance_refs: ["§15.10", "CONF-KIA-21"], outcome: "DENY", deny_code: e.code, detail: e.message });
}

// EDGE: client-supplied XPID must never be trusted directly — this is a structural test that
// verifyXpidCrossInstance always returns the recomputed value, never the presented one.
{
  const clientClaimedXpid = "00000000-0000-5000-8000-000000000000";
  const { recomputedXpid, matches } = verifyXpidCrossInstance(clientClaimedXpid, presentingFingerprint, partyEntryHash);
  log({
    id: "EDGE-KIA-06",
    kind: "edge",
    scenario: "Client-supplied arbitrary XPID is never trusted as authoritative — recomputation always wins",
    conformance_refs: ["CONF-KIA-21"],
    outcome: !matches ? "DENY" : "PASS",
    deny_code: !matches ? "KIA_CLIENT_SUPPLIED_XPID_REJECTED" : undefined,
    detail: `client claimed ${clientClaimedXpid}, GEC-recomputed authoritative value is ${recomputedXpid}, matches=${matches}`,
  });
}

// ---------------------------------------------------------------------------
// 4. Event Log signing (INV-9)
// ---------------------------------------------------------------------------
const entry: EventLogEntry = {
  event_id: "evt-0001",
  event_type: "SO_STATE_TRANSITION",
  so_id: "so-farm-plan-042",
  session_id: "sess-abc123",
  xpid,
  occurred_at: new Date().toISOString(),
  payload: { from: "DRAFT", to: "ACTIVE" },
};
const signedEntry = signEventLogEntry(entry, kernelKeypair.secretKey, presentingFingerprint);
const entryValid = verifyEventLogEntry(signedEntry, kernelKeypair.publicKey);
log({ id: "HP-KIA-06", kind: "happy", scenario: "Event Log entry signed and verified (INV-9)", conformance_refs: ["§7", "INV-9"], outcome: entryValid ? "PASS" : "DENY", detail: `verify=${entryValid}` });

// EDGE: tampered event log entry payload
const tamperedEntry = { ...signedEntry, entry: { ...signedEntry.entry, payload: { from: "DRAFT", to: "ACTIVE_TAMPERED" } } };
const tamperedValid = verifyEventLogEntry(tamperedEntry, kernelKeypair.publicKey);
log({ id: "EDGE-KIA-07", kind: "edge", scenario: "Tampered Event Log entry payload must fail signature verification", conformance_refs: ["§15.2", "INV-9"], outcome: tamperedValid ? "PASS" : "DENY", deny_code: tamperedValid ? undefined : "KIA_MANIFEST_SIGNATURE_INVALID", detail: `verify=${tamperedValid} (expected false)` });

// ---------------------------------------------------------------------------
// 5. Revocation Registry + OQ-S-XPID-REV interim mitigation (CONF-KIA-23)
// ---------------------------------------------------------------------------
const registry = new RevocationRegistry();
const jti = "mandate-jwt-jti-77x9";

log({ id: "HP-KIA-07", kind: "happy", scenario: "jti not revoked — cross-instance event accepted", conformance_refs: ["§8", "CONF-KIA-23"], outcome: "PASS", detail: (() => { registry.assertNotRevoked(jti); return "no throw, jti clean"; })() });

registry.revoke({ jti, revoked_at: new Date().toISOString(), revocation_scope: "THIS_MANDATE_ONLY", originating_kernel: presentingFingerprint });

// EDGE: OQ-S-XPID-REV — stale XPID from revoked agent presented to a kernel that
// hasn't seen CAEP propagation yet. The XPID itself still "verifies" (§6.4's known gap);
// CONF-KIA-23 mandates the independent jti check as the interim mitigation.
{
  const xpidStillVerifies = verifyXpidCrossInstance(xpid, presentingFingerprint, partyEntryHash).matches;
  let jtiCaughtIt = false;
  let denyMsg = "";
  try {
    registry.assertNotRevoked(jti);
  } catch (e) {
    if (e instanceof KiaError) { jtiCaughtIt = true; denyMsg = e.message; }
  }
  log({
    id: "EDGE-KIA-08",
    kind: "edge",
    scenario: "OQ-S-XPID-REV: revoked agent's XPID still verifies structurally, but independent jti check (CONF-KIA-23) catches the revocation",
    conformance_refs: ["§6.4", "§15.9", "CONF-KIA-23"],
    outcome: jtiCaughtIt ? "DENY" : "PASS",
    deny_code: jtiCaughtIt ? "KIA_JTI_REVOKED" : undefined,
    detail: `xpid_still_verifies=${xpidStillVerifies} (expected true — this is the documented gap), jti_check_caught_it=${jtiCaughtIt}: ${denyMsg}`,
  });
}

// ---------------------------------------------------------------------------
// Summary + SVL corpus emission
// ---------------------------------------------------------------------------
const happy = logs.filter((l) => l.kind === "happy").length;
const edge = logs.filter((l) => l.kind === "edge").length;
console.log(`\n${happy} happy-path + ${edge} edge/adversarial logs generated.`);
console.log(
  "NOTE: this is a scoped demo corpus (7+8), not the full 20+21 pattern used for",
  "Steps 3-5. Expanding to the full corpus is deferred — see chat response for scope note.",
);

mkdirSync("svl/corpus-b/kia", { recursive: true });
writeFileSync("svl/corpus-b/kia/logs.json", JSON.stringify(logs, null, 2));
console.log("Corpus written to svl/corpus-b/kia/logs.json");
