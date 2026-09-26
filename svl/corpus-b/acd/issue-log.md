# ACD — Issue Log

Built against `draft-sato-soos-acd-01`.

## Build scope

Full ACD Record schema (§6, all three layers + the `mjwt_jti` binding
addition from §9.1), the Presentation Protocol handshake (§7.2) with
the four-check sequence (§7.4) gating record issuance, resource-
provider-side validation (§7.3, all 6 steps), and now the **Trust
Hierarchy (§8)** — trust level derivation (§8.1), Audit Principal access
(§8.2, ALE-061), and Verified External Auditor access (§8.3).

## Trust Hierarchy build notes

**Trust level derivation (§8.1) is resource-provider-side**, same actor
as `validateAsResourceProvider()` — §8.1's own text is explicit that
trust level "is not carried as an explicit field in the ACD Record";
providers derive it by inspecting the referenced GEC Manifest and
attestation endpoint. `deriveTrustLevel()` implements this as a
highest-to-lowest check (GOVERNMENT → ELEVATED → STANDARD), since §8.1
gives STANDARD as an unconditional default ("the default trust level for
SOOS-governed agent deployments") rather than a set of conditions that
can fail — there's no sub-STANDARD outcome in the draft's text.

**GEC Manifest fields are a named subset, not a full KEE-1 reproduction.**
`GecManifestTrustFields` only carries the fields §8.1's own prose names
(`conformance_level`, `frost_threshold`, TEE-backed attestation,
hardware attestation chain, publisher key scheme, national deployment
profile) — KEE-1 (`draft-sato-soos-kee-00`) owns the actual Manifest
schema and wasn't in this session's dependency set, same posture as
MAD's dependency on DR-PLAN-01's Assignment schema (referenced, not
reproduced).

**Audit Principal / VEA credential issuance is explicitly out of
protocol scope** (§8.2: "issued by the operator via a credential
exchange not specified by this protocol"; §8.3: "issuance and
accreditation procedure is outside the scope of this document"). Both
`authenticateAuditPrincipal()` and `authenticateVea()` take a
caller-supplied `verifyCredential` predicate rather than implementing
issuance/accreditation themselves — there's no spec to build that
against.

**ALE-061 (ACD_HUMAN_QUERY) fires on every access attempt, granted or
denied** — verified explicitly in corpus scenario ACD-EDGE-11 (a denied
Audit Principal request still produces a GAR entry with `granted: false`),
matching §8.2's "The GEC logs every Audit Principal access as ALE-061."

## SVL Phase A question — resolved (Step 15's original question, now with KEE-1 available)

**Question:** "Does ACD-01 cite KEE-1 §4.3 normatively, or restate the
four checks? If it restates them, are there any differences from the
KEE-1 version?"

**Answer: it restates them (ACD-01 §7.4 says so explicitly — "reproduced
here for reference; KEE-1 Section 4.3 is normative"), and the
restatement has three real points of drift, plus a fourth finding that's
an inconsistency within ACD-01 itself, not a mismatch with KEE-1.**

### SDB-ACD-01 (Type II — internal ACD-01 self-inconsistency, resolved by using the fuller definition)

ACD-01 defines ALE-059 (ACD_VALIDATION_FAILED)'s fields **twice**, and
the two definitions disagree:

- **§10 (GAR Integration, the detailed section):** trigger is "GEC
  four-check sequence failed (before record issuance), **or** resource
  provider rejected the ACD Record after issuance." Fields:
  `acd_session_id`, `failed_check` (1-4, GEC-side), `failed_layer`
  (1-3, provider-side), `failed_field`, `resource_provider_id`,
  `failure_timestamp`.
- **§14.2 (IANA Considerations, the actual registration request):**
  trigger is **only** "Resource provider rejected ACD Record" — the
  GEC-side four-check failure trigger is dropped entirely. Fields:
  `acd_session_id`, `failed_layer`, `failed_field`,
  `resource_provider_id` — **no `failed_check` field at all.**

If IANA registers ALE-059 per §14.2's narrower text, the GEC-side
`failed_check` field — which §7.2, §7.4, and §10 all clearly require —
would have no normative home in the actual registry. Resolved by
following §10's fuller definition (both field sets, keyed by which side
triggered the failure), implemented in `four-check-v2.ts`'s
`AcdFourCheckLogger` and `gec-acd.ts`'s `handleQueryV2()`.

### SDB-ACD-02 (Type II — Check 3 drops the FROST threshold-key path)

KEE-1 §4.3 Check 3: "The GEC MUST verify that its **KIA signing key (or
FROST threshold key)** is currently valid and not revoked." ACD-01 §7.4's
restatement: "The GEC's KIA signing key MUST NOT appear in the
Revocation Registry" — **the FROST alternative is gone entirely.**

This isn't cosmetic: ACD-01's own §8.1 Trust Hierarchy **requires** FROST
threshold signing for the ELEVATED trust level ("KEE-1 L2 conformance
with FROST threshold signing... The GEC Manifest declares
`frost:t-of-n:2-3` or higher"). A GEC implementing only ACD-01's literal
§7.4 wording would have no defined way to run Check 3 correctly for the
exact deployments its own §8.1 defines as ELEVATED or GOVERNMENT trust.
Fixed in `four-check-v2.ts`: `runFourCheckSequence()` detects the FROST
marker in the real `GecManifestFields.deployment_constraints` (KIA's
actual field, via `frostConstraintString()`) and checks the correct
revocation flag depending on which signing path the manifest declares.
Corpus scenario ACD-V2-EDGE-01 exercises exactly the case ACD-01's
restatement can't express: a FROST-signed deployment whose threshold key
is revoked.

### SDB-ACD-03 (Type III — Check 2 drops the canonical-serialization requirement)

KEE-1 §4.3 Check 2: the hash "MUST be computed over the **canonical
serialization** of the active Cedar Policy Set **immediately before
signing**." ACD-01 §7.4: "computed as the SHA-256 hash of the Cedar
Policy Set currently active... A precomputed or stale hash MUST NOT be
used" — drops the canonical-serialization requirement specifically,
keeping only the "not stale/precomputed" half. A hash computed over a
non-canonical serialization of the same policy set could technically
satisfy ACD-01's looser wording while violating KEE-1's. Modeled in
`four-check-v2.ts` as an equality check between a caller-supplied
"active" hash and a "claimed" hash — the canonicalization itself has to
happen upstream, in whatever computes `activeCedarPolicyHash`, since
there's no live Cedar engine in this codebase to canonicalize a real
policy set (same simulation limit as Steps 9/11/12's Cedar handling).

### Check 1 and Check 4 — no meaningful drift

Check 1 (Manifest Validity): ACD-01 drops KEE-1's explanatory detail
("current if its issued_at timestamp is within the GEC Manifest
staleness window") but states nothing false — same substantive
requirement, less mechanism explained. Worth a terminology note: KEE-1
says "issued_at," but KIA's real `GecManifestFields` (the schema KEE-1
itself cites) has no field by that name — the actual freshness clock is
`attestation_timestamp` (confirmed by reading KIA's real
`assertManifestFresh()` in `deps/kia/manifest.ts`). Not a drafting error
so much as KEE-1 using a generic descriptive term for a specifically-
named field in a sibling document.

Check 4 (Revocation Status): restated near-verbatim, just inverted from
"GEC MUST verify X has not been revoked" to "X MUST NOT appear... or
have received a CAEP signal" — same requirement, no drift.

### SDB-ACD-04 (Type II — `conformance_level` has no home in KIA's real Manifest schema)

Both ACD-01 §8.1 ("Resource providers determine the trust level by
inspecting the `conformance_level` in the referenced GEC Manifest") and
KEE-1 §5.1 ("ACD Records from L1 deployments MUST include a
`conformance_level` field value of `KEE1-L1`... in the GEC Manifest
referenced by `gec_manifest_ref`") assume `conformance_level` is a field
in the GEC Manifest. It is not — checked against the actual
`GecManifestFields` interface in the real KIA module (`deps/kia/types.ts`,
copied from the KIA zip): `kernel_keypair_fingerprint`,
`operator_identity`, `deployment_timestamp`, `hardware_backed`,
`ptd_endpoint`, `ptd_current_version`, `kernel_version`,
`loaded_policy_ids`, `cedar_policy_hash`, `attestation_timestamp`,
`deployment_constraints`, `xpid_derivation_version`,
`kernel_version_date`, `kernel_implementer_id` — no `conformance_level`
anywhere. Both citing drafts assume a field that the actual schema
owner (KIA) hasn't defined, at least not in the version available this
session. `GecManifestTrustFields.conformance_level` in `types.ts` is
therefore still a caller-supplied/inferred field, not backed by real
KIA code the way `deployment_constraints` (FROST detection) and
`attestation_timestamp` (staleness) now are in `four-check-v2.ts`. Worth
surfacing to whoever maintains KIA next — this looks like a field KIA's
Manifest schema needs to actually add, not an ACD/KEE drafting error.

### What changed in this module

Added `four-check-v2.ts` and `AcdGec.handleQueryV2()`, built directly
against KEE-1 §4.3 using KIA's **real** `GecManifest`/
`assertManifestFresh()`/`assertManifestSignatureValid()` (copied from
the KIA zip, `deps/kia/manifest.ts` + `types.ts`) instead of the boolean-
flag `FourCheckInputs` the original `handleQuery()` used. The original
`handleQuery()` is kept, documented as the pre-KEE-1 simplified version,
since existing demo/corpus scenarios built against it are still valid —
they just don't exercise the FROST path or real manifest mechanics.
Corpus grew from 19 to 26 scenarios (7 new, all V2-specific).

## Not built (flagged, not blocking)

- Sub-agent MJWT chain-tracing beyond the single `mjwt_jti` field (§9.3)
  — full delegation-chain-depth verification against KIA's actual
  revocation registry per hop.
- A live `/.well-known/soos-acd` HTTPS endpoint — this module is the
  GEC-side handshake logic a real endpoint would call into, same
  simulation posture as every other Tier 1/2 module in this codebase.
