# MJWT — Mandate JWT

TypeScript sample implementation of the Mandate JWT (MJWT), the SOOS authorization
primitive that binds an AI agent's authority to a specific Sovereign Object instance
under a named human principal.

Draft: [draft-sato-soos-mjwt-02](https://datatracker.ietf.org/doc/draft-sato-soos-mjwt-02/)

## Install

```
npm install jose uuid
```

## What the demo shows

`demo.ts` issues a Root Mandate from a human principal to a booking agent, verifies it
through the GEC's full 13-step verification protocol (§8.1), then issues a narrowed
Child Mandate to a sub-agent and verifies the Narrowing Property across all seven
dimensions (§5.2) plus consent-scope validation (§8.1 Step 13, [NEW in -02]). It then
runs three denial scenarios: an attempted authority-expanding Child Mandate rejected at
issuance, a forged `alg:none` token rejected at Step 2 before signature verification is
ever attempted, and a Transition Request denied for missing `consent_scope`. Scenario
data is drawn from `svl/corpus-b/mjwt/happy-path.json` (20 logs) and `edge-cases.json`
(21 logs, one covering every deny code in §8.2).

```
tsx tier1/mjwt/demo.ts
```

## Core snippet

```typescript
/**
 * Verifies an MJWT against the GEC's 13-step protocol.
 *
 * Ordering is normative (§8.1: "MUST perform the following verification
 * steps in order... Failure at any step MUST result in an immediate DENY").
 * This function short-circuits on the first failing step.
 */
export async function verifyMandate(
  token: string,
  issuerPublicKey: CryptoKey,
  ctx: GECVerificationContext,
  parent?: MJWTClaims,
): Promise<VerificationResult> {
  const { payload: unverifiedClaims, protectedHeader } = decodeUnverified(token);

  // Step 1 — Audience binding. MUST precede signature verification.
  if (unverifiedClaims.aud !== ctx.gec_instance_id) {
    return fail(1, MJWTDenyCode.MJWT_AUD_MISMATCH, 'aud mismatch');
  }

  // Step 2 — Algorithm verification [NEW in -02]. MUST precede Step 3.
  if (protectedHeader.alg !== 'EdDSA') {
    return fail(2, MJWTDenyCode.MJWT_ALG_INVALID, `alg ${protectedHeader.alg} rejected`);
  }
  // ...steps 3-13 continue in order, short-circuiting on first failure
}
```

## Note on `delegation_chain`

MJWT's `delegation_chain` claim is adopted without modification from the McGuinness
Actor Profile [I-D.mcguinness-oauth-actor-profile] (§3.5) — it is not the same claim as
[I-D.liu-oauth-chain-delegation]'s claim of the same name. See
`MJWT-02_RelatedWork_Draft.md` §X.1 for the disambiguation; MJWT does not rename this
claim.
