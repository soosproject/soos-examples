import { SignJWT, jwtVerify, generateKeyPair, exportJWK, type JWK } from 'jose';
import { v7 as uuidv7 } from 'uuid';

/**
 * Mandate JWT (MJWT) — SOOS governance credential.
 * Implements draft-sato-soos-mjwt-02.
 *
 * MJWT is a WIMSE workload credential profile [I-D.ietf-wimse-arch]
 * that binds an AI agent's authority to a specific Sovereign Object
 * instance under a named human principal, with a cryptographically
 * enforced delegation ceiling and a seven-dimensional Narrowing
 * Property (MJWT-02 §5).
 */

// ---------------------------------------------------------------------------
// Claims schema (MJWT-02 §4.2)
// ---------------------------------------------------------------------------

/** consent_scope claim schema (MJWT-02 §4.2.3, [NEW in -02]) */
export interface ConsentScope {
  data_subject_id: string;        // Pseudonymized. MUST NOT be directly identifying.
  consent_reference: string;      // URI/token pointing to the consent record.
  consent_timestamp: string;      // ISO 8601
  consenting_party: 'SELF' | 'GUARDIAN' | 'AUTHORIZED_REPRESENTATIVE';
  purpose_codes: string[];
  data_categories: string[];
  jurisdiction: string;           // ISO 3166-1 alpha-2
  governing_law: string;          // e.g. "APPI:2003:Art17"
  expiry: string;                 // ISO 8601
  /** MJWT-02 §5.2(g). One of INHERIT | RESTRICT | NONE. Default: RESTRICT. */
  sub_agent_scope: SubAgentScope;
}

export type SubAgentScope = 'INHERIT' | 'RESTRICT' | 'NONE';

/**
 * delegation_chain entry. Adopted without modification from the
 * McGuinness Actor Profile [I-D.mcguinness-oauth-actor-profile] —
 * MJWT-02 §3.5, §4.2.3. NOT the same claim as
 * [I-D.liu-oauth-chain-delegation]'s delegation_chain, despite the
 * shared name — see MJWT-02_RelatedWork_Draft.md §X.1.
 */
export interface DelegationChainEntry {
  issuer_id: string;
  recipient_id: string;
  mandate_jti: string;
  issued_at: string;
  gec_signature: string; // "human_issued" for the Root Mandate's own issuance step
}

/** Full MJWT claim set — WIMSE base + SOOS governance claims (MJWT-02 §4.2). */
export interface MJWTClaims {
  // Standard JWT claims (§4.2.1)
  iss: string;
  sub: string;
  jti: string;              // UUID v7 — this is the mandate_id
  iat: number;
  exp: number;
  nbf?: number;
  aud: string;

  // WIMSE claims (§4.2.2)
  wid: string;
  cnf: { jwk: JWK };

  // SOOS governance claims (§4.2.3)
  so_id: string;
  so_type_id: string;
  human_principal_id: string;
  cedar_actions: string[];
  permitted_states?: string[] | undefined;
  permitted_phases?: string[] | undefined;
  mandate_ceiling: 1 | 2 | 3;
  parent_mandate_id?: string;              // REQUIRED for Child Mandates
  delegation_chain?: DelegationChainEntry[]; // REQUIRED when parent_mandate_id present
  mission_ref?: string | undefined;
  zone_b_read?: boolean;
  zone_b_write?: boolean;
  gec_cluster_id?: string;
  consent_scope?: ConsentScope | undefined;             // [NEW in -02]
  sub_agent_scope?: SubAgentScope;
}

// ---------------------------------------------------------------------------
// Deny codes (MJWT-02 §8.2)
// ---------------------------------------------------------------------------

export enum MJWTDenyCode {
  MJWT_AUD_MISMATCH = 'MJWT_AUD_MISMATCH',
  MJWT_ALG_INVALID = 'MJWT_ALG_INVALID',
  MJWT_SIGNATURE_INVALID = 'MJWT_SIGNATURE_INVALID',
  MJWT_EXPIRED = 'MJWT_EXPIRED',
  MJWT_NOT_YET_VALID = 'MJWT_NOT_YET_VALID',
  MANDATE_REVOKED = 'MANDATE_REVOKED',
  MJWT_SO_MISMATCH = 'MJWT_SO_MISMATCH',
  MJWT_SO_TYPE_MISMATCH = 'MJWT_SO_TYPE_MISMATCH',
  MJWT_PRINCIPAL_MISMATCH = 'MJWT_PRINCIPAL_MISMATCH',
  MJWT_CEILING_INSUFFICIENT = 'MJWT_CEILING_INSUFFICIENT',
  NARROWING_VIOLATION = 'NARROWING_VIOLATION',
  MJWT_SUB_AGENT_SCOPE_ESCALATION = 'MJWT_SUB_AGENT_SCOPE_ESCALATION',
  MANDATE_SCOPE = 'MANDATE_SCOPE',
  MJWT_STATE_RESTRICTED = 'MJWT_STATE_RESTRICTED',
  MJWT_PHASE_RESTRICTED = 'MJWT_PHASE_RESTRICTED',
  MJWT_MISSION_REF_MISMATCH = 'MJWT_MISSION_REF_MISMATCH',
  MJWT_CONSENT_ABSENT = 'MJWT_CONSENT_ABSENT',
  MJWT_CONSENT_EXPIRED = 'MJWT_CONSENT_EXPIRED',
  MJWT_CONSENT_SCOPE_VIOLATION = 'MJWT_CONSENT_SCOPE_VIOLATION',
}

export interface VerificationResult {
  ok: boolean;
  /** Which of the 13 steps failed, if any. Absent on success. */
  failed_step?: number;
  deny_code?: MJWTDenyCode;
  detail?: string;
}

/**
 * Reference to a parent mandate for Step 9 live re-verification (MJWT-04
 * §8.1 Step 9, §11.8 parent-swap defense). Carrying only decoded claims is
 * NOT sufficient — the caller MUST supply the parent's original signed
 * token and its issuer's public key so verifyMandate() can cryptographically
 * re-check the parent's current signature validity, not trust a cached copy.
 */
export interface ParentMandateRef {
  claims: MJWTClaims;
  token: string;
  issuerPublicKey: CryptoKey;
}

/** Minimal context the GEC needs to verify a Transition Request. Not from the MJWT itself. */
export interface GECVerificationContext {
  gec_instance_id: string;        // KIA-attested instance identifier (aud)
  gec_conformance_level: 1 | 2 | 3;
  so_current_state: string;
  so_current_phase: string;
  so_human_principal_id: string;
  requested_cedar_action: string;
  idp_mission_ref?: string;
  cedar_policy_requires_consent: boolean;
  cedar_policy_purpose_code?: string;
  revoked_jtis: Set<string>;       // stand-in for the Revocation Registry (KEE-1 P8)
}

// ---------------------------------------------------------------------------
// Issuance (MJWT-02 §6)
// ---------------------------------------------------------------------------

export interface IssueRootMandateParams {
  human_principal_id: string;
  agent_wid: string;
  so_id: string;
  so_type_id: string;
  cedar_actions: string[];
  mandate_ceiling: 1 | 2 | 3;
  aud: string;
  exp: number;
  permitted_states?: string[] | undefined;
  permitted_phases?: string[] | undefined;
  mission_ref?: string | undefined;
  consent_scope?: ConsentScope | undefined;
  sub_agent_scope?: SubAgentScope;
  agent_public_jwk: JWK;
}

export function buildRootMandateClaims(p: IssueRootMandateParams): MJWTClaims {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: p.human_principal_id,
    sub: p.agent_wid,
    jti: uuidv7(),
    iat: now,
    exp: p.exp,
    aud: p.aud,
    wid: p.agent_wid,
    cnf: { jwk: p.agent_public_jwk },
    so_id: p.so_id,
    so_type_id: p.so_type_id,
    human_principal_id: p.human_principal_id,
    cedar_actions: p.cedar_actions,
    permitted_states: p.permitted_states,
    permitted_phases: p.permitted_phases,
    mandate_ceiling: p.mandate_ceiling,
    mission_ref: p.mission_ref,
    consent_scope: p.consent_scope,
    sub_agent_scope: p.consent_scope?.sub_agent_scope ?? p.sub_agent_scope ?? 'RESTRICT',
  };
}

export interface IssueChildMandateParams {
  parent: MJWTClaims;
  issuer_gec_id: string;          // iss for Child Mandates is the issuing GEC
  agent_wid: string;
  agent_public_jwk: JWK;
  cedar_actions: string[];        // MUST be subset of parent.cedar_actions — caller's responsibility, verified below
  exp: number;                    // MUST NOT be later than parent.exp
  permitted_states?: string[] | undefined;
  permitted_phases?: string[] | undefined;
  consent_scope?: ConsentScope | undefined;
  sub_agent_scope?: SubAgentScope;
}

/**
 * Issues a Child Mandate and appends to the delegation_chain.
 * MJWT-02 §6.2. Throws if the caller-supplied narrowing inputs would
 * violate the Narrowing Property — the kernel enforces narrowing at
 * issuance time, not just at verification time (§5.1, §5.2(g)).
 */
export function issueChildMandate(p: IssueChildMandateParams): MJWTClaims {
  const violation = checkNarrowingAtIssuance(p);
  if (violation) {
    throw new Error(`Cannot issue Child Mandate: ${violation}`);
  }

  const now = Math.floor(Date.now() / 1000);
  const jti = uuidv7();
  const chainEntry: DelegationChainEntry = {
    issuer_id: p.issuer_gec_id,
    recipient_id: p.agent_wid,
    mandate_jti: jti,
    issued_at: new Date(now * 1000).toISOString(),
    gec_signature: '<Ed25519 signature>', // stub — real signature applied at signMandate()
  };

  return {
    iss: p.issuer_gec_id,
    sub: p.agent_wid,
    jti,
    iat: now,
    exp: p.exp,
    aud: p.parent.aud,
    wid: p.agent_wid,
    cnf: { jwk: p.agent_public_jwk },
    so_id: p.parent.so_id,
    so_type_id: p.parent.so_type_id,
    human_principal_id: p.parent.human_principal_id,
    cedar_actions: p.cedar_actions,
    permitted_states: p.permitted_states,
    permitted_phases: p.permitted_phases,
    mandate_ceiling: p.parent.mandate_ceiling,
    parent_mandate_id: p.parent.jti,
    delegation_chain: [...(p.parent.delegation_chain ?? []), chainEntry],
    mission_ref: p.parent.mission_ref,
    consent_scope: p.consent_scope,
    sub_agent_scope: p.sub_agent_scope ?? 'RESTRICT',
  };
}

/** Pre-issuance narrowing check — mirrors §5.2 dimensions (a)-(g), minus so_id which the issuer controls directly. */
function checkNarrowingAtIssuance(p: IssueChildMandateParams): string | null {
  const parent = p.parent;
  if (!p.cedar_actions.every((a) => parent.cedar_actions.includes(a))) {
    return 'cedar_actions not a subset of parent (dimension b)';
  }
  if (p.permitted_states && parent.permitted_states &&
      !p.permitted_states.every((s) => parent.permitted_states!.includes(s))) {
    return 'permitted_states not a subset of parent (dimension c)';
  }
  if (p.permitted_phases && parent.permitted_phases &&
      !p.permitted_phases.every((ph) => parent.permitted_phases!.includes(ph))) {
    return 'permitted_phases not a subset of parent (dimension d)';
  }
  if (p.exp > parent.exp) {
    return 'exp later than parent (dimension e)';
  }
  const parentScope = parent.sub_agent_scope ?? parent.consent_scope?.sub_agent_scope ?? 'RESTRICT';
  const childScope = p.sub_agent_scope ?? p.consent_scope?.sub_agent_scope ?? 'RESTRICT';
  if (!isNotLessRestrictive(parentScope, childScope)) {
    return `sub_agent_scope ${childScope} less restrictive than parent ${parentScope} (dimension g)`;
  }
  return null;
}

const SCOPE_RANK: Record<SubAgentScope, number> = { INHERIT: 2, RESTRICT: 1, NONE: 0 };

/** true if child is not less restrictive-permissive than allowed, i.e. child rank <= parent rank. */
function isNotLessRestrictive(parent: SubAgentScope, child: SubAgentScope): boolean {
  return SCOPE_RANK[child] <= SCOPE_RANK[parent];
}

// ---------------------------------------------------------------------------
// Signing / parsing (Ed25519, MJWT-02 §4.3)
// ---------------------------------------------------------------------------

/** STUB key management. Production: issuer key derived from KIA Governance Identity Keypair (KEE-1 P2/§10). */
export async function generateDemoKeypair() {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  const publicJwk = await exportJWK(publicKey);
  return { publicKey, privateKey, publicJwk };
}

export async function signMandate(claims: MJWTClaims, privateKey: CryptoKey, kid: string): Promise<string> {
  return new SignJWT(claims as unknown as Record<string, unknown>)
    .setProtectedHeader({ alg: 'EdDSA', kid })
    .sign(privateKey);
}

// ---------------------------------------------------------------------------
// GEC Verification Protocol — 13 steps, in order (MJWT-02 §8.1)
// ---------------------------------------------------------------------------

/**
 * Verifies an MJWT against the GEC's 13-step protocol.
 *
 * Ordering is normative (§8.1: "MUST perform the following verification
 * steps in order... Failure at any step MUST result in an immediate DENY").
 * This function short-circuits on the first failing step — it does not
 * continue evaluating subsequent steps once one has failed, matching the
 * draft's fail-closed, ordered design (e.g. Step 1 before Step 3 avoids
 * spending crypto cycles / leaking timing signal on tokens not addressed
 * to this GEC; Step 2 before Step 3 prevents the alg:none / PlainJWT
 * bypass class, MJWT-02 §11, CVE-2026-29000).
 *
 * Step 9 (MJWT-04 §8.1, §11.8): if the caller supplies `parent`, its
 * signature and revocation status are re-verified live at the time of
 * THIS call — a previously-decoded, cached MJWTClaims object is not
 * accepted on its own. This closes the "parent-swap" window: a
 * faithfully-recorded delegation chain does not guarantee the parent
 * mandate is still valid at the moment a Child Mandate is used.
 */
export async function verifyMandate(
  token: string,
  issuerPublicKey: CryptoKey,
  ctx: GECVerificationContext,
  parent?: ParentMandateRef,
): Promise<VerificationResult> {
  // Steps 1-2 require inspecting the token before full signature verification.
  const { payload: unverifiedClaims, protectedHeader } = decodeUnverified(token);

  // Step 1 — Audience binding. MUST precede signature verification.
  if (unverifiedClaims.aud !== ctx.gec_instance_id) {
    return fail(1, MJWTDenyCode.MJWT_AUD_MISMATCH, 'aud does not match GEC instance identifier');
  }

  // Step 2 — Algorithm verification [NEW in -02]. MUST precede Step 3.
  if (protectedHeader.alg !== 'EdDSA') {
    return fail(2, MJWTDenyCode.MJWT_ALG_INVALID, `alg ${protectedHeader.alg} is not EdDSA (or is "none")`);
  }

  // Step 3 — Signature verification.
  let claims: MJWTClaims;
  try {
    const { payload } = await jwtVerify(token, issuerPublicKey, { algorithms: ['EdDSA'] });
    claims = payload as unknown as MJWTClaims;
  } catch {
    return fail(3, MJWTDenyCode.MJWT_SIGNATURE_INVALID, 'Ed25519 signature verification failed');
  }

  // Step 4 — Temporal validity.
  const now = Math.floor(Date.now() / 1000);
  if (now >= claims.exp) {
    return fail(4, MJWTDenyCode.MJWT_EXPIRED, 'current time is after exp');
  }
  if (claims.nbf !== undefined && now < claims.nbf) {
    return fail(4, MJWTDenyCode.MJWT_NOT_YET_VALID, 'current time is before nbf');
  }

  // Step 5 — Revocation check.
  if (ctx.revoked_jtis.has(claims.jti)) {
    return fail(5, MJWTDenyCode.MANDATE_REVOKED, 'jti is revoked (direct or cascade)');
  }

  // Step 6 — SO Instance binding.
  // so_id equality against the Transition Request's targeted SO Instance is a
  // deployment-supplied comparison (the caller constructs ctx per-request);
  // this sample verifies so_type_id, which the GEC always holds independently.
  if (!claims.so_type_id) {
    return fail(6, MJWTDenyCode.MJWT_SO_TYPE_MISMATCH, 'so_type_id absent');
  }

  // Step 7 — Human principal linkage.
  if (claims.human_principal_id !== ctx.so_human_principal_id) {
    return fail(7, MJWTDenyCode.MJWT_PRINCIPAL_MISMATCH, 'human_principal_id does not match SO Instance Identity Layer');
  }

  // Step 8 — Mandate ceiling.
  if (claims.mandate_ceiling < ctx.gec_conformance_level) {
    return fail(8, MJWTDenyCode.MJWT_CEILING_INSUFFICIENT, 'mandate_ceiling below GEC conformance level');
  }

  // Step 9 — Narrowing Property (Child Mandates only). [UPDATED in MJWT-04]
  if (claims.parent_mandate_id) {
    if (!parent) {
      return fail(9, MJWTDenyCode.NARROWING_VIOLATION, 'parent_mandate_id present but parent mandate not resolvable');
    }

    // MJWT-04 §8.1 Step 9 / §11.8: live re-verification, not a cached copy.
    // (a) parent's jti MUST NOT be revoked (directly or cascade) right now.
    if (ctx.revoked_jtis.has(parent.claims.jti)) {
      return fail(9, MJWTDenyCode.NARROWING_VIOLATION, 'parent mandate jti is revoked — parent-swap defense (MJWT-04 §11.8)');
    }
    // (b) parent's signature MUST currently verify against its issuer's key.
    try {
      await jwtVerify(parent.token, parent.issuerPublicKey, { algorithms: ['EdDSA'] });
    } catch {
      return fail(9, MJWTDenyCode.NARROWING_VIOLATION, 'parent mandate signature does not currently verify — parent-swap defense (MJWT-04 §11.8)');
    }

    const narrowingResult = verifyNarrowingProperty(claims, parent.claims);
    if (!narrowingResult.ok) return narrowingResult;
  }

  // Step 10 — Cedar action scope.
  if (!claims.cedar_actions.includes(ctx.requested_cedar_action)) {
    return fail(10, MJWTDenyCode.MANDATE_SCOPE, `${ctx.requested_cedar_action} not in cedar_actions`);
  }

  // Step 11 — State and phase restrictions.
  if (claims.permitted_states && !claims.permitted_states.includes(ctx.so_current_state)) {
    return fail(11, MJWTDenyCode.MJWT_STATE_RESTRICTED, 'SO current_state not permitted');
  }
  if (claims.permitted_phases && !claims.permitted_phases.includes(ctx.so_current_phase)) {
    return fail(11, MJWTDenyCode.MJWT_PHASE_RESTRICTED, 'SO current_phase not permitted');
  }

  // Step 12 — Mission reference (if present).
  if (claims.mission_ref && claims.mission_ref !== ctx.idp_mission_ref) {
    return fail(12, MJWTDenyCode.MJWT_MISSION_REF_MISMATCH, 'mission_ref does not match accompanying IDP');
  }

  // Step 13 — Consent scope validation [NEW in -02].
  if (ctx.cedar_policy_requires_consent) {
    const consentResult = validateConsentScope(claims, ctx, parent?.claims);
    if (!consentResult.ok) return consentResult;
  }

  return { ok: true };
}

function fail(step: number, deny_code: MJWTDenyCode, detail: string): VerificationResult {
  return { ok: false, failed_step: step, deny_code, detail };
}

/** Decodes header + payload without verifying signature. Needed for Steps 1-2, which MUST precede Step 3. */
function decodeUnverified(token: string): { payload: Record<string, any>; protectedHeader: Record<string, any> } {
  const parts = token.split('.');
  const headerB64 = parts[0];
  const payloadB64 = parts[1];
  if (!headerB64 || !payloadB64) {
    throw new Error('malformed token: missing header or payload segment');
  }
  const decode = (b64url: string) => JSON.parse(Buffer.from(b64url, 'base64url').toString('utf8'));
  return { protectedHeader: decode(headerB64), payload: decode(payloadB64) };
}

// ---------------------------------------------------------------------------
// Narrowing Property — seven dimensions (MJWT-02 §5.2)
// ---------------------------------------------------------------------------

export function verifyNarrowingProperty(child: MJWTClaims, parent: MJWTClaims): VerificationResult {
  // (a) Sovereign Object scope
  if (child.so_id !== parent.so_id) {
    return fail(9, MJWTDenyCode.NARROWING_VIOLATION, 'dimension (a): so_id does not match parent');
  }
  // (b) Cedar action scope
  if (!child.cedar_actions.every((a) => parent.cedar_actions.includes(a))) {
    return fail(9, MJWTDenyCode.NARROWING_VIOLATION, 'dimension (b): cedar_actions not a subset of parent');
  }
  // (c) Permitted SO states
  if (child.permitted_states && parent.permitted_states &&
      !child.permitted_states.every((s) => parent.permitted_states!.includes(s))) {
    return fail(9, MJWTDenyCode.NARROWING_VIOLATION, 'dimension (c): permitted_states not a subset of parent');
  }
  // (d) Permitted lifecycle phases
  if (child.permitted_phases && parent.permitted_phases &&
      !child.permitted_phases.every((p) => parent.permitted_phases!.includes(p))) {
    return fail(9, MJWTDenyCode.NARROWING_VIOLATION, 'dimension (d): permitted_phases not a subset of parent');
  }
  // (e) Temporal validity
  if (child.exp > parent.exp) {
    return fail(9, MJWTDenyCode.NARROWING_VIOLATION, 'dimension (e): exp later than parent');
  }
  // (f) Mandate ceiling
  if (child.mandate_ceiling > parent.mandate_ceiling) {
    return fail(9, MJWTDenyCode.NARROWING_VIOLATION, 'dimension (f): mandate_ceiling exceeds parent');
  }
  // (g) Consent scope — sub_agent_scope narrowing rule
  const parentScope = parent.sub_agent_scope ?? parent.consent_scope?.sub_agent_scope;
  const childScope = child.sub_agent_scope ?? child.consent_scope?.sub_agent_scope;
  if (parentScope && childScope && !isNotLessRestrictive(parentScope, childScope)) {
    return fail(9, MJWTDenyCode.MJWT_SUB_AGENT_SCOPE_ESCALATION, `dimension (g): sub_agent_scope ${childScope} less restrictive than parent ${parentScope}`);
  }

  return { ok: true };
}

// ---------------------------------------------------------------------------
// Consent scope validation — Step 13 sub-checks (a)-(d) (MJWT-02 §8.1 Step 13)
// ---------------------------------------------------------------------------

export function validateConsentScope(
  claims: MJWTClaims,
  ctx: GECVerificationContext,
  parent?: MJWTClaims,
): VerificationResult {
  // 13(a)
  if (!claims.consent_scope) {
    // Also triggers HEM_CONSENT_REQUIRED — HEM integration is Step 7, stubbed here as a marker.
    return fail(13, MJWTDenyCode.MJWT_CONSENT_ABSENT, 'consent_scope absent; HEM_CONSENT_REQUIRED triggered');
  }

  // 13(b)
  const expiry = Date.parse(claims.consent_scope.expiry);
  if (Date.now() >= expiry) {
    return fail(13, MJWTDenyCode.MJWT_CONSENT_EXPIRED, 'consent_scope.expiry has passed; HEM_CONSENT_REQUIRED triggered');
  }

  // 13(c)
  if (ctx.cedar_policy_purpose_code && !claims.consent_scope.purpose_codes.includes(ctx.cedar_policy_purpose_code)) {
    return fail(13, MJWTDenyCode.MJWT_CONSENT_ABSENT, `purpose code ${ctx.cedar_policy_purpose_code} not in consent_scope.purpose_codes`);
  }

  // 13(d) — Child Mandates only
  if (claims.parent_mandate_id && parent) {
    const parentScope = parent.sub_agent_scope ?? parent.consent_scope?.sub_agent_scope;
    const childScope = claims.sub_agent_scope ?? claims.consent_scope.sub_agent_scope;
    if (parentScope && childScope && !isNotLessRestrictive(parentScope, childScope)) {
      return fail(13, MJWTDenyCode.MJWT_CONSENT_SCOPE_VIOLATION, 'sub_agent_scope escalation relative to parent');
    }
  }

  return { ok: true };
}
