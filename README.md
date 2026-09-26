# SOOS Reference Implementation — Early Release (GAR · MJWT · KIA · CAP)

This is a scoped, early release of four modules from the SOOS (Sovereign Object OS) reference implementation — the governance kernel specification for agentic AI, published as a 19-draft IETF Internet-Draft suite.

**This is not the complete SOOS reference implementation.** The full suite (all 19 drafts, plus an application-layer middleware demonstration built on a manufacturing reference scenario) is still under active development. This release covers exactly the four modules needed to demonstrate delegation, mandate narrowing, and operator-level policy enforcement — the subject of ongoing IETF discussion in WIMSE and RATS — ahead of the complete set.

---

## What's included

| Module | IETF Draft | Tier | Status |
|---|---|---|---|
| GAR (Governance Audit Record) | `draft-sato-soos-gar-03` | 1 — standalone | Core complete. AAS/SCITT interoperability adapter **not** included — see below. |
| MJWT (Mandate JWT) | `draft-sato-soos-mjwt-02` | 1 — standalone | Complete |
| KIA (Kernel Identity & Attestation) | `draft-sato-soos-kia-03` | 1.5 — near-standalone | Complete. Built against an unmerged `-04` proposal text — see note below. |
| CAP (Constitutional Action Policy) | `draft-sato-soos-cap-04` | 2 — interdependent | Complete |

GAR is included because MJWT and CAP both write to it as their audit trail — it's a genuine runtime dependency for the demos in this repo to make sense, not an incidental extra.

---

## What's deliberately not in this release

**GAR's SCITT / Agent Accountability Stack (AAS) adapter is not included.** GAR is one of four legs of a separate, cross-project composable standard (`draft-mih-sato-agent-accountability-composition`) with co-authors on the WHO and WHAT legs. The interoperability adapter — SCITT Signed Statement serialization, the `HEM_APPROVE` ALE profile fields — was explicitly committed for delivery **after** Vienna in an on-record exchange on the SCITT mailing list. This release matches that commitment exactly: GAR's core (append-only log, hash chain, causal ordering, Session Block) is running; the SCITT/AAS-facing adapter is not, by design, not by omission.

**Everything else in the 19-draft suite** — SOV, PT, IDP, HEM, FAIP, CAP-RRS, MAD, AEP, PEER, RGP, ACD, GRP, DAM, AOP, the distributed runtime, and the Tier 5 application middleware — is still being built and is not part of this release. It will be published as a complete set separately.

---

## A note on KIA

The KIA module in this repository is built against an unmerged `-04` proposal, not the currently-published `-03` draft text — a deliberate choice, made to demonstrate GEC Manifest extensions, FROST threshold-signing quorum and nonce-reuse handling, XPID cross-principal derivation, and the Revocation Registry's interim mitigation (`CONF-KIA-23`) end to end. Where this repository's behavior differs from what `-03` currently specifies, that's why.

---

## Known open items

- **KIA** — `SDB-KIA-01` (§5.4 manifest currency check) is open and slated for a follow-up pass. `SDB-KIA-04-01/02/03` are pending against the unmerged `-04` proposal's own unresolved open questions, not bugs in this implementation of it.
- Every module's full build record — including every point where spec text and implementation were found to diverge, and how each was resolved — is in that module's own `issue-log.md`. Nothing in that log is hidden or summarized away here; this README states the headline items, the issue logs state everything.

---

## Code conventions

Every module follows the same four-part annotation scheme, so a reader can tell at a glance what's specified, what's a placeholder, and what's a judgment call:

- **Draft Anchor Comments** — tie a block of code to the specific section of the IETF draft it implements
- **Stub Declaration Comments** — mark logic that's a placeholder, not a real implementation
- **SDB Gap Markers** — flag any point where the draft text and the running code diverge, with the reasoning for how it was resolved
- **Implementation Choice Comments** — document a judgment call the spec left open, and what was chosen and why

---

## What this code is for

A reference implementation for interoperability and pedagogical purposes — a way to check the SOOS specifications against real, running code, and for others building in this space to see exactly how the primitives compose. It is not a production-hardened library, and hasn't been audited as one.

---

## License

Apache 2.0. See `LICENSE`.

---

## Drafts

- GAR: https://datatracker.ietf.org/doc/draft-sato-soos-gar/
- MJWT: https://datatracker.ietf.org/doc/draft-sato-soos-mjwt/
- KIA: https://datatracker.ietf.org/doc/draft-sato-soos-kia/
- CAP: https://datatracker.ietf.org/doc/draft-sato-soos-cap/

## Contact

Tom Sato — CEO, MyAuberge K.K. / Founding Chair, ATP Foundation
