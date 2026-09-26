# Step 16 (GRP) — Issue Log

Built against `draft-sato-soos-grp-00` directly.

## SVL Phase A key question — resolved (Step 14's original question)

**Question (plan line 1296, filed under Step 14/RGP):** "DEC-RGP-08 is
adopted verbatim by GRP (Step 16). Confirm the three conditions are
identical in both drafts before generating logs for either."

**Resolution: confirmed identical, word-for-word.** Direct text
comparison between `draft-sato-soos-rgp-00` §13.1 and
`draft-sato-soos-grp-00` §11.6:

- Both state the three conditions in the same order with the same
  operative language (Condition 1 — trust level parity or improvement;
  Condition 2 — capability class coverage; Condition 3 — Resource
  Envelope compliance), differing only in "An agent MUST NOT" (RGP) vs.
  "A GEC MUST NOT" (GRP) — a subject-noun difference, not a substantive
  one.
- Both require evaluation against *current* Stage 1 fingerprint data,
  "not cached data older than valid_until."
- Both specify the identical HEM escalation map (Cond 1 → HEM-HIGH-1,
  Cond 2 → HEM-PRE-2, Cond 3 → HEM-DS-1) and the identical priority rule
  for simultaneous failures (HEM-HIGH-1 > HEM-PRE-2 > HEM-DS-1; GRP's own
  broader §10.2 table interleaves HEM-CONSENT into that ordering for its
  other four trigger types, which doesn't disturb the three DEC-RGP-08
  positions relative to each other).

Given the confirmed match, this build implements DEC-RGP-08 **once**,
in the RGP module (`soos-rgp-sample/src/dec-rgp-08.ts`), and GRP imports
it directly (`deps/rgp/dec-rgp-08.ts`) rather than maintaining a second
copy that could drift from RGP's. This is what "adopted verbatim" has
to mean in code, not just in prose — see `gec-grp.ts`'s `evaluateFallback()`,
which calls RGP's real `evaluateDecRgp08()` and `highestPriorityHemClass()`
directly. Corpus scenarios GRP-EDGE-09/10/11/13 exercise RGP's evaluator
through GRP's own code path, not a reimplementation.

## Design notes (not gaps)

**HEM class map reuses HEM's real type.** `HEM_CLASS_MAP` in `types.ts`
is typed against HEM-05's actual `HemInteractionClass` union
(`../deps/hem/types.ts`), not a redeclared set of string literals — so a
typo or a future HEM interaction class rename would fail to compile here
rather than silently drifting.

**Two same-named-concept ALE types, deliberately kept distinct.** RGP's
own `ALE-026 (RGP_FALLBACK_ACTIVATED)` (§13.3) and GRP's
`ALE-066 (GRP_FALLBACK_ACTIVATED)` (§14) are different audit events in
different registries — RGP logs a fallback from its own resource-
discovery perspective, GRP logs the same activation from the
remediation-orchestration perspective. Both are registered as distinct
`ALEType` enum members (`RGP_FALLBACK_ACTIVATED` / `GRP_FALLBACK_ACTIVATED`)
rather than collapsed into one, matching the two drafts' own separate
numbering.

**Cedar remediation tier (§9.3) modeled as a rules table**, same
"model the semantics directly, no live Cedar engine" approach used
throughout this codebase (Steps 9, 11, 12).

## Not built (flagged, not blocking)

- **§12 Cross-Cluster Coordination** — the SACR `propagation_scope`
  authority model and independent-verification requirements are real,
  specified logic, but weren't built this pass. Would need MAD's real
  SACR type (have it from Step 11) plus a second simulated GEC instance,
  similar to how PEER's `runPeerExchange()` simulates two independently-
  rooted GECs. Worth doing if cross-cluster remediation becomes load-
  bearing for a later step.
- **§13 Change Applicability Statement (CAS)** — explicitly deferred by
  the draft itself to a second GRP session (OQ-GRP-02); only the
  "confirmed required fields" are listed, not a full schema. Not
  implemented since there's no complete spec to build against yet.
- **§7's full Change Event schema formalization** (JSON Schema/CDDL) —
  also explicitly deferred by the draft (OQ-GRP-06). The TypeScript
  `ChangeEvent` interface here matches the fields §7 does specify.
- **EPR as a real kernel-managed Sovereign Object** — modeled as a plain
  lookup function (`eprLookup`) the caller supplies, not backed by
  SOV's real `SovereignObject`/`GECMediator` machinery. Reasonable given
  GRP-00 itself only says the EPR "MUST be a kernel-managed SO under KIA
  signing integrity" without further schema detail — nothing to bind to
  more concretely yet.
