# Sprint Issue Log
## SOOS Sample Code Plan v4 — svl/issue-log.md

---

ISSUE-001
Type:        II — Scenario A/C hybrid (structural gap in canonicalization,
             resolved pragmatically for sample code; draft still needs
             normative fix)
Encountered: GAR Step 1a, pre-flight check before log generation
Description: draft-sato-soos-gar-03 states soos.gar.prev_span_hash is
             "the hash of the immediately preceding governance span in
             the session" (Terminology, and repeated in §13.7 and §14)
             but never specifies:
               (1) which fields of the preceding span are included in
                   the hash input
               (2) the canonical serialization order/format of those
                   fields before hashing
               (3) what "event delta record" contains as a field-level
                   schema (used interchangeably with "OTel span" at
                   §14.2 Stage 5 but never given its own schema table)
               (4) the value of prev_span_hash on the first span in a
                   session (no predecessor to hash)
             Two reasonable implementers would reach different chain
             outputs from identical session data — this is a genuine
             ambiguity, not a reading-comprehension gap (three-question
             test: Q1 no, Q2 yes → Type II).
Draft ref:   GAR-03 §3 (Terminology), §13.7 (Table 9), §14.2 (Stage 2),
             §14.3 (Session Block Construction)
Resolution:  Adopted for sample code, pending draft fix:

               function computePrevSpanHash(span: GovernanceSpan): string {
                 const canonical = [
                   span.session_id,
                   span.decision,
                   span.kernel_id,
                   span.cap_profile_hash,
                   span.timestamp,
                   span.prev_span_hash ?? 'GENESIS'
                 ].join('|');
                 return sha256(canonical);
               }

             Field order and '|' separator convention chosen to match
             the house style already established in KEE-1 §10's XPID
             derivation function, for internal consistency across the
             sample code base. 'GENESIS' sentinel adopted for the first
             span in a session (answers SDB-GAR-01's original framing:
             "First entry prev_span_hash — what value?").
DR needed:   Yes — before GAR-04. Recommend §14 gain an explicit
             "Canonical Hash Input" subsection defining the exact field
             list, order, and separator/serialization convention, plus
             a stated first-span sentinel value. See SDB-GAR-01 (SDB
             Gap Register, Sample Code Plan v4) for tracking.
