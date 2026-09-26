// Step 5 (IDP) — stubs.ts
// Two small stubs per the plan's "Stubs needed" line for Step 5:
//   - SOV stub: SO Type state machine (~20L)
//   - MJWT stub: mandate_id binding (~15L)
// These are NOT re-implementations of sov-core.ts or the real MJWT
// index.ts — they represent the minimal surface IDP needs from each
// draft. Full verification (SOV's GECMediator, MJWT's 13-step
// verifyMandate()) happens upstream of the GEC handing IDP a
// MandateBinding / resolved SOTypeDefinition.

// ---------------------------------------------------------------------
// SOV stub — SO Type state machine
// Needed for: mandate_reference SPO structural validation (IDP-05 §4.2)
// and PD-EOD scope-bounding (§4.7.2), both of which check a
// requested/target state or action against "the SO Type's state
// machine" — this is that state machine, keyed by so_type_id.
// ---------------------------------------------------------------------
export interface SOTypeDefinition {
  so_type_id: string;
  states: string[]; // valid current_state values
  action_space: string[]; // Cedar action strings this SO Type permits
}

export const SO_TYPE_REGISTRY: Record<string, SOTypeDefinition> = {
  'atp/booking-object/1.0': {
    so_type_id: 'atp/booking-object/1.0',
    states: ['DRAFT', 'CONFIRMED', 'PRE_ACTIVITY', 'IN_JOURNEY', 'COMPLETED', 'CANCELLED'],
    action_space: [
      'atp:booking:confirm',
      'atp:booking:cancel',
      'atp:booking:suspend',
      'atp:booking:resume',
      'atp:booking:complete',
    ],
  },
  'atp/mission-object/1.0': {
    so_type_id: 'atp/mission-object/1.0',
    states: ['PLANNING', 'ACTIVE_ROOT', 'IN_JOURNEY', 'COMPLETE'],
    action_space: ['atp:mission:advance', 'atp:mission:abort'],
  },
};

export function resolveSOType(so_type_id: string): SOTypeDefinition | undefined {
  return SO_TYPE_REGISTRY[so_type_id];
}

// SO Instance -> SO Type binding. Real deployments resolve this from the
// SO Instance registry (SOV/Step 2's domain, not IDP's) — this fixture
// lets the demo/SVL corpus register so_id -> so_type_id pairs without
// needing a full SovereignObject construction just to test IDP-layer
// validation. Default entry covers the primary demo SO Instance.
export const SO_INSTANCE_TYPE_MAP: Record<string, string> = {
  'so-booking-azusa-001': 'atp/booking-object/1.0',
  'so-booking-azusa-002': 'atp/booking-object/1.0',
};

export function resolveSOTypeIdForSOInstance(so_id: string): string {
  return SO_INSTANCE_TYPE_MAP[so_id] ?? 'atp/booking-object/1.0'; // fixture default
}

// mandate_reference is an SPO URI (IDP-05 §4.2) that resolves to either
// an SO Type definition or a mandate document governing this session.
// This stub treats every mandate_reference as resolving directly to an
// SO Type id via a flat lookup table — real SPO resolution is a
// separate concern (SPO document fetch + expiry check) not modeled here.
export const SPO_URI_REGISTRY: Record<string, { so_type_id: string; expires_at: string | null }> = {
  'spo://myauberge/atp-booking-standard/1.0': {
    so_type_id: 'atp/booking-object/1.0',
    expires_at: null, // null = does not expire
  },
  'spo://myauberge/atp-booking-legacy/0.9': {
    so_type_id: 'atp/booking-object/1.0',
    expires_at: '2026-01-01T00:00:00Z', // expired — SVL edge coverage (IDP_SPO_EXPIRED / INTAKE_SPO_EXPIRED)
  },
};

// ---------------------------------------------------------------------
// MJWT stub — mandate_id binding
// IDP only needs to confirm the presented Mandate JWT's jti (mandate_id)
// and so_id match what the IDP declares (IDP-05 §5.2(e)/(d)) — full
// 13-step MJWT verification is Step 3's job (tier1/mjwt/index.ts,
// verifyMandate()). This represents "the GEC already ran MJWT
// verification upstream and is now checking IDP-level binding."
// ---------------------------------------------------------------------
export interface MandateBinding {
  mandate_id: string; // jti
  so_id: string;
  human_principal_id: string;
  agent_class: 'CLASS_1' | 'CLASS_2' | 'CLASS_3';
}

export function checkMandateBinding(
  idp: { mandate_id: string; so_id: string },
  binding: MandateBinding
): boolean {
  return idp.mandate_id === binding.mandate_id && idp.so_id === binding.so_id;
}
