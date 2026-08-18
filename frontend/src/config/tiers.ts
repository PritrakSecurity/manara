export type Tier = 'community' | 'starter' | 'enterprise'

export const TIER_ORDER: Record<Tier, number> = {
  community: 0,
  starter: 1,
  enterprise: 2,
}

// Every route path and the minimum tier required to use it.
// Community = "Visibility is Free"; Starter/Enterprise = "Control is Paid".
export const routeTiers: Record<string, Tier> = {
  // Command Center (Community)
  '/command-center/executive-overview': 'community',
  '/command-center/posture-risk-scorecard': 'community',
  '/command-center/threat-incident-pulse': 'community',
  '/command-center/compliance-snapshot': 'community',

  // Data Posture (DSPM)
  '/data-posture/inventory-asset-map': 'community',
  '/data-posture/classification-labels': 'starter',
  '/data-posture/data-flow-lineage': 'enterprise',
  '/data-posture/access-exposure': 'starter',
  '/data-posture/shadow-unmanaged-data': 'starter',
  '/data-posture/posture-findings': 'starter',

  // Detection & Investigation
  '/detection/incident-queue-triage': 'community',
  '/detection/alert-analytics-tuning': 'starter',
  '/detection/event-explorer': 'community',
  '/detection/user-entity-risk': 'enterprise',
  '/detection/case-management': 'enterprise',
  '/detection/response-playbooks': 'enterprise',

  // Policy Studio
  '/policy-studio/policy-builder': 'community',
  '/policy-studio/classifiers-rules': 'starter',
  '/policy-studio/dictionaries-edm': 'enterprise',
  '/policy-studio/policy-simulation': 'enterprise',
  '/policy-studio/exceptions-overrides': 'starter',
  '/policy-studio/change-review-versioning': 'enterprise',

  // Compliance & Audit
  '/compliance/framework-mapping': 'community',
  '/compliance/audit-reports': 'starter',
  '/compliance/dsar': 'enterprise',
  '/compliance/retention-residency': 'enterprise',
  '/compliance/attestation-signoff': 'enterprise',

  // Coverage & Integrations
  '/coverage/endpoints': 'community',
  '/coverage/cloud-saas': 'community',
  '/coverage/network-email': 'enterprise',
  '/coverage/identity-sync': 'starter',
  '/coverage/siem-soar-exports': 'starter',
  '/coverage/sensor-health': 'community',

  // Administration
  '/administration/users-rbac': 'community',
  '/administration/workspace': 'community',
  '/administration/notifications': 'starter',
  '/administration/api-keys': 'enterprise',
  '/administration/audit-log': 'enterprise',
  '/administration/license-usage': 'community',
}

// Returns the current user's tier. Hardcoded to 'community' for development;
// later this will come from the authenticated user / license claims.
export function useTier(): Tier {
  return 'community'
}

// Returns true when the current tier is below the route's required tier.
export function isRouteLocked(path: string, currentTier: Tier): boolean {
  const required = routeTiers[path]
  if (!required) return false
  return TIER_ORDER[currentTier] < TIER_ORDER[required]
}
