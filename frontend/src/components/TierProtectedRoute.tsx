import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { useTier, routeTiers, isRouteLocked } from '../config/tiers';
import { useUIStore } from '../store/uiStore';
import UpgradeGateModal from './UpgradeGateModal';

interface TierProtectedRouteProps {
  children: React.ReactNode;
}

// Build a human-readable feature name from a route path, e.g.
// "/policy-studio/policy-simulation" -> "Policy Simulation".
function featureNameFromPath(path: string): string {
  const segment = path.split('/').filter(Boolean).pop() || 'This feature'
  return segment
    .split('-')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ')
}

// Guards a route against tier bypass. If the current user's tier is below the
// route's required tier, the page component is NOT rendered - only the upgrade
// gate is shown, so enterprise features cannot be reached by typing the URL.
export function TierProtectedRoute({ children }: TierProtectedRouteProps) {
  const location = useLocation();
  const tier = useTier();
  const openUpgradeModal = useUIStore((s) => s.openUpgradeModal);

  const locked = isRouteLocked(location.pathname, tier);
  const requiredTier = routeTiers[location.pathname];

  useEffect(() => {
    if (locked && requiredTier) {
      const featureName = featureNameFromPath(location.pathname)
      openUpgradeModal(
        featureName,
        requiredTier,
        `${featureName} is a ${requiredTier} feature in the Pritrak DLP platform.`
      )
    }
  }, [locked, requiredTier, openUpgradeModal, location.pathname])

  if (locked) {
    return <UpgradeGateModal />
  }

  return <>{children}</>
}

export default TierProtectedRoute
