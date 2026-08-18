import React from 'react';
import { Badge } from './common/Badge';

interface SeverityBadgeProps {
  severity: string;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md', showIcon = true }) => {
  return <Badge label={severity} variant="severity" size={size} showIcon={showIcon} />;
};
