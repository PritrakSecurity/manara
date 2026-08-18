import React from 'react';
import { Badge } from './common/Badge';

interface StatusBadgeProps {
  status: string;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'incident' | 'approval' | 'device';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, size = 'md', variant = 'incident' }) => {
  return <Badge label={status} variant={variant} size={size} />;
};
