import React from 'react';
import { Badge } from './common/Badge';

interface ClassificationBadgeProps {
  classification: string;
  size?: 'sm' | 'md' | 'lg';
}

export const ClassificationBadge: React.FC<ClassificationBadgeProps> = ({ classification, size = 'md' }) => {
  return <Badge label={classification} variant="classification" size={size} />;
};
