import React from 'react';

interface StatusBadgeProps {
  status: string;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'incident' | 'approval' | 'device';
}

const incidentStatusStyles: Record<string, { bg: string; text: string; border: string }> = {
  OPEN: {
    bg: 'bg-blue-500/10',
    text: 'text-blue-400',
    border: 'border-blue-500/30',
  },
  INVESTIGATING: {
    bg: 'bg-yellow-500/10',
    text: 'text-yellow-400',
    border: 'border-yellow-500/30',
  },
  ESCALATED: {
    bg: 'bg-orange-500/10',
    text: 'text-orange-400',
    border: 'border-orange-500/30',
  },
  RESOLVED: {
    bg: 'bg-green-500/10',
    text: 'text-green-400',
    border: 'border-green-500/30',
  },
  FALSE_POSITIVE: {
    bg: 'bg-gray-500/10',
    text: 'text-gray-400',
    border: 'border-gray-500/30',
  },
  ACKNOWLEDGED: {
    bg: 'bg-purple-500/10',
    text: 'text-purple-400',
    border: 'border-purple-500/30',
  },
};

const approvalStatusStyles: Record<string, { bg: string; text: string; border: string }> = {
  PENDING: {
    bg: 'bg-yellow-500/10',
    text: 'text-yellow-400',
    border: 'border-yellow-500/30',
  },
  APPROVED: {
    bg: 'bg-green-500/10',
    text: 'text-green-400',
    border: 'border-green-500/30',
  },
  DENIED: {
    bg: 'bg-red-500/10',
    text: 'text-red-400',
    border: 'border-red-500/30',
  },
  TIMEOUT: {
    bg: 'bg-gray-500/10',
    text: 'text-gray-400',
    border: 'border-gray-500/30',
  },
  CANCELLED: {
    bg: 'bg-gray-500/10',
    text: 'text-gray-400',
    border: 'border-gray-500/30',
  },
};

const deviceStatusStyles: Record<string, { bg: string; text: string; border: string }> = {
  ONLINE: {
    bg: 'bg-green-500/10',
    text: 'text-green-400',
    border: 'border-green-500/30',
  },
  OFFLINE: {
    bg: 'bg-red-500/10',
    text: 'text-red-400',
    border: 'border-red-500/30',
  },
  SYNCING: {
    bg: 'bg-blue-500/10',
    text: 'text-blue-400',
    border: 'border-blue-500/30',
  },
};

const sizeStyles = {
  sm: 'px-1.5 py-0.5 text-xs',
  md: 'px-2 py-1 text-xs',
  lg: 'px-3 py-1.5 text-sm',
};

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  size = 'md',
  variant = 'incident',
}) => {
  let styles: Record<string, { bg: string; text: string; border: string }>;

  switch (variant) {
    case 'approval':
      styles = approvalStatusStyles;
      break;
    case 'device':
      styles = deviceStatusStyles;
      break;
    default:
      styles = incidentStatusStyles;
  }

  const style = styles[status] || { bg: 'bg-gray-500/10', text: 'text-gray-400', border: 'border-gray-500/30' };

  return (
    <span
      className={`inline-flex items-center font-medium rounded border ${style.bg} ${style.text} ${style.border} ${sizeStyles[size]}`}
    >
      {status.replace(/_/g, ' ')}
    </span>
  );
};
