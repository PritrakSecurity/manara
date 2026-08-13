import React from 'react';

interface SeverityBadgeProps {
  severity: string;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

const severityStyles: Record<string, { bg: string; text: string; border: string; icon: string }> = {
  NONE: {
    bg: 'bg-gray-500/10',
    text: 'text-gray-400',
    border: 'border-gray-500/30',
    icon: '○',
  },
  LOW: {
    bg: 'bg-green-500/10',
    text: 'text-green-400',
    border: 'border-green-500/30',
    icon: '○',
  },
  MEDIUM: {
    bg: 'bg-yellow-500/10',
    text: 'text-yellow-400',
    border: 'border-yellow-500/30',
    icon: '◐',
  },
  MEDIUM_HIGH: {
    bg: 'bg-amber-500/10',
    text: 'text-amber-400',
    border: 'border-amber-500/30',
    icon: '◐',
  },
  HIGH: {
    bg: 'bg-orange-500/10',
    text: 'text-orange-400',
    border: 'border-orange-500/30',
    icon: '◉',
  },
  CRITICAL: {
    bg: 'bg-red-500/10',
    text: 'text-red-400',
    border: 'border-red-500/30',
    icon: '●',
  },
};

const sizeStyles = {
  sm: 'px-1.5 py-0.5 text-xs',
  md: 'px-2 py-1 text-xs',
  lg: 'px-3 py-1.5 text-sm',
};

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  showIcon = true,
}) => {
  const style = severityStyles[severity] || severityStyles.MEDIUM;

  return (
    <span
      className={`inline-flex items-center gap-1 font-medium rounded border ${style.bg} ${style.text} ${style.border} ${sizeStyles[size]}`}
    >
      {showIcon && <span>{style.icon}</span>}
      {severity}
    </span>
  );
};
