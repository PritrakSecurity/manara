import React from 'react';

interface StatsCardProps {
  title: string;
  value: number | string;
  subtitle?: string;
  icon?: React.ReactNode;
  trend?: number;
  trendLabel?: string;
  color?: 'blue' | 'green' | 'yellow' | 'red' | 'purple' | 'gray';
  onClick?: () => void;
}

const colorStyles = {
  blue: {
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/30',
    icon: 'text-blue-400',
    hover: 'hover:bg-blue-500/20',
  },
  green: {
    bg: 'bg-green-500/10',
    border: 'border-green-500/30',
    icon: 'text-green-400',
    hover: 'hover:bg-green-500/20',
  },
  yellow: {
    bg: 'bg-yellow-500/10',
    border: 'border-yellow-500/30',
    icon: 'text-yellow-400',
    hover: 'hover:bg-yellow-500/20',
  },
  red: {
    bg: 'bg-red-500/10',
    border: 'border-red-500/30',
    icon: 'text-red-400',
    hover: 'hover:bg-red-500/20',
  },
  purple: {
    bg: 'bg-purple-500/10',
    border: 'border-purple-500/30',
    icon: 'text-purple-400',
    hover: 'hover:bg-purple-500/20',
  },
  gray: {
    bg: 'bg-gray-700/50',
    border: 'border-gray-600',
    icon: 'text-gray-400',
    hover: 'hover:bg-gray-700',
  },
};

export const StatsCard: React.FC<StatsCardProps> = ({
  title,
  value,
  subtitle,
  icon,
  trend,
  trendLabel,
  color = 'gray',
  onClick,
}) => {
  const styles = colorStyles[color];

  return (
    <div
      onClick={onClick}
      className={`${styles.bg} ${styles.border} ${onClick ? styles.hover + ' cursor-pointer' : ''}
        border rounded-lg p-4 transition-colors duration-200`}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-gray-400 text-sm font-medium">{title}</p>
          <p className="text-2xl font-bold text-gray-900 mt-1">{value}</p>
          {subtitle && (
            <p className="text-gray-500 text-xs mt-1">{subtitle}</p>
          )}
        </div>
        {icon && (
          <div className={`${styles.icon} p-2 rounded-lg ${styles.bg}`}>
            {icon}
          </div>
        )}
      </div>

      {trend !== undefined && (
        <div className="mt-3 flex items-center gap-1 text-sm">
          <span className={trend >= 0 ? 'text-red-400' : 'text-green-400'}>
            {trend >= 0 ? '↑' : '↓'} {Math.abs(trend).toFixed(1)}%
          </span>
          {trendLabel && (
            <span className="text-gray-500">{trendLabel}</span>
          )}
        </div>
      )}
    </div>
  );
};
