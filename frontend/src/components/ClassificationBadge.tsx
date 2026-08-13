import React from 'react';

interface ClassificationBadgeProps {
  classification: string;
  size?: 'sm' | 'md' | 'lg';
}

const classificationStyles: Record<string, { bg: string; text: string; border: string }> = {
  PUBLIC: {
    bg: 'bg-green-500/10',
    text: 'text-green-400',
    border: 'border-green-500/30',
  },
  INTERNAL: {
    bg: 'bg-blue-500/10',
    text: 'text-blue-400',
    border: 'border-blue-500/30',
  },
  PRIVATE: {
    bg: 'bg-blue-500/10',
    text: 'text-blue-400',
    border: 'border-blue-500/30',
  },
  CONFIDENTIAL: {
    bg: 'bg-yellow-500/10',
    text: 'text-yellow-400',
    border: 'border-yellow-500/30',
  },
  RESTRICTED: {
    bg: 'bg-red-500/10',
    text: 'text-red-400',
    border: 'border-red-500/30',
  },
  PENDING: {
    bg: 'bg-purple-500/10',
    text: 'text-purple-400',
    border: 'border-purple-500/30',
  },
};

const sizeStyles = {
  sm: 'px-1.5 py-0.5 text-xs',
  md: 'px-2 py-1 text-xs',
  lg: 'px-3 py-1.5 text-sm',
};

export const ClassificationBadge: React.FC<ClassificationBadgeProps> = ({
  classification,
  size = 'md',
}) => {
  const style = classificationStyles[classification] || classificationStyles.PRIVATE;

  return (
    <span
      className={`inline-flex items-center font-medium rounded border ${style.bg} ${style.text} ${style.border} ${sizeStyles[size]}`}
    >
      {classification}
    </span>
  );
};
