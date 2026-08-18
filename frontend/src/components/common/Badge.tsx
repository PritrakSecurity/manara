import React from 'react';

type Size = 'sm' | 'md' | 'lg';
type BadgeVariant = 'incident' | 'approval' | 'device' | 'severity' | 'classification' | 'evidence';

interface Tone {
  bg: string;
  text: string;
  border: string;
}

const sizeStyles: Record<Size, string> = {
  sm: 'px-1.5 py-0.5 text-xs',
  md: 'px-2 py-1 text-xs',
  lg: 'px-3 py-1.5 text-sm',
};

const statusStyles: Record<'incident' | 'approval' | 'device', Record<string, Tone>> = {
  incident: {
    OPEN: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30' },
    INVESTIGATING: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
    ESCALATED: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/30' },
    RESOLVED: { bg: 'bg-green-500/10', text: 'text-green-400', border: 'border-green-500/30' },
    FALSE_POSITIVE: { bg: 'bg-gray-500/10', text: 'text-gray-400', border: 'border-gray-500/30' },
    ACKNOWLEDGED: { bg: 'bg-purple-500/10', text: 'text-purple-400', border: 'border-purple-500/30' },
  },
  approval: {
    PENDING: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
    APPROVED: { bg: 'bg-green-500/10', text: 'text-green-400', border: 'border-green-500/30' },
    DENIED: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30' },
    TIMEOUT: { bg: 'bg-gray-500/10', text: 'text-gray-400', border: 'border-gray-500/30' },
    CANCELLED: { bg: 'bg-gray-500/10', text: 'text-gray-400', border: 'border-gray-500/30' },
  },
  device: {
    ONLINE: { bg: 'bg-green-500/10', text: 'text-green-400', border: 'border-green-500/30' },
    OFFLINE: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30' },
    SYNCING: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30' },
  },
};

const severityStyles: Record<string, Tone & { icon: string }> = {
  NONE: { bg: 'bg-gray-500/10', text: 'text-gray-400', border: 'border-gray-500/30', icon: '○' },
  LOW: { bg: 'bg-green-500/10', text: 'text-green-400', border: 'border-green-500/30', icon: '○' },
  MEDIUM: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30', icon: '◐' },
  MEDIUM_HIGH: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/30', icon: '◐' },
  HIGH: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/30', icon: '◉' },
  CRITICAL: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30', icon: '●' },
};

const classificationStyles: Record<string, Tone> = {
  PUBLIC: { bg: 'bg-green-500/10', text: 'text-green-400', border: 'border-green-500/30' },
  INTERNAL: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30' },
  PRIVATE: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30' },
  CONFIDENTIAL: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  RESTRICTED: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30' },
  PENDING: { bg: 'bg-purple-500/10', text: 'text-purple-400', border: 'border-purple-500/30' },
};

// Finding evidence strength: hard evidence (red), contextual (yellow),
// shadow-only (blue).
const evidenceStyles: Record<string, Tone> = {
  'Hard Evidence': { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30' },
  Contextual: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  'Shadow Only': { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30' },
};

const fallbackTone: Tone = { bg: 'bg-gray-500/10', text: 'text-gray-400', border: 'border-gray-500/30' };

export interface BadgeProps {
  label: string;
  variant?: BadgeVariant;
  size?: Size;
  showIcon?: boolean;
}

export const Badge: React.FC<BadgeProps> = ({ label, variant = 'incident', size = 'md', showIcon = false }) => {
  let tone: Tone = fallbackTone;
  let glyph: string | undefined;
  let display = label;

  switch (variant) {
    case 'approval':
    case 'device':
      tone = statusStyles[variant][label] || fallbackTone;
      display = label.replace(/_/g, ' ');
      break;
    case 'incident':
      tone = statusStyles.incident[label] || fallbackTone;
      display = label.replace(/_/g, ' ');
      break;
    case 'severity': {
      const s = severityStyles[label] || severityStyles.MEDIUM;
      tone = { bg: s.bg, text: s.text, border: s.border };
      glyph = s.icon;
      display = label;
      break;
    }
    case 'classification':
      tone = classificationStyles[label] || classificationStyles.PRIVATE;
      display = label;
      break;
    case 'evidence':
      tone = evidenceStyles[label] || fallbackTone;
      display = label.replace(/_/g, ' ');
      break;
  }

  return (
    <span
      className={`inline-flex items-center font-medium rounded border ${tone.bg} ${tone.text} ${tone.border} ${sizeStyles[size]} ${showIcon && glyph ? 'gap-1' : ''}`}
    >
      {showIcon && glyph ? <span>{glyph}</span> : null}
      {display}
    </span>
  );
};

export default Badge;
