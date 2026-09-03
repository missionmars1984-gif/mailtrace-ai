import React from 'react';
import type { RiskLevel, ThreatClassification } from '../../types.js';

interface RiskBadgeProps {
  score?: number;
  level?: RiskLevel;
  classification?: ThreatClassification;
  showScore?: boolean;
  size?: 'sm' | 'md' | 'lg';
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({
  score,
  level,
  classification,
  showScore = true,
  size = 'md',
}) => {
  // Determine level if score is provided
  let computedLevel: RiskLevel = level || 'Clean';
  if (score !== undefined) {
    if (score >= 81) computedLevel = 'Critical';
    else if (score >= 61) computedLevel = 'High Risk';
    else if (score >= 41) computedLevel = 'Suspicious';
    else if (score >= 21) computedLevel = 'Low Risk';
    else computedLevel = 'Clean';
  }

  const getStyle = () => {
    switch (computedLevel) {
      case 'Critical':
        return 'bg-red-50 text-red-700 border-red-200';
      case 'High Risk':
        return 'bg-orange-50 text-orange-700 border-orange-200';
      case 'Elevated Review':
      case 'Suspicious':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'Low Risk':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      case 'Clean':
      case 'Lower Concern':
      default:
        return 'bg-emerald-50 text-emerald-700 border-emerald-200';
    }
  };

  const getDotStyle = () => {
    switch (computedLevel) {
      case 'Critical':
        return 'bg-red-500';
      case 'High Risk':
        return 'bg-orange-500';
      case 'Elevated Review':
      case 'Suspicious':
        return 'bg-amber-500';
      case 'Low Risk':
        return 'bg-blue-500';
      case 'Clean':
      case 'Lower Concern':
      default:
        return 'bg-emerald-500';
    }
  };

  const sizeClasses = {
    sm: 'text-[11px] px-2 py-0.5',
    md: 'text-xs px-2.5 py-1',
    lg: 'text-sm px-3.5 py-1.5 font-semibold',
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border font-medium ${getStyle()} ${sizeClasses[size]}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${getDotStyle()}`} />
      {classification ? classification : computedLevel}
      {showScore && score !== undefined && (
        <span className="font-mono font-bold opacity-80">({score})</span>
      )}
    </span>
  );
};
