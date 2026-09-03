import React from 'react';
import type { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  variant?: 'default' | 'danger' | 'warning' | 'success' | 'blue';
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = 'default',
}) => {
  const getIconStyles = () => {
    switch (variant) {
      case 'danger':
        return 'bg-red-50 text-red-600 border-red-100';
      case 'warning':
        return 'bg-amber-50 text-amber-600 border-amber-100';
      case 'success':
        return 'bg-emerald-50 text-emerald-600 border-emerald-100';
      case 'blue':
        return 'bg-blue-50 text-blue-600 border-blue-100';
      case 'default':
      default:
        return 'bg-slate-50 text-slate-600 border-slate-200';
    }
  };

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm hover:shadow transition-shadow duration-150 flex items-start justify-between">
      <div>
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider">{title}</p>
        <h3 className="text-2xl font-bold text-slate-900 mt-1 font-mono tracking-tight">{value}</h3>
        {subtitle && <p className="text-xs text-slate-400 mt-1 font-medium">{subtitle}</p>}
      </div>
      <div className={`p-2.5 rounded-lg border ${getIconStyles()}`}>
        <Icon className="w-5 h-5" />
      </div>
    </div>
  );
};
