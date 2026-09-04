import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Globe,
  Radio,
  ExternalLink,
  ChevronRight,
  Target,
  ListFilter,
  CheckCircle2,
} from 'lucide-react';
import type { CaseRecord } from '../../types.js';
import { RiskBadge } from '../common/RiskBadge.js';

interface OverviewTabProps {
  caseData: CaseRecord;
  onNavigateTab?: (tabKey: string) => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({ caseData, onNavigateTab }) => {
  const { metadata, classification, riskScore, riskLevel, confidence, summary, keyFindings, aiAssessment, scoreBreakdown, hops, iocs } = caseData;

  // Origin info from first public hop or first hop
  const originHop = hops.find((h) => h.isOrigin) || hops[0];

  // Why Flagged description
  const whyFlagged = scoreBreakdown?.whyHighRisk || summary;

  // Recommended actions
  const rawActions = aiAssessment?.recommended_actions || [];
  const recommendedActions = [
    ...(caseData.recommendedAction ? [caseData.recommendedAction] : []),
    ...rawActions.filter((a) => a !== caseData.recommendedAction),
  ];
  if (recommendedActions.length === 0) {
    recommendedActions.push(
      'Quarantine message and purge from victim inbox.',
      'Block originating sender address and envelope return path on mail security gateway.',
      'Add extracted domain and IP indicators to organization perimeter firewall blocklist.'
    );
  }

  const threatTypes: string[] = caseData.threatTypes || (scoreBreakdown as any)?.threatTypes || [];

  // Top critical or high IOCs
  const topIocs = (iocs || []).filter((i) => i.severity === 'HIGH').slice(0, 4);

  return (
    <div className="space-y-6">
      {/* 1. Primary Verdict Card */}
      <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-slate-100">
          <div>
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-xs font-mono font-bold text-blue-700 bg-blue-50 px-2.5 py-1 rounded border border-blue-200">
                CASE #{caseData.caseNumber}
              </span>
              <RiskBadge score={riskScore} level={riskLevel} classification={classification} size="lg" />
              <div className="flex items-center gap-1.5 text-xs text-slate-500 bg-slate-50 px-3 py-1 rounded-md border border-slate-200">
                <span>Model Confidence:</span>
                <strong className="text-slate-800 font-mono">{confidence}%</strong>
              </div>
            </div>

            <h3 className="text-xl font-bold text-slate-900 mt-3 tracking-tight">
              {metadata.subject !== undefined && metadata.subject !== ''
                ? metadata.subject
                : (metadata.subject === '' ? '(Empty Subject)' : '(No Subject)')}
            </h3>

            {threatTypes.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 mt-2">
                {threatTypes.map((t: string, idx: number) => (
                  <span
                    key={idx}
                    className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 border border-slate-200"
                  >
                    {t}
                  </span>
                ))}
              </div>
            )}

            <p className="text-xs text-slate-500 mt-2 flex items-center gap-2">
              <span>Claimed Sender: <strong>{metadata.from.address}</strong></span>
              <span>•</span>
              <span>Date: {metadata.date ? new Date(metadata.date).toUTCString() : 'N/A'}</span>
            </p>
          </div>

          {/* Risk Gauge Tile */}
          <div className="flex items-center gap-4 bg-slate-900 text-white p-4 rounded-xl border border-slate-800 self-start lg:self-auto min-w-[220px]">
            <div className="text-center">
              <div className="text-3xl font-black font-mono tracking-tight text-white">
                {riskScore}<span className="text-sm font-normal text-slate-400">/100</span>
              </div>
              <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mt-0.5">
                Threat Score
              </div>
            </div>
            <div className="flex-1">
              <div className="text-xs font-semibold uppercase tracking-wider mb-1.5 text-right">
                <span
                  className={
                    riskScore >= 81
                      ? 'text-red-400'
                      : riskScore >= 61
                      ? 'text-orange-400'
                      : riskScore >= 41
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }
                >
                  {riskLevel}
                </span>
              </div>
              <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${
                    riskScore >= 81
                      ? 'bg-red-500'
                      : riskScore >= 61
                      ? 'bg-orange-500'
                      : riskScore >= 41
                      ? 'bg-amber-500'
                      : 'bg-emerald-500'
                  }`}
                  style={{ width: `${Math.max(5, riskScore)}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Why Flagged (Direct Security Rationale) */}
        <div className="mt-5">
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-700 mb-2">
            <Radio className="w-4 h-4 text-blue-600" />
            <span>Why Flagged / Security Rationale</span>
          </div>
          <div
            className={`p-4 rounded-lg border text-sm leading-relaxed ${
              riskScore >= 81
                ? 'bg-red-50/70 border-red-200 text-red-950'
                : riskScore >= 61
                ? 'bg-orange-50/70 border-orange-200 text-orange-950'
                : riskScore >= 41
                ? 'bg-amber-50/70 border-amber-200 text-amber-950'
                : 'bg-slate-50 border-slate-200 text-slate-700'
            }`}
          >
            {whyFlagged}
          </div>
        </div>
      </div>

      {/* 2. Dual Column: Top Findings & Recommended Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Findings */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-4">
              <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Target className="w-4 h-4 text-blue-600" />
                Top Evidentiary Findings
              </h4>
              {onNavigateTab && (
                <button
                  onClick={() => onNavigateTab('evidence')}
                  className="text-xs text-blue-600 hover:text-blue-800 font-medium flex items-center gap-1"
                >
                  View All Evidence <ChevronRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            <div className="space-y-2.5">
              {(keyFindings || []).slice(0, 4).map((finding, idx) => (
                <div
                  key={idx}
                  className="flex items-start gap-2.5 p-3 rounded-lg bg-slate-50 border border-slate-100 text-xs text-slate-700"
                >
                  <span className="w-5 h-5 rounded-full bg-blue-100 text-blue-700 font-bold flex items-center justify-center flex-shrink-0 text-[10px] mt-0.5">
                    {idx + 1}
                  </span>
                  <span className="leading-relaxed font-medium">{finding}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Recommended Actions */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-4">
              <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                Recommended Response Actions
              </h4>
              {onNavigateTab && (
                <button
                  onClick={() => onNavigateTab('report')}
                  className="text-xs text-blue-600 hover:text-blue-800 font-medium flex items-center gap-1"
                >
                  Forensic Dossier <ChevronRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            <div className="space-y-2.5">
              {recommendedActions.slice(0, 4).map((action, idx) => (
                <div
                  key={idx}
                  className="flex items-start gap-2.5 p-3 rounded-lg bg-slate-50 border border-slate-100 text-xs text-slate-700"
                >
                  <span className="w-5 h-5 rounded-full bg-emerald-100 text-emerald-700 font-bold flex items-center justify-center flex-shrink-0 text-[10px] mt-0.5">
                    ✓
                  </span>
                  <span className="leading-relaxed">{action}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* 3. Observed Origin & Important IOCs Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Observed Origin Snapshot */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-4">
            <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Globe className="w-4 h-4 text-blue-600" />
              Observed Sending Infrastructure
            </h4>
            {onNavigateTab && (
              <button
                onClick={() => onNavigateTab('geo')}
                className="text-xs text-blue-600 hover:text-blue-800 font-medium flex items-center gap-1"
              >
                Inspect Geo Map <ChevronRight className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="bg-slate-50 p-3 rounded-lg border border-slate-100">
                <span className="text-slate-400 block text-[11px] mb-0.5">Observed Origin IP</span>
                <span className="font-mono font-bold text-slate-800 text-sm">
                  {originHop?.ip || 'Unavailable'}
                </span>
              </div>
              <div className="bg-slate-50 p-3 rounded-lg border border-slate-100">
                <span className="text-slate-400 block text-[11px] mb-0.5">Approximate Location</span>
                <span className="font-medium text-slate-800 text-sm">
                  {originHop?.geo?.country
                    ? `${originHop.geo.city ? originHop.geo.city + ', ' : ''}${originHop.geo.country}`
                    : 'RFC 1918 Private Subnet'}
                </span>
              </div>
              <div className="bg-slate-50 p-3 rounded-lg border border-slate-100">
                <span className="text-slate-400 block text-[11px] mb-0.5">Autonomous System (ASN)</span>
                <span className="font-mono text-slate-800">
                  {originHop?.geo?.asn || 'Internal / Direct'}
                </span>
              </div>
              <div className="bg-slate-50 p-3 rounded-lg border border-slate-100">
                <span className="text-slate-400 block text-[11px] mb-0.5">Network Operator / ISP</span>
                <span className="font-medium text-slate-800 truncate block">
                  {originHop?.geo?.org || originHop?.geo?.isp || 'Internal Enterprise Relay'}
                </span>
              </div>
            </div>
            <p className="text-[11px] text-slate-400 italic">
              * Observed email infrastructure represents approximate network location, not human sender identity.
            </p>
          </div>
        </div>

        {/* Important IOCs Snapshot */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-4">
            <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <ListFilter className="w-4 h-4 text-blue-600" />
              High-Priority Indicators of Compromise
            </h4>
            {onNavigateTab && (
              <button
                onClick={() => onNavigateTab('iocs')}
                className="text-xs text-blue-600 hover:text-blue-800 font-medium flex items-center gap-1"
              >
                All IOCs ({iocs?.length || 0}) <ChevronRight className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {topIocs.length === 0 ? (
            <div className="text-center py-6 text-slate-400 text-xs">
              No high-severity external indicators extracted from this message.
            </div>
          ) : (
            <div className="space-y-2.5">
              {topIocs.map((ioc, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-2.5 rounded-lg bg-slate-50 border border-slate-100 text-xs"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-[10px] font-bold font-mono px-2 py-0.5 rounded bg-red-100 text-red-700">
                      {ioc.type}
                    </span>
                    <span className="font-mono text-slate-800 truncate" title={ioc.value}>
                      {ioc.value}
                    </span>
                  </div>
                  <span className="text-[10px] text-slate-400 font-medium flex-shrink-0 ml-2">
                    {ioc.context}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
