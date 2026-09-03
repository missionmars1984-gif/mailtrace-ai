import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Layers,
  ShieldAlert,
  ExternalLink,
  Calendar,
  Crosshair,
  Server,
  Globe,
  Link,
  AlertTriangle,
  RefreshCw,
  Hash,
} from 'lucide-react';
import { ApiService } from '../services/api.js';
import type { CampaignCluster } from '../types.js';
import { RiskBadge } from '../components/common/RiskBadge.js';

export const CampaignsPage: React.FC = () => {
  const navigate = useNavigate();
  const [campaigns, setCampaigns] = useState<CampaignCluster[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  const loadCampaigns = async () => {
    try {
      setLoading(true);
      const data = await ApiService.getCampaigns();
      setCampaigns(data);
    } catch (err) {
      console.error('Failed to load campaigns:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCampaigns();
  }, []);

  const getIndicatorIcon = (type: string) => {
    switch (type) {
      case 'IP':
        return <Server className="w-3.5 h-3.5 text-[#246BFE]" />;
      case 'DOMAIN':
        return <Globe className="w-3.5 h-3.5 text-purple-600" />;
      case 'URL':
        return <Link className="w-3.5 h-3.5 text-red-600" />;
      case 'SENDER':
      default:
        return <Crosshair className="w-3.5 h-3.5 text-amber-600" />;
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[#0B1F3A] tracking-tight">Attack Campaigns</h1>
          <p className="text-xs text-[#68809F] mt-1">
            Emails sharing infrastructure, domains, or payload artifacts are grouped into active attack campaigns.
          </p>
        </div>
        <button
          onClick={loadCampaigns}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-[#E5E9F2] text-[#0B1F3A] hover:bg-slate-50 rounded-xl text-xs font-semibold shadow-2xs transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-[#246BFE]' : ''}`} />
          <span>Re-cluster</span>
        </button>
      </div>

      {/* Stats Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-4 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
          <div className="flex items-center gap-2 mb-1">
            <Layers className="w-4 h-4 text-[#246BFE]" />
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Active Campaigns</span>
          </div>
          <div className="text-2xl font-extrabold text-[#0B1F3A] font-mono">{campaigns.length}</div>
        </div>
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-4 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
          <div className="flex items-center gap-2 mb-1">
            <Crosshair className="w-4 h-4 text-purple-600" />
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Targeted Groups</span>
          </div>
          <div className="text-2xl font-extrabold text-purple-600 font-mono">
            {Array.from(new Set(campaigns.flatMap((c) => c.targetedDepartments || []))).length || (campaigns.length > 0 ? 1 : 0)}
          </div>
        </div>
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-4 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
          <div className="flex items-center gap-2 mb-1">
            <ShieldAlert className="w-4 h-4 text-red-500" />
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Related Emails</span>
          </div>
          <div className="text-2xl font-extrabold text-red-600 font-mono">
            {campaigns.reduce((acc, c) => acc + c.caseCount, 0)}
          </div>
        </div>
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-4 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
          <div className="flex items-center gap-2 mb-1">
            <AlertTriangle className="w-4 h-4 text-emerald-500" />
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Match Confidence</span>
          </div>
          <div className="text-2xl font-extrabold text-emerald-600 font-mono">
            {campaigns.length > 0 ? `${Math.round(campaigns.reduce((acc, c) => acc + (c.matchConfidence || 92), 0) / campaigns.length)}%` : '—'}
          </div>
        </div>
      </div>

      {/* Campaign Cards Grid */}
      {loading ? (
        <div className="flex items-center justify-center p-12 text-[#68809F] text-xs">
          <RefreshCw className="w-4 h-4 animate-spin mr-2 text-[#246BFE]" />
          Analyzing cross-case telemetry for campaign correlation...
        </div>
      ) : campaigns.length === 0 ? (
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-12 text-center">
          <div className="flex flex-col items-center justify-center space-y-3">
            <div className="w-12 h-12 rounded-full bg-slate-100 text-slate-400 flex items-center justify-center">
              <Layers className="w-6 h-6" />
            </div>
            <p className="font-semibold text-slate-800 text-sm">No attack campaigns detected yet</p>
            <p className="text-slate-500 max-w-sm text-xs leading-relaxed">
              Campaigns are automatically detected when 2 or more analyzed emails share a common sending
              IP, lookalike domain, or high-risk URL infrastructure. Analyze more emails to start seeing patterns.
            </p>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {campaigns.map((camp) => (
            <div
              key={camp.id}
              className="bg-white rounded-xl border border-[#E5E9F2] p-6 shadow-[0_1px_3px_rgba(11,31,58,0.03)] hover:border-[#246BFE]/30 transition-all flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between pb-3 border-b border-[#E5E9F2]">
                  <div className="flex items-center gap-2.5">
                    <div className="w-8 h-8 rounded-lg bg-red-50 text-red-600 flex items-center justify-center">
                      <Layers className="w-4 h-4" />
                    </div>
                    <div>
                      <h3 className="font-bold text-sm text-[#0B1F3A]">{camp.name}</h3>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-[10px] font-mono text-[#68809F]">{camp.id}</span>
                        {camp.matchConfidence && (
                          <span className="px-1.5 py-0.2 bg-emerald-50 text-emerald-700 text-[9px] font-bold rounded">
                            {camp.matchConfidence}% Match
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                  <RiskBadge classification={camp.threatType} size="sm" />
                </div>

                <p className="text-xs text-[#68809F] mt-3 leading-relaxed">
                  {camp.description}
                </p>

                {/* Explainability Callout: Why these emails are linked */}
                {camp.whyLinked && (
                  <div className="mt-3 p-3 rounded-xl bg-blue-50/60 border border-blue-100 text-xs">
                    <div className="font-bold text-[#246BFE] text-[11px] mb-1 flex items-center gap-1.5">
                      <Crosshair className="w-3.5 h-3.5" />
                      Why these emails are linked:
                    </div>
                    <p className="text-slate-700 text-[11px] leading-relaxed">
                      {camp.whyLinked}
                    </p>
                  </div>
                )}

                {/* Targeted Departments */}
                {camp.targetedDepartments && camp.targetedDepartments.length > 0 && (
                  <div className="mt-3 flex flex-wrap items-center gap-1.5">
                    <span className="text-[10px] font-bold text-[#68809F] uppercase tracking-wider mr-1">Targeted:</span>
                    {camp.targetedDepartments.map((dept) => (
                      <span key={dept} className="px-2 py-0.5 bg-[#F1F5F9] text-slate-700 rounded-md text-[10px] font-medium">
                        {dept}
                      </span>
                    ))}
                  </div>
                )}

                {/* Common Indicator Callout */}
                <div className="mt-3 p-2.5 rounded-xl bg-[#F7F9FC] border border-[#E5E9F2] flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    {getIndicatorIcon(camp.commonIndicatorType)}
                    <span className="text-[11px] font-bold text-[#68809F]">Shared {camp.commonIndicatorType}:</span>
                  </div>
                  <span className="font-mono font-bold text-[#0B1F3A] max-w-[220px] truncate" title={camp.commonIndicatorValue}>
                    {camp.commonIndicatorValue}
                  </span>
                </div>

                {/* Timeline */}
                <div className="mt-3 flex items-center justify-between text-[11px] text-[#68809F]">
                  <span className="flex items-center gap-1">
                    <Calendar className="w-3 h-3" />
                    First Seen: {new Date(camp.firstSeen).toLocaleDateString()}
                  </span>
                  <span>Last Seen: {new Date(camp.lastSeen).toLocaleDateString()}</span>
                </div>
              </div>

              {/* Associated Cases */}
              <div className="mt-4 pt-4 border-t border-[#E5E9F2]">
                <div className="text-xs font-bold text-[#68809F] uppercase tracking-wider mb-2">
                  Emails in Campaign ({camp.caseCount}):
                </div>
                <div className="space-y-1.5">
                  {camp.cases.map((c) => (
                    <div
                      key={c.id}
                      onClick={() => navigate(`/investigation/${c.id}`)}
                      className="p-2 rounded-lg bg-[#F7F9FC] hover:bg-[#EEF4FF] cursor-pointer transition-colors flex items-center justify-between text-xs"
                    >
                      <div className="flex items-center gap-2 max-w-[280px] truncate">
                        <span className="font-mono font-bold text-[#246BFE]">{c.caseNumber}</span>
                        <span className="text-[#0B1F3A] truncate">{c.subject}</span>
                      </div>
                      <span className="font-mono text-xs font-bold text-[#EF4444]">
                        Score: {c.riskScore}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
