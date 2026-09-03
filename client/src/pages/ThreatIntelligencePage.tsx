import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Crosshair,
  Search,
  Copy,
  Check,
  ExternalLink,
  Download,
  RefreshCw,
  Globe,
  Link,
  Hash,
  ShieldAlert,
  Server,
  Mail,
  AlertTriangle,
} from 'lucide-react';
import { ApiService } from '../services/api.js';

interface IndicatorRow {
  value: string;
  type: string;
  severity: string;
  count: number;
  cases: Array<{ id: string; caseNumber: string; riskScore: number }>;
  firstObserved: string;
  context: string;
}

const TYPE_META: Record<string, { icon: React.ReactNode; label: string; color: string }> = {
  IP:         { icon: <Server className="w-3.5 h-3.5" />,    label: 'IP Address',  color: 'bg-blue-50 text-blue-700 border-blue-200' },
  DOMAIN:     { icon: <Globe className="w-3.5 h-3.5" />,     label: 'Domain',      color: 'bg-purple-50 text-purple-700 border-purple-200' },
  URL:        { icon: <Link className="w-3.5 h-3.5" />,      label: 'URL',         color: 'bg-red-50 text-red-700 border-red-200' },
  HASH:       { icon: <Hash className="w-3.5 h-3.5" />,      label: 'File Hash',   color: 'bg-amber-50 text-amber-700 border-amber-200' },
  EMAIL:      { icon: <Mail className="w-3.5 h-3.5" />,      label: 'Email',       color: 'bg-slate-100 text-slate-700 border-slate-200' },
  ATTACHMENT: { icon: <AlertTriangle className="w-3.5 h-3.5" />, label: 'Attachment', color: 'bg-orange-50 text-orange-700 border-orange-200' },
};

export const ThreatIntelligencePage: React.FC = () => {
  const navigate = useNavigate();
  const [indicators, setIndicators] = useState<IndicatorRow[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [selectedType, setSelectedType] = useState<string>('ALL');
  const [copiedValue, setCopiedValue] = useState<string | null>(null);

  const loadIndicators = async () => {
    try {
      setLoading(true);
      const data = await ApiService.getIocs(searchTerm, selectedType);
      setIndicators(data);
    } catch (err) {
      console.error('Failed to load threat indicators:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIndicators();
  }, [searchTerm, selectedType]);

  const handleCopy = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedValue(val);
    setTimeout(() => setCopiedValue(null), 2000);
  };

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(indicators, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mailtrace-ioc-feed-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Summary counts
  const ipCount     = indicators.filter((i) => i.type === 'IP').length;
  const domainCount = indicators.filter((i) => i.type === 'DOMAIN').length;
  const urlCount    = indicators.filter((i) => i.type === 'URL').length;
  const hashCount   = indicators.filter((i) => i.type === 'HASH' || i.type === 'ATTACHMENT').length;

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL': return 'bg-red-50 text-red-700 border-red-200';
      case 'HIGH':     return 'bg-orange-50 text-orange-700 border-orange-200';
      case 'MEDIUM':   return 'bg-amber-50 text-amber-700 border-amber-200';
      default:         return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

  const getTypeMeta = (type: string) =>
    TYPE_META[type.toUpperCase()] ?? {
      icon: <Crosshair className="w-3.5 h-3.5" />,
      label: type,
      color: 'bg-slate-100 text-slate-700 border-slate-200',
    };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-[#EEF4FF] text-[#246BFE] flex items-center justify-center">
              <Crosshair className="w-4 h-4" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-[#0B1F3A] tracking-tight">Threat Intelligence</h1>
              <p className="text-xs text-[#68809F] mt-0.5">
                Observed IOCs auto-extracted from every analyzed email — IPs, domains, URLs, and file hashes.
              </p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadIndicators}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-[#E5E9F2] text-[#0B1F3A] hover:bg-slate-50 rounded-xl text-xs font-semibold shadow-2xs transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-[#246BFE]' : ''}`} />
            <span>Refresh</span>
          </button>
          <button
            onClick={handleExportJson}
            disabled={indicators.length === 0}
            className="inline-flex items-center gap-1.5 px-4 py-2 bg-[#246BFE] hover:bg-blue-700 disabled:opacity-40 text-white rounded-xl text-xs font-bold shadow-sm shadow-blue-500/20 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* IOC Category Summary Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Phishing URLs',     count: urlCount,    icon: <Link className="w-4 h-4" />,   bg: 'bg-red-50',    text: 'text-red-600',    desc: 'Credential harvest pages' },
          { label: 'Malicious Domains', count: domainCount, icon: <Globe className="w-4 h-4" />,  bg: 'bg-purple-50', text: 'text-purple-600', desc: 'Lookalikes & spoofed domains' },
          { label: 'Origin IPs',        count: ipCount,     icon: <Server className="w-4 h-4" />, bg: 'bg-[#EEF4FF]', text: 'text-[#246BFE]', desc: 'Observed sending infrastructure' },
          { label: 'File Hashes',       count: hashCount,   icon: <Hash className="w-4 h-4" />,   bg: 'bg-amber-50',  text: 'text-amber-600',  desc: 'SHA-256 attachment digests' },
        ].map(({ label, count, icon, bg, text, desc }) => (
          <div key={label} className="bg-white rounded-xl border border-[#E5E9F2] p-5 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">{label}</span>
              <div className={`w-8 h-8 rounded-lg ${bg} ${text} flex items-center justify-center`}>{icon}</div>
            </div>
            <div className={`text-3xl font-extrabold mt-3 font-mono ${text}`}>{count}</div>
            <p className="text-[11px] text-[#68809F] mt-1">{desc}</p>
          </div>
        ))}
      </div>

      {/* Search + Type Filter */}
      <div className="bg-white rounded-xl border border-[#E5E9F2] p-4 shadow-[0_1px_3px_rgba(11,31,58,0.03)] flex flex-col sm:flex-row gap-4 justify-between items-center">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-[#68809F] absolute left-3.5 top-2.5" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search IP, domain, URL, hash, context..."
            className="w-full pl-10 pr-4 py-2 rounded-xl bg-[#F7F9FC] border border-[#E5E9F2] text-xs text-[#0B1F3A] placeholder-[#68809F] focus:outline-none focus:ring-2 focus:ring-[#246BFE]/30"
          />
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {['ALL', 'IP', 'DOMAIN', 'URL', 'HASH', 'EMAIL', 'ATTACHMENT'].map((type) => (
            <button
              key={type}
              onClick={() => setSelectedType(type)}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${
                selectedType === type
                  ? 'bg-[#246BFE] text-white shadow-2xs'
                  : 'bg-[#F7F9FC] text-[#68809F] hover:text-[#0B1F3A] border border-[#E5E9F2]'
              }`}
            >
              {type}
            </button>
          ))}
        </div>
      </div>

      {/* Indicators Table */}
      <div className="bg-white rounded-xl border border-[#E5E9F2] shadow-[0_1px_3px_rgba(11,31,58,0.03)] overflow-hidden">
        <div className="p-5 border-b border-[#E5E9F2] flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-[#0B1F3A]">Observed IOC Feed</h3>
            <p className="text-xs text-[#68809F] mt-0.5">
              Auto-populated from analyzed emails. Click any case badge to investigate.
            </p>
          </div>
          {indicators.length > 0 && (
            <span className="px-2.5 py-1 bg-[#EEF4FF] text-[#246BFE] rounded-full text-xs font-bold font-mono border border-blue-100">
              {indicators.length} IOCs
            </span>
          )}
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#E5E9F2] bg-[#F7F9FC] text-[#68809F] font-bold">
                <th className="py-3 px-4 uppercase text-[10px]">Type</th>
                <th className="py-3 px-4 uppercase text-[10px]">Indicator</th>
                <th className="py-3 px-4 uppercase text-[10px]">Severity</th>
                <th className="py-3 px-4 uppercase text-[10px]">Occurrences</th>
                <th className="py-3 px-4 uppercase text-[10px]">Linked Cases</th>
                <th className="py-3 px-4 uppercase text-[10px]">First Observed</th>
                <th className="py-3 px-4 uppercase text-[10px]">Context</th>
                <th className="py-3 px-4 uppercase text-[10px] text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E5E9F2]">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-10 text-center text-xs text-[#68809F]">
                    <RefreshCw className="w-4 h-4 animate-spin text-[#246BFE] inline mr-2" />
                    Loading threat indicators...
                  </td>
                </tr>
              ) : indicators.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-16 text-center">
                    <div className="flex flex-col items-center justify-center space-y-3">
                      <div className="w-12 h-12 rounded-full bg-blue-50 text-[#246BFE] flex items-center justify-center">
                        <ShieldAlert className="w-6 h-6" />
                      </div>
                      <p className="font-semibold text-slate-800 text-sm">No threat indicators observed yet.</p>
                      <p className="text-slate-500 max-w-sm text-xs leading-relaxed">
                        Indicators of Compromise are automatically extracted when emails are analyzed.
                        Suspicious URLs, sending IPs, domains, and attachment hashes appear here.
                      </p>
                      <button
                        onClick={() => navigate('/analyze')}
                        className="mt-1 px-4 py-2 bg-[#246BFE] hover:bg-blue-700 text-white rounded-xl text-xs font-bold shadow-sm transition-colors"
                      >
                        Analyze an Email
                      </button>
                    </div>
                  </td>
                </tr>
              ) : (
                indicators.map((ioc, idx) => {
                  const meta = getTypeMeta(ioc.type);
                  return (
                    <tr key={idx} className="hover:bg-[#F7F9FC] transition-colors">
                      <td className="py-3 px-4">
                        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-mono font-bold text-[10px] border ${meta.color}`}>
                          {meta.icon}
                          {ioc.type}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono font-bold text-[#0B1F3A] max-w-[280px] truncate" title={ioc.value}>
                        {ioc.value}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${getSeverityBadge(ioc.severity)}`}>
                          {ioc.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 border border-slate-200 text-[10px] font-bold font-mono">
                          ×{ioc.count}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          {ioc.cases.slice(0, 3).map((c) => (
                            <button
                              key={c.id}
                              onClick={() => navigate(`/investigation/${c.id}`)}
                              className="font-mono text-[11px] text-[#246BFE] hover:underline bg-[#EEF4FF] px-1.5 py-0.5 rounded border border-blue-100"
                            >
                              {c.caseNumber}
                            </button>
                          ))}
                          {ioc.cases.length > 3 && (
                            <span className="text-[10px] text-[#68809F] font-mono">+{ioc.cases.length - 3}</span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-[#68809F] whitespace-nowrap">
                        {new Date(ioc.firstObserved).toLocaleDateString()}
                      </td>
                      <td className="py-3 px-4 text-[#68809F] max-w-[200px] truncate" title={ioc.context}>
                        {ioc.context}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => handleCopy(ioc.value)}
                            className="p-1.5 rounded-lg border border-[#E5E9F2] hover:bg-slate-100 text-[#68809F] hover:text-[#0B1F3A] transition-colors"
                            title="Copy IOC value"
                          >
                            {copiedValue === ioc.value ? (
                              <Check className="w-3.5 h-3.5 text-emerald-600" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                          {ioc.cases[0] && (
                            <button
                              onClick={() => navigate(`/investigation/${ioc.cases[0].id}`)}
                              className="p-1.5 rounded-lg border border-[#E5E9F2] hover:bg-slate-100 text-[#246BFE] transition-colors"
                              title="Investigate associated case"
                            >
                              <ExternalLink className="w-3.5 h-3.5" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
