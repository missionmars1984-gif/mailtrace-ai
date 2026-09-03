import React, { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Lock,
  RefreshCw,
  AlertTriangle,
  Flame,
  ShieldAlert,
  ExternalLink,
  Search,
  Filter,
  CheckCircle2,
} from 'lucide-react';
import { ApiService } from '../services/api.js';
import type { CaseRecord } from '../types.js';
import { RiskBadge } from '../components/common/RiskBadge.js';

/** Determines if a case should be quarantined */
function isQuarantined(c: CaseRecord): boolean {
  if (c.riskScore >= 80) return true;
  if (c.riskScore >= 61 && ['Phishing', 'BEC', 'Malware'].includes(c.classification)) return true;
  return false;
}

/** Returns the quarantine reason based on case evidence */
function getQuarantineReason(c: CaseRecord): string {
  if (c.riskScore >= 95) return 'Critical threat payload — automatic block';
  if (c.classification === 'Phishing' && c.riskScore >= 80) return 'Active phishing credential harvester';
  if (c.classification === 'BEC' && c.riskScore >= 80) return 'Business Email Compromise pattern detected';
  if (c.classification === 'Malware') return 'Malware / dangerous attachment payload';
  if (c.riskScore >= 80) return 'Risk score exceeds critical threshold (≥80)';
  if (c.classification === 'Phishing') return 'Phishing indicators exceed high-risk threshold';
  if (c.classification === 'BEC') return 'BEC indicators exceed high-risk threshold';
  return 'Multiple high-severity threat signals';
}

/** Returns the display status for a quarantined case */
function getQuarantineStatus(c: CaseRecord): 'Quarantined' | 'Released' {
  // Future: persist release status; for now all quarantined cases remain quarantined
  return 'Quarantined';
}

const STATUS_STYLES: Record<string, string> = {
  Quarantined: 'bg-red-50 text-red-700 border border-red-200',
  Released: 'bg-emerald-50 text-emerald-700 border border-emerald-200',
};

export const QuarantinePage: React.FC = () => {
  const navigate = useNavigate();
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState<string>('ALL');
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const loadCases = async () => {
    try {
      setRefreshing(true);
      const quarantined = await ApiService.getQuarantine();
      setCases(quarantined);
    } catch (err) {
      console.error('Failed to load quarantined emails:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const handleRelease = async (e: React.MouseEvent, caseId: string) => {
    e.stopPropagation();
    try {
      setActionLoading(caseId);
      await ApiService.releaseQuarantinedCase(caseId, 'Analyst authorized release from quarantine');
      await loadCases();
    } catch (err) {
      console.error('Failed to release case:', err);
    } finally {
      setActionLoading(null);
    }
  };

  useEffect(() => {
    loadCases();
    const handleRefresh = () => loadCases();
    window.addEventListener('mailtrace:refresh', handleRefresh);
    return () => window.removeEventListener('mailtrace:refresh', handleRefresh);
  }, []);

  const filtered = useMemo(() => {
    let list = cases;
    if (filterType !== 'ALL') {
      list = list.filter((c) => c.classification === filterType);
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(
        (c) =>
          c.metadata.from.address.toLowerCase().includes(q) ||
          (c.metadata.from.name || '').toLowerCase().includes(q) ||
          c.metadata.subject.toLowerCase().includes(q) ||
          c.caseNumber.toLowerCase().includes(q)
      );
    }
    return list;
  }, [cases, search, filterType]);

  const classificationTypes = useMemo(() => {
    const types = new Set(cases.map((c) => c.classification));
    return Array.from(types);
  }, [cases]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[65vh]">
        <div className="flex items-center space-x-3 text-[#68809F] text-sm font-medium">
          <RefreshCw className="w-5 h-5 animate-spin text-[#246BFE]" />
          <span>Loading quarantined emails...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-red-50 text-red-600 flex items-center justify-center">
              <Lock className="w-4 h-4" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-[#0B1F3A] tracking-tight">Quarantine</h1>
              <p className="text-xs text-[#68809F] mt-0.5">
                Isolated high-risk and critical threat emails pending analyst review.
              </p>
            </div>
          </div>
        </div>
        <button
          onClick={loadCases}
          disabled={refreshing}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-[#E5E9F2] text-[#0B1F3A] hover:bg-slate-50 rounded-xl text-xs font-semibold shadow-2xs transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-[#246BFE]' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Stats Strip */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-4 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
          <div className="flex items-center gap-2 mb-1">
            <Flame className="w-4 h-4 text-red-500" />
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Total Quarantined</span>
          </div>
          <div className="text-2xl font-extrabold text-[#EF4444] font-mono">{cases.length}</div>
        </div>
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-4 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
          <div className="flex items-center gap-2 mb-1">
            <ShieldAlert className="w-4 h-4 text-orange-500" />
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Critical (≥81)</span>
          </div>
          <div className="text-2xl font-extrabold text-orange-600 font-mono">
            {cases.filter((c) => c.riskScore >= 81).length}
          </div>
        </div>
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-4 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
          <div className="flex items-center gap-2 mb-1">
            <AlertTriangle className="w-4 h-4 text-amber-500" />
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">High Risk (61–80)</span>
          </div>
          <div className="text-2xl font-extrabold text-amber-600 font-mono">
            {cases.filter((c) => c.riskScore >= 61 && c.riskScore < 81).length}
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#68809F]" />
          <input
            type="text"
            placeholder="Search sender, subject, case ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-2 bg-white border border-[#E5E9F2] rounded-xl text-xs text-[#0B1F3A] placeholder-[#68809F] focus:outline-none focus:ring-2 focus:ring-[#246BFE]/20 focus:border-[#246BFE]"
          />
        </div>
        <div className="relative">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#68809F]" />
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="pl-9 pr-8 py-2 bg-white border border-[#E5E9F2] rounded-xl text-xs text-[#0B1F3A] focus:outline-none focus:ring-2 focus:ring-[#246BFE]/20 focus:border-[#246BFE] appearance-none"
          >
            <option value="ALL">All Threat Types</option>
            {classificationTypes.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Main Table */}
      <div className="bg-white rounded-xl border border-[#E5E9F2] shadow-[0_1px_3px_rgba(11,31,58,0.03)] overflow-hidden">
        <div className="p-5 border-b border-[#E5E9F2] flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-[#0B1F3A]">Quarantined Email Registry</h3>
            <p className="text-xs text-[#68809F] mt-0.5">
              Click any row to open the full forensic investigation.
            </p>
          </div>
          {filtered.length !== cases.length && (
            <span className="text-xs text-[#68809F] font-medium">
              Showing {filtered.length} of {cases.length}
            </span>
          )}
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#E5E9F2] bg-[#F7F9FC] text-[#68809F] font-bold">
                <th className="py-3 px-4 uppercase text-[10px]">Case ID</th>
                <th className="py-3 px-4 uppercase text-[10px]">Sender</th>
                <th className="py-3 px-4 uppercase text-[10px]">Recipient</th>
                <th className="py-3 px-4 uppercase text-[10px]">Subject</th>
                <th className="py-3 px-4 uppercase text-[10px]">Threat Type</th>
                <th className="py-3 px-4 uppercase text-[10px]">Risk</th>
                <th className="py-3 px-4 uppercase text-[10px]">Date / Time</th>
                <th className="py-3 px-4 uppercase text-[10px]">Quarantine Reason</th>
                <th className="py-3 px-4 uppercase text-[10px]">Status</th>
                <th className="py-3 px-4 uppercase text-[10px] text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E5E9F2]">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-16 text-center">
                    <div className="flex flex-col items-center justify-center space-y-3">
                      <div className="w-12 h-12 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center">
                        <CheckCircle2 className="w-6 h-6" />
                      </div>
                      {cases.length === 0 ? (
                        <>
                          <p className="font-semibold text-slate-800 text-sm">No quarantined emails yet</p>
                          <p className="text-slate-500 max-w-sm text-xs leading-relaxed">
                            Emails with a risk score of 80 or higher, or high-risk phishing/BEC/malware
                            classifications above 61, are automatically quarantined here after analysis.
                          </p>
                          <button
                            onClick={() => navigate('/analyze')}
                            className="mt-1 px-4 py-2 bg-[#246BFE] hover:bg-blue-700 text-white rounded-xl text-xs font-bold shadow-sm transition-colors"
                          >
                            Analyze an Email
                          </button>
                        </>
                      ) : (
                        <>
                          <p className="font-semibold text-slate-800 text-sm">No results match your filter</p>
                          <p className="text-slate-500 text-xs">
                            Try adjusting your search or clearing the threat type filter.
                          </p>
                          <button
                            onClick={() => { setSearch(''); setFilterType('ALL'); }}
                            className="mt-1 px-4 py-2 bg-white border border-[#E5E9F2] text-[#0B1F3A] hover:bg-slate-50 rounded-xl text-xs font-semibold transition-colors"
                          >
                            Clear Filters
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ) : (
                filtered.map((c) => {
                  const sender = c.metadata.from.name
                    ? `${c.metadata.from.name} <${c.metadata.from.address}>`
                    : c.metadata.from.address;
                  const recipient = c.metadata.to?.[0]?.address || '—';
                  const reason = getQuarantineReason(c);
                  const status = getQuarantineStatus(c);
                  const date = new Date(c.createdAt);
                  return (
                    <tr
                      key={c.id}
                      onClick={() => navigate(`/investigation/${c.id}`)}
                      className="hover:bg-[#F7F9FC] cursor-pointer transition-colors"
                    >
                      <td className="py-3 px-4 font-mono font-bold text-[#246BFE] whitespace-nowrap">
                        {c.caseNumber}
                      </td>
                      <td className="py-3 px-4 max-w-[180px]">
                        <span className="block truncate font-medium text-[#0B1F3A]" title={sender}>
                          {sender}
                        </span>
                      </td>
                      <td className="py-3 px-4 max-w-[140px]">
                        <span className="block truncate text-[#68809F]" title={recipient}>
                          {recipient}
                        </span>
                      </td>
                      <td className="py-3 px-4 max-w-[220px]">
                        <span className="block truncate font-medium text-[#0B1F3A]" title={c.metadata.subject}>
                          {c.metadata.subject}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <RiskBadge score={c.riskScore} classification={c.classification} showScore={false} size="sm" />
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <span
                            className={`font-mono font-bold ${
                              c.riskScore >= 81 ? 'text-red-600' : 'text-orange-600'
                            }`}
                          >
                            {c.riskScore}
                          </span>
                          <div className="w-14 bg-[#E5E9F2] h-1.5 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                c.riskScore >= 81 ? 'bg-red-500' : 'bg-orange-500'
                              }`}
                              style={{ width: `${c.riskScore}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap text-[#68809F]">
                        <div>{date.toLocaleDateString()}</div>
                        <div className="text-[10px] font-mono">{date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</div>
                      </td>
                      <td className="py-3 px-4 max-w-[200px]">
                        <span className="block truncate text-[#68809F]" title={reason}>
                          {reason}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded-full text-[10px] font-bold font-mono ${STATUS_STYLES[status] || 'bg-slate-100 text-slate-600'}`}
                        >
                          {status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={(e) => handleRelease(e, c.id)}
                            disabled={actionLoading === c.id}
                            className="px-2.5 py-1 text-[11px] font-bold text-emerald-700 bg-emerald-50 hover:bg-emerald-100 border border-emerald-200 rounded-lg transition-colors"
                          >
                            {actionLoading === c.id ? 'Releasing...' : 'Release'}
                          </button>
                          <button
                            onClick={() => navigate(`/investigation/${c.id}`)}
                            className="px-2.5 py-1 text-[11px] font-bold text-[#246BFE] bg-blue-50 hover:bg-blue-100 border border-blue-200 rounded-lg transition-colors flex items-center gap-1"
                          >
                            Investigate
                            <ExternalLink className="w-3 h-3" />
                          </button>
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
