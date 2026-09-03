import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Flame,
  ArrowUpRight,
  TrendingUp,
  RefreshCw,
  MailSearch,
  Inbox,
  Radio,
  FileCheck2,
  Lock,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area,
} from 'recharts';
import { ApiService } from '../services/api.js';
import type { DashboardStats } from '../types.js';
import { RiskBadge } from '../components/common/RiskBadge.js';

export const CommandCenter: React.FC = () => {
  const navigate = useNavigate();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);

  const loadStats = async () => {
    try {
      setRefreshing(true);
      const data = await ApiService.getDashboard();
      setStats(data);
    } catch (err) {
      console.error('Failed to load dashboard statistics:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadStats();
    const handleGlobalRefresh = () => loadStats();
    window.addEventListener('mailtrace:refresh', handleGlobalRefresh);
    return () => window.removeEventListener('mailtrace:refresh', handleGlobalRefresh);
  }, []);

  if (loading || !stats) {
    return (
      <div className="flex items-center justify-center min-h-[65vh]">
        <div className="flex items-center space-x-3 text-[#68809F] text-sm font-medium">
          <RefreshCw className="w-5 h-5 animate-spin text-[#246BFE]" />
          <span>Synchronizing Enterprise SOC Telemetry...</span>
        </div>
      </div>
    );
  }

  // Distribution chart data
  const riskChartData = [
    { name: 'Clean / Low Risk (0-40)', value: stats.riskDistribution.safe, color: '#10B981' },
    { name: 'Suspicious (41-60)', value: stats.riskDistribution.suspicious, color: '#F59E0B' },
    { name: 'High Risk (61-80)', value: stats.riskDistribution.highRisk, color: '#F97316' },
    { name: 'Critical (81-100)', value: stats.riskDistribution.critical, color: '#EF4444' },
  ].filter((d) => d.value > 0);

  const classChartData = [
    { name: 'Clean', count: stats.classificationDistribution.clean, fill: '#10B981' },
    { name: 'Phishing', count: stats.classificationDistribution.phishing, fill: '#EF4444' },
    { name: 'BEC', count: stats.classificationDistribution.bec, fill: '#F59E0B' },
    { name: 'Impersonation', count: stats.classificationDistribution.impersonation, fill: '#8B5CF6' },
    { name: 'Malware', count: stats.classificationDistribution.malware, fill: '#EC4899' },
    { name: 'Suspicious', count: stats.classificationDistribution.suspicious, fill: '#246BFE' },
  ];

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[#0B1F3A] tracking-tight">Enterprise Threat Dashboard</h1>
          <p className="text-xs text-[#68809F] mt-1">
            Real-time aggregate security posture, forensic extraction metrics, and automated risk scoring.
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={loadStats}
            disabled={refreshing}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-[#E5E9F2] text-[#0B1F3A] hover:bg-slate-50 rounded-xl text-xs font-semibold shadow-2xs transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-[#246BFE]' : ''}`} />
            <span>Sync Stats</span>
          </button>
          <button
            onClick={() => navigate('/analyze')}
            className="inline-flex items-center gap-2 px-4 py-2 bg-[#246BFE] hover:bg-blue-700 text-white rounded-xl text-xs font-bold shadow-sm shadow-blue-500/20 transition-colors"
          >
            <MailSearch className="w-4 h-4" />
            <span>Analyze New Email</span>
          </button>
        </div>
      </div>

      {/* Four Primary Cards - Perfectly Aligned */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        {/* Card 1: Total Scanned */}
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-5 shadow-[0_1px_3px_rgba(11,31,58,0.03)] hover:border-[#246BFE]/30 transition-all h-[136px] flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Total Scanned</span>
            <div className="w-8 h-8 rounded-lg bg-[#EEF4FF] text-[#246BFE] flex items-center justify-center shrink-0">
              <Inbox className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold text-[#0B1F3A] font-mono leading-none">
            {stats.totalScanned}
          </div>
          <p className="text-[11px] text-[#68809F] truncate">
            RFC822 emails analyzed
          </p>
        </div>

        {/* Card 2: Threats Detected */}
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-5 shadow-[0_1px_3px_rgba(11,31,58,0.03)] hover:border-[#F59E0B]/30 transition-all h-[136px] flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Threats Detected</span>
            <div className="w-8 h-8 rounded-lg bg-amber-50 text-[#F59E0B] flex items-center justify-center shrink-0">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold text-[#F59E0B] font-mono leading-none">
            {stats.threatsDetected}
          </div>
          <p className="text-[11px] text-[#68809F] truncate">
            {stats.totalScanned > 0
              ? `${Math.round((stats.threatsDetected / stats.totalScanned) * 100)}% of scanned volume`
              : 'Active threat vectors'}
          </p>
        </div>

        {/* Card 3: High / Critical */}
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-5 shadow-[0_1px_3px_rgba(11,31,58,0.03)] hover:border-[#EF4444]/30 transition-all h-[136px] flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">High / Critical</span>
            <div className="w-8 h-8 rounded-lg bg-red-50 text-[#EF4444] flex items-center justify-center shrink-0">
              <Flame className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold text-[#EF4444] font-mono leading-none">
            {stats.highRiskCount + stats.criticalCount}
          </div>
          <p className="text-[11px] text-[#68809F] truncate">
            Score ≥ 61 ({stats.criticalCount} Critical, {stats.highRiskCount} High)
          </p>
        </div>

        {/* Card 4: Quarantined */}
        <div
          onClick={() => navigate('/quarantine')}
          className="bg-white rounded-xl border border-[#E5E9F2] p-5 shadow-[0_1px_3px_rgba(11,31,58,0.03)] hover:border-red-300 hover:shadow-md transition-all cursor-pointer h-[136px] flex flex-col justify-between"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Quarantined</span>
            <div className="w-8 h-8 rounded-lg bg-red-50 text-red-600 flex items-center justify-center shrink-0">
              <Lock className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold text-red-600 font-mono leading-none">
            {stats.quarantined}
          </div>
          <p className="text-[11px] text-[#246BFE] font-semibold truncate flex items-center gap-0.5">
            View quarantine registry →
          </p>
        </div>
      </div>

      {/* Visual Analytics Grid: Threat Activity Trend & Threat Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Activity Trend (2 cols) */}
        <div className="lg:col-span-2 bg-white rounded-xl border border-[#E5E9F2] p-6 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
          <div className="flex items-center justify-between pb-4 border-b border-[#E5E9F2]">
            <div>
              <h3 className="text-sm font-bold text-[#0B1F3A] tracking-wide flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-[#246BFE]" />
                Threat Activity Trend
              </h3>
              <p className="text-xs text-[#68809F] mt-0.5">Chronological timeline of analyzed emails vs flagged threat payloads</p>
            </div>
          </div>

          <div className="h-64 mt-4">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats.threatActivityTrend} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="scannedGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#246BFE" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#246BFE" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#EF4444" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" stroke="#68809F" fontSize={11} tickLine={false} />
                <YAxis stroke="#68809F" fontSize={11} tickLine={false} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0B1F3A', borderRadius: '8px', border: 'none', color: '#fff', fontSize: '12px' }}
                />
                <Area type="monotone" dataKey="scanned" stroke="#246BFE" strokeWidth={2} fillOpacity={1} fill="url(#scannedGrad)" name="Total Scanned" />
                <Area type="monotone" dataKey="threats" stroke="#EF4444" strokeWidth={2} fillOpacity={1} fill="url(#threatGrad)" name="Threats Flagged" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Risk Severity Donut (1 col) */}
        <div className="bg-white rounded-xl border border-[#E5E9F2] p-6 shadow-[0_1px_3px_rgba(11,31,58,0.03)] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-[#E5E9F2]">
              <h3 className="text-sm font-bold text-[#0B1F3A]">Threat Severity Distribution</h3>
            </div>
            <div className="h-48 flex items-center justify-center mt-2">
              {riskChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={riskChartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={52}
                      outerRadius={75}
                      paddingAngle={3}
                      dataKey="value"
                    >
                      {riskChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0B1F3A', borderRadius: '8px', border: 'none', color: '#fff', fontSize: '12px' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="text-xs text-[#68809F]">No case data available</div>
              )}
            </div>
          </div>

          <div className="space-y-1.5 pt-3 border-t border-[#E5E9F2] text-xs">
            <div className="flex items-center justify-between text-slate-700">
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-emerald-500" /> Clean / Low (0–40)</span>
              <span className="font-bold font-mono">{stats.riskDistribution.safe}</span>
            </div>
            <div className="flex items-center justify-between text-slate-700">
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-amber-500" /> Suspicious (41–60)</span>
              <span className="font-bold font-mono">{stats.riskDistribution.suspicious}</span>
            </div>
            <div className="flex items-center justify-between text-slate-700">
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-orange-500" /> High Risk (61–80)</span>
              <span className="font-bold font-mono">{stats.riskDistribution.highRisk}</span>
            </div>
            <div className="flex items-center justify-between text-slate-700">
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-red-500" /> Critical (81–100)</span>
              <span className="font-bold font-mono">{stats.riskDistribution.critical}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Threat Classification Breakdown */}
      <div className="bg-white rounded-xl border border-[#E5E9F2] p-6 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
        <div className="flex items-center justify-between pb-4 border-b border-[#E5E9F2]">
          <div>
            <h3 className="text-sm font-bold text-[#0B1F3A] tracking-wide">Threat Classification Matrix</h3>
            <p className="text-xs text-[#68809F] mt-0.5">Categorization across Clean, Phishing, BEC, Impersonation, and Malware payloads</p>
          </div>
        </div>
        <div className="h-44 mt-4">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={classChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <XAxis dataKey="name" stroke="#68809F" fontSize={11} tickLine={false} />
              <YAxis stroke="#68809F" fontSize={11} tickLine={false} allowDecimals={false} />
              <Tooltip
                contentStyle={{ backgroundColor: '#0B1F3A', borderRadius: '8px', border: 'none', color: '#fff', fontSize: '12px' }}
                cursor={{ fill: 'rgba(238, 244, 255, 0.4)' }}
              />
              <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                {classChartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent Investigations Table */}
      <div className="bg-white rounded-xl border border-[#E5E9F2] shadow-[0_1px_3px_rgba(11,31,58,0.03)] overflow-hidden">
        <div className="p-6 border-b border-[#E5E9F2] flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-[#0B1F3A] tracking-wide">Recent Case Investigations</h3>
            <p className="text-xs text-[#68809F] mt-0.5">Click any investigation to review envelope evidence, route hops, and forensic report.</p>
          </div>
          <button
            onClick={() => navigate('/cases')}
            className="text-xs font-bold text-[#246BFE] hover:underline flex items-center gap-1"
          >
            <span>View All Cases</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#E5E9F2] bg-[#F7F9FC] text-[#68809F] font-bold">
                <th className="py-3 px-4 uppercase text-[10px]">Case ID</th>
                <th className="py-3 px-4 uppercase text-[10px]">Claimed Sender</th>
                <th className="py-3 px-4 uppercase text-[10px]">Subject</th>
                <th className="py-3 px-4 uppercase text-[10px]">Classification</th>
                <th className="py-3 px-4 uppercase text-[10px]">Risk Score</th>
                <th className="py-3 px-4 uppercase text-[10px]">Status</th>
                <th className="py-3 px-4 uppercase text-[10px] text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E5E9F2]">
              {stats.recentCases.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-xs text-slate-500">
                    <div className="flex flex-col items-center justify-center space-y-3">
                      <div className="w-10 h-10 rounded-full bg-blue-50 text-blue-600 flex items-center justify-center">
                        <MailSearch className="w-5 h-5" />
                      </div>
                      <p className="font-semibold text-slate-800 text-sm">No forensic investigations recorded yet</p>
                      <p className="text-slate-500 max-w-sm">
                        The database is clean and ready. Analyze an email to start forensic threat investigation.
                      </p>
                      <button
                        onClick={() => navigate('/analyze')}
                        className="mt-1 px-4 py-2 bg-[#246BFE] hover:bg-blue-700 text-white rounded-xl text-xs font-bold shadow-sm transition-colors"
                      >
                        Analyze an Email Now
                      </button>
                    </div>
                  </td>
                </tr>
              ) : (
                stats.recentCases.map((c) => (
                  <tr
                    key={c.id}
                    onClick={() => navigate(`/investigation/${c.id}`)}
                    className="hover:bg-[#F7F9FC] cursor-pointer transition-colors"
                  >
                    <td className="py-3.5 px-4 font-mono font-bold text-[#246BFE] whitespace-nowrap">
                      {c.caseNumber}
                    </td>
                    <td className="py-3.5 px-4 font-medium text-[#0B1F3A] max-w-[200px] truncate" title={c.from}>
                      {c.from}
                    </td>
                    <td className="py-3.5 px-4 text-[#0B1F3A] max-w-[280px] truncate font-medium" title={c.subject}>
                      {c.subject}
                    </td>
                    <td className="py-3.5 px-4">
                      <RiskBadge score={c.riskScore} classification={c.classification} showScore={false} size="sm" />
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-[#0B1F3A] w-6">{c.riskScore}</span>
                        <div className="w-16 bg-[#E5E9F2] h-1.5 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              c.riskScore >= 81
                                ? 'bg-red-500'
                                : c.riskScore >= 61
                                ? 'bg-orange-500'
                                : c.riskScore >= 41
                                ? 'bg-amber-500'
                                : 'bg-emerald-500'
                            }`}
                            style={{ width: `${Math.max(4, c.riskScore)}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`px-2 py-0.5 rounded-full font-mono text-[10px] font-bold border ${
                          c.status === 'Quarantined'
                            ? 'bg-red-50 text-red-700 border-red-200'
                            : c.status === 'Under Review'
                            ? 'bg-amber-50 text-amber-700 border-amber-200'
                            : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        }`}
                      >
                        {c.status}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <span className="text-[#246BFE] font-bold text-xs flex items-center justify-end gap-1 hover:underline">
                        Investigate ➔
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
