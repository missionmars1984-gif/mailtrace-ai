import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FolderArchive,
  Search,
  Filter,
  ExternalLink,
  ShieldAlert,
  Calendar,
  FileSpreadsheet,
  RefreshCw,
  ArrowUpRight,
  Trash2,
} from 'lucide-react';
import { ApiService } from '../services/api.js';
import type { CaseRecord } from '../types.js';
import { RiskBadge } from '../components/common/RiskBadge.js';

export const ForensicCasesPage: React.FC = () => {
  const navigate = useNavigate();
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [selectedClass, setSelectedClass] = useState<string>('ALL');

  const loadCases = async () => {
    try {
      setLoading(true);
      const data = await ApiService.getCases(searchTerm, selectedClass);
      setCases(data);
    } catch (err) {
      console.error('Failed to load cases:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteCase = async (id: string, caseNumber: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (window.confirm(`Are you sure you want to delete Case ${caseNumber}?`)) {
      try {
        await ApiService.deleteCase(id);
        await loadCases();
      } catch (err) {
        console.error('Failed to delete case:', err);
        alert('Could not delete case.');
      }
    }
  };

  const handleClearAll = async () => {
    if (window.confirm('Are you sure you want to delete all cases from the registry?')) {
      try {
        await ApiService.deleteAllCases();
        await loadCases();
      } catch (err) {
        console.error('Failed to clear cases:', err);
        alert('Could not clear cases.');
      }
    }
  };

  useEffect(() => {
    loadCases();
  }, [searchTerm, selectedClass]);

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[#0B1F3A] tracking-tight">Forensic Cases Registry</h1>
          <p className="text-xs text-[#68809F] mt-1">
            Complete database of opened digital forensic investigations, active triage states, and custody manifests.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadCases}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-[#E5E9F2] text-[#0B1F3A] hover:bg-slate-50 rounded-xl text-xs font-semibold shadow-2xs transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-[#246BFE]' : ''}`} />
            <span>Refresh</span>
          </button>
          {cases.length > 0 && (
            <button
              onClick={handleClearAll}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-red-200 text-red-600 hover:bg-red-50 rounded-xl text-xs font-semibold transition-colors"
              title="Delete all cases in registry"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear Registry</span>
            </button>
          )}
          <button
            onClick={() => navigate('/reports')}
            className="inline-flex items-center gap-1.5 px-4 py-2 bg-white border border-[#246BFE] text-[#246BFE] hover:bg-[#EEF4FF] rounded-xl text-xs font-bold transition-colors"
          >
            <FileSpreadsheet className="w-3.5 h-3.5" />
            <span>View Reports</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-white rounded-xl border border-[#E5E9F2] p-4 shadow-[0_1px_3px_rgba(11,31,58,0.03)] flex flex-col sm:flex-row gap-4 justify-between items-center">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-[#68809F] absolute left-3.5 top-3" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by Case ID, sender, subject, IP..."
            className="w-full pl-10 pr-4 py-2 rounded-xl bg-[#F7F9FC] border border-[#E5E9F2] text-xs text-[#0B1F3A] placeholder-[#68809F] focus:outline-none focus:ring-2 focus:ring-[#246BFE]/30"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto overflow-x-auto">
          {['ALL', 'Clean', 'Phishing', 'BEC', 'Impersonation', 'Malware', 'Suspicious'].map((cls) => (
            <button
              key={cls}
              onClick={() => setSelectedClass(cls)}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${
                selectedClass === cls
                  ? 'bg-[#246BFE] text-white shadow-2xs'
                  : 'bg-[#F7F9FC] text-[#68809F] hover:text-[#0B1F3A] border border-[#E5E9F2]'
              }`}
            >
              {cls}
            </button>
          ))}
        </div>
      </div>

      {/* Cases Table */}
      <div className="bg-white rounded-xl border border-[#E5E9F2] shadow-[0_1px_3px_rgba(11,31,58,0.03)] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#E5E9F2] bg-[#F7F9FC] text-[#68809F] font-bold">
                <th className="py-3 px-4 uppercase text-[10px]">Case ID</th>
                <th className="py-3 px-4 uppercase text-[10px]">Severity</th>
                <th className="py-3 px-4 uppercase text-[10px]">Investigation Title</th>
                <th className="py-3 px-4 uppercase text-[10px]">Linked Sender Email</th>
                <th className="py-3 px-4 uppercase text-[10px]">Lead Analyst</th>
                <th className="py-3 px-4 uppercase text-[10px]">Status</th>
                <th className="py-3 px-4 uppercase text-[10px] text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E5E9F2]">
              {cases.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-xs text-[#68809F]">
                    No cases match the given filter criteria.
                  </td>
                </tr>
              ) : (
                cases.map((c) => (
                  <tr
                    key={c.id}
                    onClick={() => navigate(`/investigation/${c.id}`)}
                    className="hover:bg-[#F7F9FC] cursor-pointer transition-colors"
                  >
                    <td className="py-3.5 px-4 font-mono font-bold text-[#246BFE] whitespace-nowrap">
                      {c.caseNumber}
                    </td>
                    <td className="py-3.5 px-4">
                      <RiskBadge score={c.riskScore} classification={c.classification} showScore={false} size="sm" />
                    </td>
                    <td className="py-3.5 px-4 font-medium text-[#0B1F3A] max-w-[260px] truncate" title={c.metadata.subject}>
                      {c.metadata.subject}
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[#68809F] max-w-[200px] truncate" title={c.metadata.from.address}>
                      {c.metadata.from.address}
                    </td>
                    <td className="py-3.5 px-4 text-[#0B1F3A] font-medium whitespace-nowrap">
                      SOC Auto-Triage
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded-full bg-slate-100 text-slate-800 text-[10px] font-mono border border-slate-200">
                        OPEN TRIAGE
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <div className="inline-flex items-center gap-1.5 justify-end">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/investigation/${c.id}`);
                          }}
                          className="px-2.5 py-1 text-xs font-bold text-[#246BFE] hover:bg-[#EEF4FF] rounded-lg transition-colors inline-flex items-center gap-1"
                        >
                          <span>Investigate</span>
                          <ArrowUpRight className="w-3 h-3" />
                        </button>
                        <button
                          onClick={(e) => handleDeleteCase(c.id, c.caseNumber, e)}
                          className="p-1 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                          title="Delete Case"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
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
