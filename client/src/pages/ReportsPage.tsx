import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FileSpreadsheet,
  Printer,
  Download,
  Eye,
  ShieldCheck,
  Calendar,
  FileCheck2,
  Lock,
  RefreshCw,
  ArrowLeft,
  Fingerprint,
  Globe2,
} from 'lucide-react';
import { ApiService } from '../services/api.js';
import type { ReportRecord, CaseRecord } from '../types.js';
import { RiskBadge } from '../components/common/RiskBadge.js';

export const ReportsPage: React.FC = () => {
  const navigate = useNavigate();
  const [reports, setReports] = useState<ReportRecord[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedReport, setSelectedReport] = useState<(ReportRecord & { data?: CaseRecord }) | null>(null);

  const loadReports = async () => {
    try {
      setLoading(true);
      const data = await ApiService.getReports();
      setReports(data);
    } catch (err) {
      console.error('Failed to load reports:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReports();
  }, []);

  const handleViewReport = async (reportId: string) => {
    try {
      const detailed = await ApiService.getReportById(reportId);
      setSelectedReport(detailed);
    } catch (err) {
      console.error('Failed to view report:', err);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadDossier = (report: ReportRecord) => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.dossierId}-forensic-dossier.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 no-print">
        <div>
          <h1 className="text-2xl font-bold text-[#0B1F3A] tracking-tight">Forensic Reports & Dossiers</h1>
          <p className="text-xs text-[#68809F] mt-1">
            Tamper-evident investigative dossiers sealed with cryptographic SHA-256 integrity hashes for legal chain of custody.
          </p>
        </div>
        <button
          onClick={loadReports}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-[#E5E9F2] text-[#0B1F3A] hover:bg-slate-50 rounded-xl text-xs font-semibold shadow-2xs transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-[#246BFE]' : ''}`} />
          <span>Refresh Dossiers</span>
        </button>
      </div>

      {/* Reports Table Required by Section 25 */}
      {!selectedReport && (
        <div className="bg-white rounded-xl border border-[#E5E9F2] shadow-[0_1px_3px_rgba(11,31,58,0.03)] overflow-hidden no-print">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#E5E9F2] bg-[#F7F9FC] text-[#68809F] font-bold">
                  <th className="py-3 px-4 uppercase text-[10px]">Dossier ID</th>
                  <th className="py-3 px-4 uppercase text-[10px]">Classification</th>
                  <th className="py-3 px-4 uppercase text-[10px]">Risk Score</th>
                  <th className="py-3 px-4 uppercase text-[10px]">Evidence SHA-256</th>
                  <th className="py-3 px-4 uppercase text-[10px]">Generated UTC</th>
                  <th className="py-3 px-4 uppercase text-[10px]">Size</th>
                  <th className="py-3 px-4 uppercase text-[10px] text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E5E9F2]">
                {reports.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-xs text-[#68809F]">
                      No reports currently generated. Run an email analysis to produce sealed forensic dossiers.
                    </td>
                  </tr>
                ) : (
                  reports.map((r) => (
                    <tr
                      key={r.id}
                      onClick={() => handleViewReport(r.id)}
                      className="hover:bg-[#F7F9FC] cursor-pointer transition-colors"
                    >
                      <td className="py-3.5 px-4 font-mono font-bold text-[#246BFE] whitespace-nowrap">
                        {r.dossierId}
                      </td>
                      <td className="py-3.5 px-4">
                        <RiskBadge score={r.riskScore} classification={r.classification} showScore={false} size="sm" />
                      </td>
                      <td className="py-3.5 px-4 font-mono font-bold text-[#0B1F3A]">
                        {r.riskScore}/100
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[#68809F] max-w-[200px] truncate" title={r.evidenceHash}>
                        {r.evidenceHash.substring(0, 16)}...
                      </td>
                      <td className="py-3.5 px-4 text-[#0B1F3A] whitespace-nowrap">
                        {new Date(r.generatedAt).toLocaleString()}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[#68809F]">
                        {(r.sizeBytes / 1024).toFixed(1)} KB
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => handleViewReport(r.id)}
                            className="p-1.5 rounded-lg border border-[#E5E9F2] hover:bg-slate-100 text-[#246BFE] transition-colors"
                            title="View Dossier"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => handleDownloadDossier(r)}
                            className="p-1.5 rounded-lg border border-[#E5E9F2] hover:bg-slate-100 text-[#0B1F3A] transition-colors"
                            title="Download JSON"
                          >
                            <Download className="w-3.5 h-3.5" />
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
      )}

      {/* Forensic Dossier Detailed Modal / View */}
      {selectedReport && (
        <div className="space-y-6">
          <div className="flex items-center justify-between no-print">
            <button
              onClick={() => setSelectedReport(null)}
              className="inline-flex items-center gap-1.5 text-xs font-bold text-[#246BFE] hover:underline"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Back to Reports List</span>
            </button>
            <div className="flex items-center gap-2">
              <button
                onClick={handlePrint}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-[#E5E9F2] text-[#0B1F3A] hover:bg-slate-50 rounded-xl text-xs font-semibold shadow-2xs transition-colors"
              >
                <Printer className="w-3.5 h-3.5 text-[#246BFE]" />
                <span>Print / Save as PDF</span>
              </button>
              <button
                onClick={() => handleDownloadDossier(selectedReport)}
                className="inline-flex items-center gap-1.5 px-4 py-2 bg-[#246BFE] hover:bg-blue-700 text-white rounded-xl text-xs font-bold shadow-sm shadow-blue-500/20 transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download Sealed Dossier</span>
              </button>
            </div>
          </div>

          {/* Dossier Document Container */}
          <div className="bg-white rounded-xl border border-[#E5E9F2] p-8 shadow-[0_1px_3px_rgba(11,31,58,0.03)] space-y-6 report-page">
            {/* Dossier Header */}
            <div className="border-b border-[#E5E9F2] pb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <span className="text-[10px] font-bold uppercase tracking-wider text-[#68809F] block">
                  DIGITAL FORENSIC INCIDENT DOSSIER
                </span>
                <h2 className="text-xl font-bold text-[#0B1F3A] mt-1 font-mono">
                  {selectedReport.dossierId}
                </h2>
                <div className="text-xs text-[#68809F] mt-1">
                  Investigation Target: {selectedReport.caseNumber}
                </div>
              </div>

              <div className="flex items-center gap-3">
                <RiskBadge score={selectedReport.riskScore} classification={selectedReport.classification} size="lg" />
              </div>
            </div>

            {/* Cryptographic Custody Seal */}
            <div className="p-4 bg-[#F7F9FC] border border-[#E5E9F2] rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-4 text-xs font-mono">
              <div>
                <span className="text-[#68809F] block text-[10px] uppercase font-bold">Evidence Payload SHA-256:</span>
                <span className="text-[#0B1F3A] break-all font-bold">{selectedReport.evidenceHash}</span>
              </div>
              <div className="flex items-center gap-2 text-emerald-800 bg-emerald-50 px-3 py-1.5 rounded-lg border border-emerald-200 self-start md:self-auto">
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
                <span className="font-bold">Cryptographically Sealed</span>
              </div>
            </div>

            {/* Section 1: Executive Summary */}
            <div className="space-y-2">
              <h3 className="text-xs font-bold uppercase tracking-wider text-[#0B1F3A] border-b border-[#E5E9F2] pb-1.5">
                1. Executive Summary & Synthesis
              </h3>
              <p className="text-xs text-[#0B1F3A] leading-relaxed">
                {selectedReport.summary}
              </p>
            </div>

            {/* Section 2: Claimed vs Observed Identity */}
            {selectedReport.data?.identityAnalysis && (
              <div className="space-y-2">
                <h3 className="text-xs font-bold uppercase tracking-wider text-[#0B1F3A] border-b border-[#E5E9F2] pb-1.5 flex items-center justify-between">
                  <span>2. Identity Consistency Audit</span>
                  <span className="text-[10px] font-mono text-[#246BFE]">
                    Rating: {selectedReport.data.identityAnalysis.consistency}
                  </span>
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                  <div className="p-3 bg-[#F7F9FC] rounded-lg border border-[#E5E9F2]">
                    <span className="text-[10px] uppercase font-bold text-[#68809F] block">Claimed Identity</span>
                    <div className="font-bold text-[#0B1F3A] mt-1">{selectedReport.data.identityAnalysis.claimed.displayName}</div>
                    <div className="font-mono text-[#68809F]">{selectedReport.data.identityAnalysis.claimed.email}</div>
                  </div>
                  <div className="p-3 bg-[#F7F9FC] rounded-lg border border-[#E5E9F2]">
                    <span className="text-[10px] uppercase font-bold text-[#68809F] block">Observed Technical Identity</span>
                    <div className="font-mono text-[#0B1F3A] mt-1">Return-Path: {selectedReport.data.identityAnalysis.observed.returnPath || 'N/A'}</div>
                    <div className="font-mono text-[#68809F]">Sending IP: {selectedReport.data.identityAnalysis.observed.sendingIp || 'N/A'}</div>
                  </div>
                </div>
              </div>
            )}

            {/* Section 3: Route Hops & Geolocation */}
            {selectedReport.data?.hops && (
              <div className="space-y-2">
                <h3 className="text-xs font-bold uppercase tracking-wider text-[#0B1F3A] border-b border-[#E5E9F2] pb-1.5">
                  3. Observed Transport Infrastructure
                </h3>
                <div className="p-2.5 bg-blue-50/70 border border-blue-200 rounded-lg text-[11px] text-blue-950">
                  IP geolocation represents approximate network infrastructure location. It does not prove the physical location or identity of the human sender.
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-[#E5E9F2] text-[#68809F] text-[10px] uppercase">
                        <th className="py-2">Hop</th>
                        <th className="py-2">Observed IP</th>
                        <th className="py-2">Jurisdiction</th>
                        <th className="py-2">Autonomous System</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#E5E9F2]">
                      {selectedReport.data.hops.map((hop) => (
                        <tr key={hop.hopNumber}>
                          <td className="py-2 font-mono">#{hop.hopNumber}</td>
                          <td className="py-2 font-mono font-bold text-[#246BFE]">{hop.ip || 'N/A'}</td>
                          <td className="py-2">{hop.isPrivate ? 'NON-PUBLIC IP' : `${hop.geo?.city ? hop.geo.city + ', ' : ''}${hop.geo?.country || 'Unknown'}`}</td>
                          <td className="py-2 text-[#68809F]">{hop.geo?.asn || 'Internal'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Section 4: Extracted IOCs */}
            {selectedReport.data?.iocs && selectedReport.data.iocs.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-xs font-bold uppercase tracking-wider text-[#0B1F3A] border-b border-[#E5E9F2] pb-1.5">
                  4. Actionable Indicators of Compromise (IOCs)
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                  {selectedReport.data.iocs.map((ioc, idx) => (
                    <div key={idx} className="p-2 bg-[#F7F9FC] rounded border border-[#E5E9F2] flex items-center justify-between">
                      <span className="font-mono text-[#0B1F3A] truncate max-w-[240px]">{ioc.value}</span>
                      <span className="px-1.5 py-0.5 rounded font-mono text-[9px] bg-slate-200 text-slate-700">
                        {ioc.type}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
