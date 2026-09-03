import React from 'react';
import {
  FileCheck2,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Hash,
  Info,
  Database,
} from 'lucide-react';
import type { CaseRecord, SecurityFinding } from '../../types.js';

interface EvidenceTabProps {
  caseData: CaseRecord;
}

export const EvidenceTab: React.FC<EvidenceTabProps> = ({ caseData }) => {
  const { findings, evidenceHash } = caseData;

  const getSeverityBadge = (severity: SecurityFinding['severity']) => {
    switch (severity) {
      case 'CRITICAL':
        return <span className="px-2.5 py-0.5 rounded text-[10px] font-extrabold bg-red-600 text-white font-mono">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-orange-100 text-orange-800 border border-orange-200 font-mono">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-800 border border-amber-200 font-mono">MEDIUM</span>;
      case 'LOW':
        return <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-slate-200 text-slate-700 font-mono">LOW</span>;
      case 'INFO':
      default:
        return <span className="px-2.5 py-0.5 rounded text-[10px] font-bold bg-blue-100 text-blue-700 border border-blue-200 font-mono">INFO</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Evidence Integrity Hash Header Card */}
      <div className="bg-slate-900 text-slate-200 rounded-xl p-6 border border-slate-800 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-bold text-blue-400 uppercase tracking-wider mb-1">
            <Hash className="w-4 h-4" />
            Cryptographic Evidence Integrity Seal (SHA-256)
          </div>
          <p className="font-mono text-xs text-slate-300 break-all select-all">
            {evidenceHash}
          </p>
        </div>
        <div className="text-right sm:self-auto self-start text-[11px] text-slate-400 bg-slate-950 px-3 py-1.5 rounded border border-slate-800 font-mono">
          SHA-256 Immutable Digest
        </div>
      </div>

      {/* Forensic Evidence Items Ledger */}
      <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
        <div className="pb-4 border-b border-slate-100 mb-6 flex items-center justify-between">
          <div>
            <h4 className="text-sm font-bold text-slate-900 tracking-wide flex items-center gap-2">
              <FileCheck2 className="w-4 h-4 text-blue-600" />
              Supporting Evidentiary Findings Ledger ({findings.length})
            </h4>
            <p className="text-xs text-slate-500 mt-0.5">
              Itemized technical artifacts with verifiable source, severity rating, and security impact explanation.
            </p>
          </div>
        </div>

        {findings.length === 0 ? (
          <div className="py-12 text-center text-slate-400 text-xs">
            No adverse forensic evidence detected in this case.
          </div>
        ) : (
          <div className="space-y-4">
            {findings.map((f, idx) => (
              <div
                key={idx}
                className="p-5 rounded-xl border border-slate-200 bg-slate-50/50 hover:bg-slate-50 transition-colors"
              >
                {/* Header row: Finding name, Source tag, Severity */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-200/70">
                  <div className="flex items-center gap-2.5">
                    <span className="w-6 h-6 rounded-md bg-slate-200 text-slate-700 font-bold text-[10px] flex items-center justify-center font-mono">
                      #{idx + 1}
                    </span>
                    <h5 className="text-xs font-bold text-slate-900 tracking-wide">
                      {f.title}
                    </h5>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 font-semibold">
                      Source: {f.source || 'Header analysis'}
                    </span>
                    {getSeverityBadge(f.severity)}
                  </div>
                </div>

                {/* Evidence Details */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3 text-xs">
                  <div>
                    <span className="text-[10px] font-bold text-slate-400 uppercase block mb-1">
                      Observed Technical Artifact
                    </span>
                    <div className="p-3 bg-white rounded-lg border border-slate-200 text-slate-800 font-mono break-all leading-relaxed select-all">
                      {f.observed}
                    </div>
                  </div>

                  <div>
                    <span className="text-[10px] font-bold text-slate-400 uppercase block mb-1">
                      Forensic Security Explanation
                    </span>
                    <div className="p-3 bg-white rounded-lg border border-slate-200 text-slate-700 leading-relaxed font-medium">
                      {f.impact}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
