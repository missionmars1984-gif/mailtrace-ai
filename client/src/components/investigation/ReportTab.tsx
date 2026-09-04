import React from 'react';
import {
  Printer,
  Download,
  ShieldAlert,
  ShieldCheck,
  Hash,
  FileText,
  CheckCircle2,
  AlertTriangle,
  Fingerprint,
  Info,
} from 'lucide-react';
import type { CaseRecord } from '../../types.js';
import { RiskBadge } from '../common/RiskBadge.js';

interface ReportTabProps {
  caseData: CaseRecord;
}

export const ReportTab: React.FC<ReportTabProps> = ({ caseData }) => {
  const {
    caseNumber,
    createdAt,
    metadata,
    classification,
    riskScore,
    riskLevel,
    confidence,
    summary,
    keyFindings,
    identityAnalysis,
    findings,
    urls,
    attachments,
    hops,
    iocs,
    aiAssessment,
    evidenceHash,
    reportHash,
  } = caseData;

  const originRelay =
    caseData.observedOriginRelay ||
    hops.find((h) => h.isPublicOriginRelay) ||
    hops.find((h) => h.ip && !h.isPrivate) ||
    hops[0] ||
    undefined;

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadJson = () => {
    const jsonStr = JSON.stringify(caseData, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ForensicReport-${caseNumber}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Print / Export Action Bar (Hidden on print) */}
      <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-3 print:hidden">
        <div className="flex items-center space-x-2 text-xs text-slate-600">
          <FileText className="w-4 h-4 text-blue-600" />
          <span className="font-semibold text-slate-900">Incident Dossier Ready</span>
          <span>• Certified forensic record #{caseNumber}</span>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={handleDownloadJson}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border border-slate-200 text-slate-700 hover:bg-slate-50 text-xs font-semibold shadow-sm transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-slate-500" />
            <span>Export JSON</span>
          </button>
          <button
            onClick={handlePrint}
            className="flex items-center space-x-1.5 px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-sm transition-colors"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print Forensic Report</span>
          </button>
        </div>
      </div>

      {/* Printable Forensic Report Container */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-8 sm:p-12 space-y-8 print:shadow-none print:border-none print:p-0">
        {/* Dossier Header */}
        <div className="flex flex-col sm:flex-row sm:items-start justify-between border-b-2 border-slate-900 pb-6 gap-4">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <ShieldCheck className="w-6 h-6 text-blue-600" />
              <h2 className="text-xl font-black tracking-tight text-slate-900">
                MAILTRACE AI FORENSIC INCIDENT DOSSIER
              </h2>
            </div>
            <p className="text-xs text-slate-500 uppercase tracking-widest font-mono">
              CONFIDENTIAL SECURITY OPERATIONS CENTER BRIEFING
            </p>
          </div>

          <div className="text-left sm:text-right font-mono text-xs">
            <div><strong>CASE ID:</strong> {caseNumber}</div>
            <div className="text-slate-500 mt-0.5"><strong>DATE:</strong> {new Date(createdAt).toUTCString()}</div>
            <div className="text-slate-500 mt-0.5"><strong>CLASSIFICATION:</strong> {classification.toUpperCase()}</div>
          </div>
        </div>

        {/* Section 1: Executive Threat Overview */}
        <section className="space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 border-b border-slate-200 pb-1.5">
            1. Threat Executive Summary & Risk Rating
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 text-center">
              <span className="text-[10px] font-bold text-slate-400 uppercase block">Threat Level</span>
              <div className="mt-1">
                <RiskBadge score={riskScore} level={riskLevel} classification={classification} size="lg" />
              </div>
            </div>
            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 text-center">
              <span className="text-[10px] font-bold text-slate-400 uppercase block">Composite Threat Score</span>
              <div className="text-2xl font-black font-mono mt-1 text-slate-900">
                {riskScore} <span className="text-sm font-normal text-slate-400">/ 100</span>
              </div>
            </div>
            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 text-center">
              <span className="text-[10px] font-bold text-slate-400 uppercase block">Diagnostic Confidence</span>
              <div className="text-2xl font-black font-mono mt-1 text-slate-900">
                {confidence}%
              </div>
            </div>
          </div>
          <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg text-xs leading-relaxed text-slate-800 space-y-2">
            <div>{summary}</div>
            {(caseData.threatTypes?.length || 0) > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-slate-200">
                <span className="text-[10px] font-bold text-slate-500 uppercase">Classified Threat Patterns:</span>
                {caseData.threatTypes?.map((t, idx) => (
                  <span key={idx} className="text-[10px] font-bold px-2 py-0.5 rounded bg-white border border-slate-300 text-slate-800">
                    {t}
                  </span>
                ))}
              </div>
            )}
          </div>
        </section>

        {/* Section 2: Email Metadata */}
        <section className="space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 border-b border-slate-200 pb-1.5">
            2. Transmission Envelope Metadata
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
            <div className="p-2.5 bg-slate-50 rounded border border-slate-200">
              <strong className="font-sans text-[10px] text-slate-400 uppercase block">From</strong>
              <span className="text-slate-900 break-all">{metadata.from.name ? `"${metadata.from.name}" <${metadata.from.address}>` : metadata.from.address}</span>
            </div>
            <div className="p-2.5 bg-slate-50 rounded border border-slate-200">
              <strong className="font-sans text-[10px] text-slate-400 uppercase block">To</strong>
              <span className="text-slate-900 break-all">{metadata.to.map(t => t.address).join(', ')}</span>
            </div>
            <div className="p-2.5 bg-slate-50 rounded border border-slate-200">
              <strong className="font-sans text-[10px] text-slate-400 uppercase block">Reply-To</strong>
              <span className="text-slate-900 break-all">{metadata.replyTo?.address || '(None)'}</span>
            </div>
            <div className="p-2.5 bg-slate-50 rounded border border-slate-200">
              <strong className="font-sans text-[10px] text-slate-400 uppercase block">Return-Path</strong>
              <span className="text-slate-900 break-all">{metadata.returnPath || '(None)'}</span>
            </div>
            <div className="p-2.5 bg-slate-50 rounded border border-slate-200 md:col-span-2">
              <strong className="font-sans text-[10px] text-slate-400 uppercase block">Subject</strong>
              <span className="text-slate-900 break-all font-sans font-bold">{metadata.subject !== undefined && metadata.subject !== '' ? metadata.subject : (metadata.subject === '' ? '(Empty Subject)' : '(No Subject)')}</span>
            </div>
          </div>
        </section>

        {/* Section 3: Claimed vs Observed Technical Identity */}
        <section className="space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 border-b border-slate-200 pb-1.5">
            3. Claimed vs Observed Technical Identity Correlation
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            <div className="p-3 rounded-lg border border-slate-200 bg-slate-50">
              <strong className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Claimed Identity</strong>
              <p><strong>Display Name:</strong> {identityAnalysis.claimed.displayName || 'None'}</p>
              <p className="font-mono mt-0.5"><strong>Address:</strong> {identityAnalysis.claimed.email}</p>
              <p className="font-mono mt-0.5"><strong>Domain:</strong> @{identityAnalysis.claimed.domain}</p>
            </div>
            <div className="p-3 rounded-lg border border-slate-200 bg-slate-50">
              <strong className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Observed Infrastructure</strong>
              <p className="font-mono"><strong>Return-Path:</strong> {identityAnalysis.observed.returnPath}</p>
              <p className="font-mono mt-0.5"><strong>Reply-To:</strong> {identityAnalysis.observed.replyTo}</p>
              <p className="font-mono mt-0.5"><strong>Origin Relay:</strong> {originRelay?.ip || identityAnalysis.observed.sendingIp || '(None detected)'}</p>
              <p className="font-mono mt-0.5">
                <strong>Relay Infrastructure:</strong>{' '}
                {originRelay?.geo?.country
                  ? `${originRelay.geo.city ? originRelay.geo.city + ', ' : ''}${originRelay.geo.country} (${originRelay.geo.asn || 'Public ASN'}${originRelay.geo.org ? ' ' + originRelay.geo.org : ''})`
                  : originRelay?.isPrivate
                  ? 'Internal / RFC 1918 Private'
                  : 'Unresolved'}
              </p>
            </div>
          </div>
          <p className="text-xs text-slate-700 bg-slate-50 p-3 rounded border border-slate-200">
            <strong>Identity Consistency Rating:</strong> <span className="font-bold">{identityAnalysis.consistency}</span>. {identityAnalysis.reasons.join(' ')}
          </p>
          <p className="text-[11px] text-slate-500 italic bg-blue-50/50 p-2.5 rounded border border-blue-100">
            <strong>Forensic Disclaimer:</strong> IP geolocation represents observed infrastructure and does not establish the physical location or identity of the sender.
          </p>
        </section>

        {/* Section 4: Authentication Telemetry */}
        <section className="space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 border-b border-slate-200 pb-1.5">
            4. Cryptographic Authentication & Alignment
          </h3>
          <div className="grid grid-cols-3 gap-3 text-xs text-center font-mono">
            <div className="p-3 rounded border border-slate-200 bg-slate-50">
              <span className="text-[10px] font-sans font-bold text-slate-400 block uppercase">SPF</span>
              <span className="font-bold text-sm block mt-1 uppercase">{metadata.auth?.spf?.status || 'UNKNOWN'}</span>
            </div>
            <div className="p-3 rounded border border-slate-200 bg-slate-50">
              <span className="text-[10px] font-sans font-bold text-slate-400 block uppercase">DKIM</span>
              <span className="font-bold text-sm block mt-1 uppercase">{metadata.auth?.dkim?.status || 'UNKNOWN'}</span>
            </div>
            <div className="p-3 rounded border border-slate-200 bg-slate-50">
              <span className="text-[10px] font-sans font-bold text-slate-400 block uppercase">DMARC</span>
              <span className="font-bold text-sm block mt-1 uppercase">{metadata.auth?.dmarc?.status || 'UNKNOWN'}</span>
            </div>
          </div>
        </section>

        {/* Section 5: Extracted Indicators of Compromise (IOC) */}
        <section className="space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 border-b border-slate-200 pb-1.5">
            5. Actionable Indicators of Compromise (IOC)
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono border-collapse">
              <thead>
                <tr className="border-b border-slate-200 text-slate-400 text-[10px]">
                  <th className="py-1.5 px-2">Type</th>
                  <th className="py-1.5 px-2">Artifact</th>
                  <th className="py-1.5 px-2">Context</th>
                  <th className="py-1.5 px-2">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {iocs.slice(0, 8).map((ioc, idx) => (
                  <tr key={idx}>
                    <td className="py-1.5 px-2 font-bold font-sans text-slate-700">{ioc.type}</td>
                    <td className="py-1.5 px-2 break-all text-slate-900">{ioc.value}</td>
                    <td className="py-1.5 px-2 text-slate-500 font-sans">{ioc.context}</td>
                    <td className="py-1.5 px-2 font-sans font-bold">{ioc.severity}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Section 6: Recommended Actions */}
        <section className="space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 border-b border-slate-200 pb-1.5">
            6. Prescribed Incident Response Actions
          </h3>
          <ul className="space-y-2 text-xs text-slate-800">
            {(
              (aiAssessment?.recommended_actions && aiAssessment.recommended_actions.length > 0
                ? aiAssessment.recommended_actions
                : caseData.recommendedAction
                ? [caseData.recommendedAction]
                : [
                    'Quarantine message and purge from recipient inbox.',
                    'Block originating sender address and envelope return path on perimeter security gateway.',
                    'Add extracted indicators of compromise to SOC firewall and proxy blocklists.',
                  ])
            ).map((act, idx) => (
              <li key={idx} className="flex items-start gap-2">
                <span className="w-4 h-4 rounded-full bg-slate-200 text-slate-800 flex items-center justify-center font-bold text-[10px] flex-shrink-0 mt-0.5">
                  {idx + 1}
                </span>
                <span className="leading-relaxed">{act}</span>
              </li>
            ))}
          </ul>
        </section>

        {/* Section 7: Cryptographic Forensic Integrity Block */}
        <section className="space-y-3 pt-6 border-t-2 border-slate-900">
          <div className="flex items-center gap-2 text-xs font-bold text-slate-900 uppercase">
            <Hash className="w-4 h-4 text-blue-600" />
            7. Chain of Custody & Forensic Evidence Integrity
          </div>
          <p className="text-xs text-slate-500">
            SHA-256 hash used to verify evidence integrity. Any tampering with the underlying evidentiary records invalidates this forensic seal.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
            <div className="p-3 bg-slate-50 rounded border border-slate-200 break-all">
              <strong className="text-[10px] text-slate-400 font-sans uppercase block mb-0.5">Evidence Payload Hash</strong>
              {evidenceHash}
            </div>
            <div className="p-3 bg-slate-50 rounded border border-slate-200 break-all">
              <strong className="text-[10px] text-slate-400 font-sans uppercase block mb-0.5">Report Integrity Hash</strong>
              {reportHash}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};
