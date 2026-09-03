import React, { useState } from 'react';
import {
  Link2,
  ExternalLink,
  Copy,
  Check,
  Globe,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import type { CaseRecord } from '../../types.js';

interface UrlsTabProps {
  caseData: CaseRecord;
}

export const UrlsTab: React.FC<UrlsTabProps> = ({ caseData }) => {
  const { urls, identityAnalysis, metadata } = caseData;
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Extract all distinct domains (from sender and all extracted URLs)
  const senderDomain: string = metadata.from?.domain || (metadata.from?.address ? metadata.from.address.split('@')[1] || '' : '');
  const uniqueDomains: string[] = Array.from(
    new Set([senderDomain, ...urls.map((u) => u.domain)].filter((d): d is string => typeof d === 'string' && d.length > 0))
  );

  return (
    <div className="space-y-6">
      {/* 1. Domain Forensic Analysis Card */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-sm">
        <div className="p-5 border-b border-slate-200 bg-slate-50/70 flex items-center justify-between">
          <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
            <Globe className="w-4 h-4 text-blue-600" />
            Observed Domain Forensics & Typosquatting Analysis
          </h4>
          <span className="text-xs text-slate-500 font-mono">
            {uniqueDomains.length} Distinct Domain(s) Identified
          </span>
        </div>

        <div className="divide-y divide-slate-100">
          {uniqueDomains.map((dom: string, idx: number) => {
            const isSenderDomain = dom === senderDomain;
            const isLookalike = Boolean(isSenderDomain && identityAnalysis.lookalikeDomain);
            const isPunycode = Boolean((dom && dom.startsWith('xn--')) || (isSenderDomain && identityAnalysis.punycodeDetected));
            const isSenderMismatch = Boolean(isSenderDomain && (identityAnalysis.replyToMismatch || identityAnalysis.returnPathMismatch));

            return (
              <div key={idx} className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-slate-50/50 transition-colors">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-sm text-slate-900">{dom}</span>
                    {isSenderDomain && (
                      <span className="text-[10px] uppercase font-mono font-bold bg-blue-100 text-blue-800 px-2 py-0.5 rounded">
                        Sender Host Domain
                      </span>
                    )}
                  </div>
                  <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 pt-1">
                    <span>
                      Lookalike Status:{' '}
                      <strong className={isLookalike ? 'text-red-600' : 'text-slate-700'}>
                        {isLookalike ? `Targeting ${identityAnalysis.lookalikeTarget}` : 'Negative'}
                      </strong>
                    </span>
                    <span>•</span>
                    <span>
                      Punycode / Homoglyph:{' '}
                      <strong className={isPunycode ? 'text-red-600' : 'text-slate-700'}>
                        {isPunycode ? 'Detected' : 'Negative'}
                      </strong>
                    </span>
                    <span>•</span>
                    <span>
                      Envelope Mismatch:{' '}
                      <strong className={isSenderMismatch ? 'text-amber-600' : 'text-slate-700'}>
                        {isSenderMismatch ? 'Divergent' : 'Aligned'}
                      </strong>
                    </span>
                  </div>
                </div>

                <div>
                  {isLookalike || isPunycode ? (
                    <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-bold bg-red-100 text-red-800 border border-red-300">
                      <XCircle className="w-3.5 h-3.5" /> High Deception Risk
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800 border border-emerald-300">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Normal Syntax
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 2. Extracted URLs Table */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-sm">
        <div className="px-6 py-4 border-b border-slate-100 bg-slate-50 flex items-center justify-between">
          <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
            <Link2 className="w-4 h-4 text-blue-600" />
            Extracted Technical Hyperlinks & Anchors ({urls.length})
          </h4>
          <span className="text-xs text-slate-500 font-mono">
            Source: URL analysis
          </span>
        </div>

        {urls.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-400">
            No hyperlinks, web anchors, or external endpoints detected in the email body.
          </div>
        ) : (
          <div className="divide-y divide-slate-100">
            {urls.map((u, idx) => {
              const isHigh = u.riskLevel === 'HIGH';
              const isMed = u.riskLevel === 'MEDIUM';

              return (
                <div key={idx} className="p-5 hover:bg-slate-50/50 transition-colors">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-2">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <span
                        className={`text-[10px] font-bold font-mono uppercase px-2.5 py-0.5 rounded ${
                          isHigh
                            ? 'bg-red-100 text-red-800 border border-red-200'
                            : isMed
                            ? 'bg-amber-100 text-amber-800 border border-amber-200'
                            : 'bg-slate-100 text-slate-700 border border-slate-200'
                        }`}
                      >
                        {u.riskLevel} RISK
                      </span>
                      <span className="font-mono text-xs font-bold text-slate-900">
                        Domain: {u.domain}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">
                        ({u.protocol.toUpperCase()})
                      </span>
                    </div>

                    <button
                      onClick={() => handleCopy(u.url, `url-${idx}`)}
                      className="inline-flex items-center gap-1 text-xs text-slate-500 hover:text-slate-900 p-1 rounded hover:bg-slate-100"
                    >
                      {copiedKey === `url-${idx}` ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-600" />
                          <span className="text-emerald-700 text-[11px]">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5 text-slate-400" />
                          <span className="text-[11px]">Copy URL</span>
                        </>
                      )}
                    </button>
                  </div>

                  {/* Raw URL */}
                  <p className="font-mono text-xs text-blue-600 break-all bg-slate-50 p-2 rounded border border-slate-200 my-2 select-all">
                    {u.url}
                  </p>

                  {/* Reasons / Indicators */}
                  <div className="text-xs text-slate-600 mt-2">
                    <span className="font-semibold text-slate-700">Risk Assessment Rationale: </span>
                    {u.riskIndicators.length > 0 ? (
                      <span className="text-slate-800">{u.riskIndicators.join(' • ')}</span>
                    ) : (
                      <span className="text-slate-500">Standard HTTPS URL with no suspicious hostname or path patterns.</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
