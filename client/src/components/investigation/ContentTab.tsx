import React from 'react';
import {
  MessageSquareWarning,
  AlertTriangle,
  Clock,
  KeyRound,
  DollarSign,
  UserX,
  Flame,
  ShieldAlert,
} from 'lucide-react';
import type { CaseRecord } from '../../types.js';

interface ContentTabProps {
  caseData: CaseRecord;
}

export const ContentTab: React.FC<ContentTabProps> = ({ caseData }) => {
  const { findings, aiAssessment } = caseData;

  // Filter ONLY content-related findings (Phishing & BEC)
  const contentFindings = findings.filter(
    (f) => f.type === 'PHISHING' || f.type === 'BEC'
  );

  const phishingIndicators = aiAssessment?.phishing_indicators || [];
  const becIndicators = aiAssessment?.bec_indicators || [];

  return (
    <div className="space-y-6">
      {/* Overview Notice */}
      <div className="p-4 bg-slate-900 text-white rounded-xl flex items-start gap-3 shadow-sm border border-slate-800">
        <MessageSquareWarning className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
        <div>
          <h4 className="text-sm font-bold tracking-wide">
            Linguistic & Behavioral Content Analysis
          </h4>
          <p className="text-xs text-slate-300 mt-1 leading-relaxed">
            Evaluates message body syntax, psychological pressure tactics, credential harvesting patterns, financial redirection lures, and executive pretexts.
          </p>
        </div>
      </div>

      {/* Semantic Indicators Grid (Phishing vs BEC) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Phishing & Social Engineering Indicators */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-100 mb-4">
            <Flame className="w-4 h-4 text-red-500" />
            <h4 className="text-sm font-bold text-slate-900">
              Phishing & Social Engineering Signals ({phishingIndicators.length})
            </h4>
          </div>

          {phishingIndicators.length === 0 ? (
            <div className="py-6 text-center text-xs text-slate-400">
              No generic credential phishing or urgency patterns detected in message content.
            </div>
          ) : (
            <div className="space-y-2.5">
              {phishingIndicators.map((ind, idx) => (
                <div
                  key={idx}
                  className="flex items-start gap-2.5 p-3 rounded-lg bg-red-50/50 border border-red-100 text-xs text-red-950"
                >
                  <span className="w-4 h-4 rounded-full bg-red-200 text-red-700 font-bold flex items-center justify-center flex-shrink-0 text-[10px] mt-0.5">
                    !
                  </span>
                  <span className="leading-relaxed font-medium">{ind}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* BEC & Financial Fraud Indicators */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-100 mb-4">
            <DollarSign className="w-4 h-4 text-amber-500" />
            <h4 className="text-sm font-bold text-slate-900">
              Business Email Compromise (BEC) Signals ({becIndicators.length})
            </h4>
          </div>

          {becIndicators.length === 0 ? (
            <div className="py-6 text-center text-xs text-slate-400">
              No executive wire fraud, payroll diversion, or gift card solicitations detected.
            </div>
          ) : (
            <div className="space-y-2.5">
              {becIndicators.map((ind, idx) => (
                <div
                  key={idx}
                  className="flex items-start gap-2.5 p-3 rounded-lg bg-amber-50/50 border border-amber-100 text-xs text-amber-950"
                >
                  <span className="w-4 h-4 rounded-full bg-amber-200 text-amber-800 font-bold flex items-center justify-center flex-shrink-0 text-[10px] mt-0.5">
                    $
                  </span>
                  <span className="leading-relaxed font-medium">{ind}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Itemized Content Findings Table */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-sm">
        <div className="px-6 py-4 border-b border-slate-100 bg-slate-50 flex items-center justify-between">
          <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-blue-600" />
            Itemized Content Threat Evidence ({contentFindings.length})
          </h4>
          <span className="text-xs text-slate-500 font-mono">
            Source: Content analysis
          </span>
        </div>

        {contentFindings.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-400">
            No malicious linguistic or behavioral patterns extracted from the email body.
          </div>
        ) : (
          <div className="divide-y divide-slate-100">
            {contentFindings.map((f, idx) => (
              <div key={idx} className="p-5 hover:bg-slate-50/50 transition-colors">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2.5">
                    <span
                      className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded font-mono ${
                        f.severity === 'CRITICAL'
                          ? 'bg-red-100 text-red-800 border border-red-200'
                          : f.severity === 'HIGH'
                          ? 'bg-orange-100 text-orange-800 border border-orange-200'
                          : 'bg-amber-100 text-amber-800 border border-amber-200'
                      }`}
                    >
                      {f.severity}
                    </span>
                    <span className="text-xs font-bold text-slate-900">{f.title}</span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-400">
                    Category: {f.type}
                  </span>
                </div>

                {f.snippet && (
                  <div className="bg-slate-50 p-2.5 rounded border border-slate-200 text-xs font-mono text-slate-700 my-2 italic">
                    {f.snippet}
                  </div>
                )}

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs mt-2 text-slate-600">
                  <div>
                    <span className="font-semibold text-slate-700">Observed Trigger: </span>
                    {f.observed}
                  </div>
                  <div>
                    <span className="font-semibold text-slate-700">Security Impact: </span>
                    {f.impact}
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
