import React, { useState } from 'react';
import {
  Paperclip,
  FileCode,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Copy,
  Check,
  FileText,
  FileCheck,
} from 'lucide-react';
import type { CaseRecord } from '../../types.js';

interface AttachmentsTabProps {
  caseData: CaseRecord;
}

export const AttachmentsTab: React.FC<AttachmentsTabProps> = ({ caseData }) => {
  const { attachments } = caseData;
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="space-y-6">
      {/* Non-Execution Security Notice */}
      <div className="p-4 bg-blue-50/70 border border-blue-200 rounded-xl flex items-start gap-3 text-xs text-blue-950 shadow-sm">
        <FileCheck className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="font-bold block text-sm mb-0.5">Static Payload Inspection Guarantee:</strong>
          All attachments are analyzed strictly in an isolated static memory buffer. MailTrace AI calculates cryptographic SHA-256 digests, analyzes file headers, extensions, and MIME structures, and <strong>never executes</strong> binary payloads or active macro scripts.
        </div>
      </div>

      {/* Attachments List */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-sm">
        <div className="px-6 py-4 border-b border-slate-100 bg-slate-50 flex items-center justify-between">
          <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
            <Paperclip className="w-4 h-4 text-blue-600" />
            Static File Attachment Records ({attachments.length})
          </h4>
          <span className="text-xs text-slate-500 font-mono">
            Source: Attachment analysis
          </span>
        </div>

        {attachments.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-400">
            No binary attachments, scripts, or container files were attached to this message.
          </div>
        ) : (
          <div className="divide-y divide-slate-100">
            {attachments.map((att, idx) => {
              const isCrit = att.isDoubleExtension || att.isDangerous;
              const isHigh = att.isMacro;
              const ext = att.filename.split('.').pop()?.toUpperCase() || 'UNKNOWN';

              return (
                <div key={idx} className="p-6 hover:bg-slate-50/50 transition-colors">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
                    <div className="flex items-center gap-3">
                      <div
                        className={`w-10 h-10 rounded-lg flex items-center justify-center font-mono font-bold text-xs ${
                          isCrit
                            ? 'bg-red-100 text-red-700'
                            : isHigh
                            ? 'bg-amber-100 text-amber-700'
                            : 'bg-slate-100 text-slate-700'
                        }`}
                      >
                        .{ext}
                      </div>
                      <div>
                        <h5 className="font-bold text-sm text-slate-900 break-all">{att.filename}</h5>
                        <p className="text-xs text-slate-400 font-mono mt-0.5">
                          MIME: {att.contentType} • Size: {formatBytes(att.size)}
                        </p>
                      </div>
                    </div>

                    <div>
                      {isCrit ? (
                        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-red-100 text-red-800 border border-red-300">
                          <ShieldAlert className="w-3.5 h-3.5" /> CRITICAL PAYLOAD
                        </span>
                      ) : isHigh ? (
                        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-amber-100 text-amber-800 border border-amber-300">
                          <AlertTriangle className="w-3.5 h-3.5" /> ELEVATED RISK
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800 border border-emerald-300">
                          <ShieldCheck className="w-3.5 h-3.5" /> BENIGN FORMAT
                        </span>
                      )}
                    </div>
                  </div>

                  {/* SHA-256 Digest Bar */}
                  <div className="bg-slate-900 rounded-lg p-3 border border-slate-800 flex items-center justify-between gap-3 text-xs font-mono">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-slate-400 text-[11px] font-sans font-semibold">SHA-256:</span>
                      <span className="text-emerald-400 truncate select-all">{att.sha256}</span>
                    </div>
                    <button
                      onClick={() => handleCopyHash(att.sha256)}
                      className="inline-flex items-center gap-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px] font-sans transition-colors flex-shrink-0"
                    >
                      {copiedHash === att.sha256 ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span className="text-emerald-400">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy Hash</span>
                        </>
                      )}
                    </button>
                  </div>

                  {/* Risk Assessment Reason */}
                  <div className="mt-3 text-xs text-slate-700">
                    <span className="font-semibold text-slate-800">Forensic Analysis Reason: </span>
                    {att.riskReasons.length > 0 ? (
                      <span className="font-medium text-red-700">{att.riskReasons.join(' • ')}</span>
                    ) : (
                      <span className="text-slate-500">Standard non-executable file format without embedded scripts or dual extension signatures.</span>
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
