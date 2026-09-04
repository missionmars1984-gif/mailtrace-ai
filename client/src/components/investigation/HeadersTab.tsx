import React, { useState } from 'react';
import {
  Copy,
  Check,
  FileCode,
  ListFilter,
  Layers,
  Terminal,
} from 'lucide-react';
import type { CaseRecord } from '../../types.js';

interface HeadersTabProps {
  caseData: CaseRecord;
}

export const HeadersTab: React.FC<HeadersTabProps> = ({ caseData }) => {
  const { metadata, rawHeaders, rawEmail } = caseData;
  const [viewMode, setViewMode] = useState<'formatted' | 'raw'>('formatted');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Explicit important headers list according to specification
  const primaryHeaders = [
    { label: 'From', value: metadata.from ? `"${metadata.from.name || ''}" <${metadata.from.address}>` : 'N/A' },
    { label: 'To', value: metadata.to ? metadata.to.map((t) => t.address).join(', ') : 'N/A' },
    { label: 'CC', value: metadata.cc && metadata.cc.length > 0 ? metadata.cc.map((c) => c.address).join(', ') : '(None)' },
    { label: 'Reply-To', value: metadata.replyTo ? `"${metadata.replyTo.name || ''}" <${metadata.replyTo.address}>` : '(Not Specified)' },
    { label: 'Return-Path', value: metadata.returnPath || '(Not Specified)' },
    { label: 'Subject', value: metadata.subject !== undefined && metadata.subject !== '' ? metadata.subject : (metadata.subject === '' ? '(Empty Subject Header)' : '(No Subject Header)') },
    { label: 'Date', value: metadata.date ? new Date(metadata.date).toUTCString() : 'N/A' },
    { label: 'Message-ID', value: metadata.messageId || 'N/A' },
    { label: 'Authentication-Results', value: (rawHeaders && (rawHeaders['authentication-results'] as string)) || 'N/A' },
  ];

  return (
    <div className="space-y-6">
      {/* Top Bar: View Mode Switcher */}
      <div className="flex items-center justify-between bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setViewMode('formatted')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              viewMode === 'formatted'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
            }`}
          >
            Structured Key Headers
          </button>
          <button
            onClick={() => setViewMode('raw')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              viewMode === 'raw'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
            }`}
          >
            Raw RFC 822 Source
          </button>
        </div>

        <button
          onClick={() => handleCopy(rawEmail || '', 'all-raw')}
          className="inline-flex items-center space-x-1.5 text-xs text-slate-600 hover:text-slate-900 bg-slate-50 hover:bg-slate-100 border border-slate-200 px-3 py-1.5 rounded-lg font-medium transition-colors"
        >
          {copiedKey === 'all-raw' ? (
            <>
              <Check className="w-3.5 h-3.5 text-emerald-600" />
              <span className="text-emerald-700">Copied!</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5 text-slate-400" />
              <span>Copy Full Raw Email</span>
            </>
          )}
        </button>
      </div>

      {viewMode === 'formatted' ? (
        <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-sm">
          <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between bg-slate-50">
            <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Layers className="w-4 h-4 text-blue-600" />
              Primary Envelope & Transport Headers
            </h4>
            <span className="text-xs text-slate-500 font-mono">
              RFC 5322 / RFC 822 Compliant
            </span>
          </div>

          <div className="divide-y divide-slate-100">
            {primaryHeaders.map((hdr, idx) => (
              <div key={idx} className="p-4 flex flex-col sm:flex-row sm:items-start justify-between gap-4 hover:bg-slate-50/60 transition-colors">
                <div className="sm:w-52 flex-shrink-0">
                  <span className="text-xs font-mono font-bold text-slate-700 block">
                    {hdr.label}:
                  </span>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-mono text-slate-800 break-all leading-relaxed bg-slate-50 p-2 rounded border border-slate-200/70 select-all">
                    {hdr.value}
                  </p>
                </div>
                <div className="flex-shrink-0">
                  <button
                    onClick={() => handleCopy(hdr.value, `hdr-${idx}`)}
                    className="p-1.5 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded transition-colors"
                    title="Copy value"
                  >
                    {copiedKey === `hdr-${idx}` ? (
                      <Check className="w-3.5 h-3.5 text-emerald-600" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        /* Raw Source Viewer */
        <div className="bg-slate-950 rounded-xl border border-slate-800 overflow-hidden shadow-sm">
          <div className="px-5 py-3 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-slate-400" />
              <span className="text-xs font-mono font-semibold text-slate-300">
                Raw RFC 822 Email Stream
              </span>
            </div>
            <span className="text-[11px] font-mono text-slate-500">
              {rawEmail ? `${rawEmail.length.toLocaleString()} bytes` : '0 bytes'}
            </span>
          </div>
          <pre className="p-5 text-xs font-mono text-emerald-400/90 overflow-x-auto whitespace-pre leading-relaxed max-h-[600px] select-all">
            {rawEmail || 'No raw email source recorded.'}
          </pre>
        </div>
      )}
    </div>
  );
};
