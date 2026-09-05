import React, { useState } from 'react';
import DOMPurify from 'dompurify';
import { 
  Reply, 
  Forward, 
  Trash2, 
  Mail, 
  Download, 
  Paperclip, 
  FileText
} from 'lucide-react';
import type { ExchangeMessage } from '../types';

interface MessageDetailProps {
  message: ExchangeMessage | null;
  onReply: (message: ExchangeMessage) => void;
  onForward: (message: ExchangeMessage) => void;
  onDelete: (id: string) => void;
  onMarkUnread: (id: string) => void;
}

export const MessageDetail: React.FC<MessageDetailProps> = ({
  message,
  onReply,
  onForward,
  onDelete,
  onMarkUnread,
}) => {
  const [viewMode, setViewMode] = useState<'html' | 'text' | 'raw'>('html');

  if (!message) {
    return (
      <div className="flex-1 bg-slate-50/50 flex flex-col items-center justify-center p-8 text-center select-none">
        <div className="w-16 h-16 rounded-full bg-slate-100 flex items-center justify-center mb-4 text-slate-400">
          <Mail className="w-8 h-8 text-slate-300" />
        </div>
        <h3 className="text-sm font-semibold text-slate-700 mb-1">No message selected</h3>
        <p className="text-xs text-slate-400 max-w-sm">
          Select an email from the list on the left to view its contents, attachments, and forensic headers.
        </p>
      </div>
    );
  }

  const formatFullDate = (isoStr: string) => {
    try {
      return new Date(isoStr).toLocaleString([], {
        weekday: 'short',
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
    } catch {
      return isoStr;
    }
  };

  const sanitizedHtml = message.html ? DOMPurify.sanitize(message.html) : '';

  return (
    <div className="flex-1 bg-white flex flex-col h-full overflow-hidden">
      {/* Top Action Bar */}
      <div className="h-12 border-b border-slate-200 px-4 flex items-center justify-between shrink-0 bg-slate-50/30">
        <div className="flex items-center gap-1 text-slate-700">
          <button
            onClick={() => onReply(message)}
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium hover:bg-slate-200/70 rounded transition-colors"
          >
            <Reply className="w-3.5 h-3.5 text-slate-600" />
            <span>Reply</span>
          </button>
          <button
            onClick={() => onForward(message)}
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium hover:bg-slate-200/70 rounded transition-colors"
          >
            <Forward className="w-3.5 h-3.5 text-slate-600" />
            <span>Forward</span>
          </button>
          <div className="h-4 w-px bg-slate-200 mx-1" />
          <button
            onClick={() => onDelete(message.id)}
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium hover:bg-red-50 hover:text-red-700 rounded transition-colors text-slate-700"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Delete</span>
          </button>
          <button
            onClick={() => onMarkUnread(message.id)}
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium hover:bg-slate-200/70 rounded transition-colors"
          >
            <Mail className="w-3.5 h-3.5 text-slate-600" />
            <span>Mark Unread</span>
          </button>
        </div>

        {/* EML download & View switcher */}
        <div className="flex items-center gap-2">
          {/* View switcher */}
          <div className="flex items-center bg-slate-100 p-0.5 rounded text-xs font-medium border border-slate-200">
            {message.html && (
              <button
                onClick={() => setViewMode('html')}
                className={`px-2 py-0.5 rounded text-[11px] ${
                  viewMode === 'html' ? 'bg-white text-slate-800 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                HTML
              </button>
            )}
            <button
              onClick={() => setViewMode('text')}
              className={`px-2 py-0.5 rounded text-[11px] ${
                viewMode === 'text' ? 'bg-white text-slate-800 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Text
            </button>
            <button
              onClick={() => setViewMode('raw')}
              className={`px-2 py-0.5 rounded text-[11px] ${
                viewMode === 'raw' ? 'bg-white text-slate-800 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              RFC 822
            </button>
          </div>

          {/* Download Raw EML */}
          <a
            href={`/api/messages/${message.id}/raw`}
            download={`${message.subject || 'message'}.eml`}
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-700 bg-white border border-slate-200 hover:bg-slate-50 rounded shadow-2xs transition-colors"
            title="Download original unedited RFC 822 MIME (.eml)"
          >
            <Download className="w-3.5 h-3.5 text-slate-600" />
            <span>Download .eml</span>
          </a>
        </div>
      </div>

      {/* Message Header Information */}
      <div className="p-6 border-b border-slate-200 select-text">
        {/* Security & Delivery Assessment Banner */}
        {typeof message.riskScore === 'number' ? (
          <div
            className={`mb-4 px-3 py-2 rounded-md border flex items-center justify-between text-xs ${
              message.riskScore >= 60
                ? 'bg-red-50 border-red-200 text-red-800'
                : message.riskScore >= 30
                ? 'bg-amber-50 border-amber-200 text-amber-800'
                : 'bg-emerald-50/70 border-emerald-200 text-emerald-800'
            }`}
          >
            <div className="flex items-center gap-2 font-medium">
              <span
                className={`w-2 h-2 rounded-full ${
                  message.riskScore >= 60
                    ? 'bg-red-600 animate-pulse'
                    : message.riskScore >= 30
                    ? 'bg-amber-500'
                    : 'bg-emerald-500'
                }`}
              />
              <span>
                {message.riskScore >= 60
                  ? `Threat Detected: ${message.threatClassification || 'Malicious / Suspicious'}`
                  : message.riskScore >= 30
                  ? `Warning: ${message.threatClassification || 'Suspicious Indicators'}`
                  : 'MailTrace Security Verified: Clean'}
              </span>
              <span className="font-mono text-[11px] opacity-80">(Risk Score: {message.riskScore}/100)</span>
            </div>
            <div className="flex items-center gap-2">
              {message.deliveryStatus && (
                <span className="text-[11px] font-medium opacity-80">{message.deliveryStatus}</span>
              )}
              {message.caseId && (
                <span className="font-mono text-[11px] font-semibold bg-white/80 px-2 py-0.5 rounded border border-current">
                  Case {message.caseId}
                </span>
              )}
            </div>
          </div>
        ) : message.deliveryStatus ? (
          <div className="mb-4 px-3 py-1.5 rounded-md bg-slate-50 border border-slate-200 flex items-center justify-between text-xs text-slate-600">
            <span>Status: <strong>{message.deliveryStatus}</strong></span>
          </div>
        ) : null}

        <h1 className="text-lg font-semibold text-slate-900 mb-4 leading-snug">
          {message.subject || '(No Subject)'}
        </h1>

        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3 min-w-0">
            <div className="w-10 h-10 rounded-full bg-blue-100 text-blue-700 flex items-center justify-center font-bold text-sm shrink-0 uppercase">
              {(message.from.name || message.from.address || 'U').charAt(0)}
            </div>
            <div className="min-w-0 text-xs">
              <div className="flex items-center gap-2">
                <span className="font-semibold text-slate-900 text-sm">
                  {message.from.name || message.from.address}
                </span>
                {message.from.name && (
                  <span className="text-slate-500 font-normal">
                    &lt;{message.from.address}&gt;
                  </span>
                )}
              </div>
              <div className="text-slate-500 mt-1">
                <span className="font-medium text-slate-600">To: </span>
                {message.to.map((t) => t.name ? `${t.name} <${t.address}>` : t.address).join(', ')}
              </div>
              {message.cc && message.cc.length > 0 && (
                <div className="text-slate-500 mt-0.5">
                  <span className="font-medium text-slate-600">Cc: </span>
                  {message.cc.map((t) => t.name ? `${t.name} <${t.address}>` : t.address).join(', ')}
                </div>
              )}
            </div>
          </div>

          <div className="text-right shrink-0 text-xs text-slate-500">
            {formatFullDate(message.date)}
          </div>
        </div>

        {/* Attachments Banner */}
        {message.attachments && message.attachments.length > 0 && (
          <div className="mt-4 pt-3 border-t border-slate-100">
            <div className="text-xs font-semibold text-slate-700 mb-2 flex items-center gap-1.5">
              <Paperclip className="w-3.5 h-3.5 text-slate-500" />
              <span>Attachments ({message.attachments.length})</span>
            </div>
            <div className="flex flex-wrap gap-2">
              {message.attachments.map((att) => (
                <a
                  key={att.id}
                  href={`/api/messages/${message.id}/attachments/${att.id}`}
                  download={att.filename}
                  className="flex items-center gap-2 px-3 py-1.5 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded-md text-xs text-slate-700 font-medium transition-colors group"
                >
                  <FileText className="w-3.5 h-3.5 text-slate-500 group-hover:text-blue-600" />
                  <span className="truncate max-w-[180px]">{att.filename}</span>
                  <span className="text-[10px] text-slate-400">
                    ({(att.size / 1024).toFixed(1)} KB)
                  </span>
                  <Download className="w-3 h-3 text-slate-400 group-hover:text-blue-600 ml-1" />
                </a>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Message Body Content */}
      <div className="flex-1 overflow-y-auto p-6 select-text">
        {viewMode === 'html' && message.html ? (
          <div 
            className="prose prose-sm max-w-none text-slate-800 leading-relaxed font-sans"
            dangerouslySetInnerHTML={{ __html: sanitizedHtml }}
          />
        ) : viewMode === 'text' ? (
          <pre className="text-xs text-slate-800 font-mono whitespace-pre-wrap leading-relaxed">
            {message.text || '(No plain text content)'}
          </pre>
        ) : (
          <div className="bg-slate-900 text-slate-200 p-4 rounded-md font-mono text-xs overflow-x-auto whitespace-pre leading-normal">
            {message.rawSource || 'Raw RFC 822 source not stored for this message.'}
          </div>
        )}
      </div>
    </div>
  );
};
