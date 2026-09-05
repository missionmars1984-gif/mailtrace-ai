import React from 'react';
import { X, Server, Mail, Shield } from 'lucide-react';
import type { MailboxStatus } from '../types';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  status: MailboxStatus | null;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({
  isOpen,
  onClose,
  status,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4">
      <div className="bg-white rounded-lg shadow-xl border border-slate-300 w-full max-w-lg flex flex-col overflow-hidden">
        {/* Header */}
        <div className="h-11 bg-slate-900 text-white px-4 flex items-center justify-between select-none">
          <div className="flex items-center gap-2 text-xs font-semibold tracking-wide">
            <Server className="w-4 h-4 text-blue-400" />
            <span>Mail Server Configuration</span>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 space-y-4 text-xs text-slate-700">
          {/* SMTP Section */}
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-md">
            <div className="flex items-center justify-between mb-2">
              <span className="font-semibold text-slate-900 flex items-center gap-1.5">
                <Mail className="w-3.5 h-3.5 text-blue-600" />
                SMTP Sending Service
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                status?.smtpConnected
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-amber-50 text-amber-700 border-amber-200'
              }`}>
                {status?.smtpConnected ? 'ONLINE' : 'OFFLINE'}
              </span>
            </div>
            <div className="text-slate-500 text-[11px] leading-relaxed">
              {status?.smtpMessage || 'Checking connection status...'}
            </div>
            <div className="mt-2 text-[11px] font-mono text-slate-600 bg-white p-2 rounded border border-slate-200">
              Transport: nodemailer (SMTP RFC 5321)<br />
              Default Port: 1025 / 587
            </div>
          </div>

          {/* Mailbox Section */}
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-md">
            <div className="flex items-center justify-between mb-2">
              <span className="font-semibold text-slate-900 flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-blue-600" />
                Mailbox Retrieval ({status?.mode || 'Mailpit'})
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                status?.mailboxConnected
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-slate-50 text-slate-600 border-slate-200'
              }`}>
                {status?.mailboxConnected ? 'CONNECTED' : 'DISCONNECTED'}
              </span>
            </div>
            <div className="text-slate-500 text-[11px] leading-relaxed">
              {status?.mailboxMessage || 'Checking mailbox connection...'}
            </div>
            <div className="mt-2 text-[11px] font-mono text-slate-600 bg-white p-2 rounded border border-slate-200">
              API Mode: {status?.mode || 'Mailpit API'}<br />
              Last Sync: {status?.lastSyncedAt ? new Date(status.lastSyncedAt).toLocaleTimeString() : 'Not yet synced'}
            </div>
          </div>

          {/* Background Security Sync */}
          <div className="p-3 bg-blue-50/50 border border-blue-200/60 rounded-md">
            <div className="flex items-center gap-1.5 font-semibold text-blue-900 mb-1">
              <Shield className="w-3.5 h-3.5 text-blue-700" />
              <span>SOC Ingestion Pipeline</span>
            </div>
            <p className="text-[11px] text-blue-800 leading-relaxed">
              Incoming raw RFC 822 MIME emails are automatically mirrored to the MailTrace SOC backend ingest endpoint in the background without UI coupling or link exposure.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="h-12 bg-slate-50 border-t border-slate-200 px-4 flex items-center justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-900 text-white rounded text-xs font-medium transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
