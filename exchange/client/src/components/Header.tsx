import React from 'react';
import { Mail, RefreshCw, Search, AlertCircle, Settings, CheckCircle2 } from 'lucide-react';
import type { MailboxStatus } from '../types';

interface HeaderProps {
  status: MailboxStatus | null;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  onRefresh: () => void;
  isRefreshing: boolean;
  onOpenSettings: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  status,
  searchQuery,
  onSearchChange,
  onRefresh,
  isRefreshing,
  onOpenSettings,
}) => {
  return (
    <header className="h-14 bg-white border-b border-slate-200 px-4 flex items-center justify-between select-none shrink-0 z-10 shadow-xs">
      {/* Brand */}
      <div className="flex items-center gap-3 w-64 shrink-0">
        <div className="w-8 h-8 rounded bg-blue-700 text-white flex items-center justify-center shadow-xs">
          <Mail className="w-5 h-5" />
        </div>
        <div>
          <div className="font-semibold text-sm tracking-tight text-slate-900 flex items-center gap-1.5">
            MailTrace Exchange
            <span className="text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200/60">
              Enterprise
            </span>
          </div>
          <p className="text-[11px] text-slate-500 font-normal leading-tight">Mail Server & Mailbox</p>
        </div>
      </div>

      {/* Search bar */}
      <div className="flex-1 max-w-xl mx-4">
        <div className="relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search emails by sender, recipient, subject, or content..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            className="w-full pl-9 pr-4 py-1.5 text-xs bg-slate-50 hover:bg-slate-100/80 focus:bg-white border border-slate-200 focus:border-blue-500 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-100 transition-all text-slate-800 placeholder-slate-400"
          />
          {searchQuery && (
            <button
              onClick={() => onSearchChange('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 text-xs font-semibold px-1 rounded"
            >
              ✕
            </button>
          )}
        </div>
      </div>

      {/* Status & Actions */}
      <div className="flex items-center gap-2 shrink-0">
        {/* Connection Status Pills */}
        <div className="hidden lg:flex items-center gap-2 mr-2">
          {/* SMTP Status */}
          <div
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium border ${
              status?.smtpConnected
                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                : 'bg-amber-50 text-amber-700 border-amber-200'
            }`}
            title={
              status?.smtpConnected
                ? `SMTP Relay Online: ${status?.smtpHost || 'localhost'}:${status?.smtpPort || 1025} (${status?.smtpMessage || 'Ready'})`
                : `SMTP Offline: ${status?.smtpMessage || 'Connection refused or not running'}`
            }
          >
            {status?.smtpConnected ? (
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
            ) : (
              <AlertCircle className="w-3.5 h-3.5 text-amber-600" />
            )}
            <span>{status?.smtpConnected ? 'SMTP Active' : 'SMTP Offline'}</span>
          </div>

          {/* Mailbox Status */}
          <div
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium border ${
              status?.mailboxConnected
                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                : 'bg-slate-50 text-slate-600 border-slate-200'
            }`}
            title={
              status?.mailboxConnected
                ? `${status?.mailboxMessage || 'Connected to Mailpit'} (Latency: ${status?.latencyMs ?? 1}ms)`
                : `Mailbox Offline: ${status?.mailboxMessage || 'Cannot connect to mail service'}`
            }
          >
            <span className={`w-2 h-2 rounded-full ${status?.mailboxConnected ? 'bg-emerald-500' : 'bg-slate-400'}`} />
            <span>{status?.mailboxConnected ? 'Mailpit Online' : 'Mailpit Offline'}</span>
          </div>
        </div>

        {/* Sync / Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-200 hover:bg-slate-50 active:bg-slate-100 rounded-md shadow-2xs transition-colors disabled:opacity-50"
          title="Sync mailbox"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-slate-600 ${isRefreshing ? 'animate-spin' : ''}`} />
          <span className="hidden sm:inline">Sync</span>
        </button>

        {/* Settings Button */}
        <button
          onClick={onOpenSettings}
          className="p-1.5 text-slate-600 hover:text-slate-900 border border-slate-200 hover:bg-slate-50 rounded-md transition-colors shadow-2xs"
          title="Server Settings"
        >
          <Settings className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
};
