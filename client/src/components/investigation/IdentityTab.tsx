import React from 'react';
import {
  Fingerprint,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  UserCheck,
  Server,
  ArrowRight,
  Info,
  CheckCircle2,
  XCircle,
  HelpCircle,
} from 'lucide-react';
import type { CaseRecord } from '../../types.js';

interface IdentityTabProps {
  caseData: CaseRecord;
}

export const IdentityTab: React.FC<IdentityTabProps> = ({ caseData }) => {
  const { identityAnalysis, metadata, hops } = caseData;
  const { claimed, observed, consistency, reasons, replyToMismatch, returnPathMismatch, displayNameSpoofing, lookalikeDomain, punycodeDetected } = identityAnalysis;

  const originHop = hops.length > 0 ? hops[hops.length - 1] : undefined;

  const getConsistencyBadge = (c: string) => {
    switch (c) {
      case 'HIGH':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-extrabold bg-emerald-100 text-emerald-800 border border-emerald-300">
            <CheckCircle2 className="w-3.5 h-3.5" /> HIGH ALIGNMENT
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-extrabold bg-amber-100 text-amber-800 border border-amber-300">
            <AlertTriangle className="w-3.5 h-3.5" /> MODERATE DIVERGENCE
          </span>
        );
      case 'LOW':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-extrabold bg-red-100 text-red-800 border border-red-300">
            <XCircle className="w-3.5 h-3.5" /> CRITICAL MISALIGNMENT (DECEPTION DETECTED)
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Notice */}
      <div className="p-4 bg-slate-900 text-white rounded-xl flex items-start gap-3 shadow-sm border border-slate-800">
        <Fingerprint className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
        <div>
          <h4 className="text-sm font-bold tracking-wide">
            Claimed Identity vs. Observed Technical Identity Cross-Examination
          </h4>
          <p className="text-xs text-slate-300 mt-1 leading-relaxed">
            Attackers frequently forge human-facing sender addresses while technical transmission envelopes disclose their actual infrastructure.
            MailTrace AI juxtaposes the visible persona against immutable transport headers.
          </p>
        </div>
      </div>

      {/* Visual Split: Claimed Identity vs Observed Technical Identity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Card: Claimed Identity */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-100 mb-4">
            <UserCheck className="w-4 h-4 text-blue-600" />
            <h4 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
              Claimed Human-Facing Identity
            </h4>
          </div>

          <div className="space-y-4 text-xs font-mono">
            <div>
              <span className="text-slate-400 font-sans block text-[11px] font-bold uppercase mb-0.5">
                Display Name
              </span>
              <div className="p-2.5 rounded bg-slate-50 border border-slate-200 text-slate-900 font-sans font-semibold text-sm">
                {claimed.displayName || '(No Display Name Stated)'}
              </div>
            </div>

            <div>
              <span className="text-slate-400 font-sans block text-[11px] font-bold uppercase mb-0.5">
                From Header Address
              </span>
              <div className="p-2.5 rounded bg-slate-50 border border-slate-200 text-slate-900 break-all font-semibold">
                {claimed.email}
              </div>
            </div>

            <div>
              <span className="text-slate-400 font-sans block text-[11px] font-bold uppercase mb-0.5">
                Claimed Sender Domain
              </span>
              <div className="p-2.5 rounded bg-slate-50 border border-slate-200 text-slate-900 font-semibold">
                @{claimed.domain}
              </div>
            </div>

            <div>
              <span className="text-slate-400 font-sans block text-[11px] font-bold uppercase mb-0.5">
                Reply-To Address
              </span>
              <div
                className={`p-2.5 rounded border break-all font-semibold ${
                  replyToMismatch
                    ? 'bg-red-50 border-red-200 text-red-700'
                    : 'bg-slate-50 border-slate-200 text-slate-900'
                }`}
              >
                {observed.replyTo || claimed.email}
              </div>
            </div>
          </div>
        </div>

        {/* Right Card: Observed Technical Identity */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-100 mb-4">
            <Server className="w-4 h-4 text-indigo-600" />
            <h4 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
              Observed Technical Infrastructure Identity
            </h4>
          </div>

          <div className="space-y-4 text-xs font-mono">
            <div>
              <span className="text-slate-400 font-sans block text-[11px] font-bold uppercase mb-0.5">
                Return-Path Envelope Address
              </span>
              <div
                className={`p-2.5 rounded border break-all font-semibold ${
                  returnPathMismatch
                    ? 'bg-amber-50 border-amber-200 text-amber-800'
                    : 'bg-slate-50 border-slate-200 text-slate-900'
                }`}
              >
                {observed.returnPath || 'Unavailable'}
              </div>
            </div>

            <div>
              <span className="text-slate-400 font-sans block text-[11px] font-bold uppercase mb-0.5">
                Sending IP Address
              </span>
              <div className="p-2.5 rounded bg-slate-50 border border-slate-200 text-slate-900 font-bold">
                {observed.sendingIp || originHop?.ip || 'Unavailable'}
              </div>
            </div>

            <div>
              <span className="text-slate-400 font-sans block text-[11px] font-bold uppercase mb-0.5">
                Observed Technical Domain
              </span>
              <div className="p-2.5 rounded bg-slate-50 border border-slate-200 text-slate-900 font-semibold">
                @{observed.sendingDomain || claimed.domain}
              </div>
            </div>

            <div>
              <span className="text-slate-400 font-sans block text-[11px] font-bold uppercase mb-0.5">
                Transmitting Mail Server & ASN / ISP
              </span>
              <div className="p-2.5 rounded bg-slate-50 border border-slate-200 text-slate-800 font-sans text-xs">
                {originHop?.by || originHop?.from || 'Direct Gateway'}
                <span className="block text-slate-500 font-mono text-[11px] mt-0.5">
                  ASN: {originHop?.geo?.asn || 'Unassigned'} • ISP: {originHop?.geo?.org || originHop?.geo?.isp || 'Internal Network'}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Identity Consistency Rating & Findings */}
      <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-100 gap-3">
          <div>
            <h4 className="text-sm font-bold text-slate-900">Identity Consistency Rating</h4>
            <p className="text-xs text-slate-500 mt-0.5">
              Automated correlation of display persona, envelope addresses, and server routing.
            </p>
          </div>
          <div>{getConsistencyBadge(consistency)}</div>
        </div>

        <div className="mt-5 space-y-3">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-400 block">
            Corroborating Reasons & Evidence
          </span>

          {reasons.length === 0 ? (
            <div className="p-3 bg-emerald-50 text-emerald-800 rounded-lg text-xs border border-emerald-200 font-medium">
              No identity inconsistencies or deceptive spoofing indicators detected. Envelope alignment is consistent.
            </div>
          ) : (
            <div className="space-y-2">
              {reasons.map((r, idx) => (
                <div
                  key={idx}
                  className="flex items-start gap-2.5 p-3 rounded-lg bg-slate-50 border border-slate-100 text-xs text-slate-800"
                >
                  <span className="w-4 h-4 rounded-full bg-red-100 text-red-600 font-bold flex items-center justify-center flex-shrink-0 text-[10px] mt-0.5">
                    !
                  </span>
                  <span className="leading-relaxed font-medium">{r}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
