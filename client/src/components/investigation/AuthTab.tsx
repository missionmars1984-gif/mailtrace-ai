import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  HelpCircle,
  CheckCircle2,
  XCircle,
  KeyRound,
  FileCheck2,
  Lock,
} from 'lucide-react';
import type { AuthenticationResults } from '../../types.js';

interface AuthTabProps {
  auth?: AuthenticationResults;
}

export const AuthTab: React.FC<AuthTabProps> = ({ auth }) => {
  const getStatusBadge = (status?: string) => {
    switch (status?.toLowerCase()) {
      case 'pass':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800 border border-emerald-300">
            <CheckCircle2 className="w-3.5 h-3.5" /> PASS
          </span>
        );
      case 'fail':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-red-100 text-red-800 border border-red-300">
            <XCircle className="w-3.5 h-3.5" /> FAIL
          </span>
        );
      case 'softfail':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-amber-100 text-amber-800 border border-amber-300">
            <AlertTriangle className="w-3.5 h-3.5" /> SOFTFAIL
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-slate-100 text-slate-700 border border-slate-300">
            <HelpCircle className="w-3.5 h-3.5" /> {status?.toUpperCase() || 'UNKNOWN'}
          </span>
        );
    }
  };

  const protocols = [
    {
      name: 'SPF (Sender Policy Framework)',
      short: 'SPF',
      icon: Lock,
      status: auth?.spf.status || 'none',
      explanation:
        auth?.spf.status === 'pass'
          ? 'Sending mail transfer agent (MTA) IP address is authorized in the sender domain DNS TXT record.'
          : auth?.spf.status === 'fail'
          ? 'Transmitting server IP address is explicitly not authorized to send mail on behalf of the claimed domain (~all/-all).'
          : auth?.spf.status === 'softfail'
          ? 'Transmitting server IP is questionable or not listed; domain designates a soft failure policy (~all).'
          : 'No valid SPF record evaluated or record absent in sender domain DNS.',
      rawOutput: auth?.spf.raw || 'No SPF record evaluated',
    },
    {
      name: 'DKIM (DomainKeys Identified Mail)',
      short: 'DKIM',
      icon: KeyRound,
      status: auth?.dkim.status || 'none',
      explanation:
        auth?.dkim.status === 'pass'
          ? 'Cryptographic public key signature verified. Message body and critical headers were intact during transit.'
          : auth?.dkim.status === 'fail'
          ? 'Cryptographic signature verification failed. The message body or headers were modified in transit, or the key was revoked.'
          : 'No DKIM cryptographic signature header present in the message.',
      rawOutput: auth?.dkim.raw || 'No DKIM signature evaluated',
    },
    {
      name: 'DMARC (Domain-based Message Authentication)',
      short: 'DMARC',
      icon: FileCheck2,
      status: auth?.dmarc.status || 'none',
      explanation:
        auth?.dmarc.status === 'pass'
          ? 'DMARC alignment satisfied. Visible From header domain aligns with authenticated SPF and/or DKIM domains.'
          : auth?.dmarc.status === 'fail'
          ? 'DMARC alignment policy violated. The human-facing From domain fails to align with SPF/DKIM envelope domains.'
          : 'No DMARC policy published by the sender domain or alignment could not be established.',
      rawOutput: auth?.dmarc.raw || 'No DMARC policy evaluated',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Overview Notice */}
      <div className="bg-blue-50/70 border border-blue-200 p-4 rounded-xl flex items-start gap-3">
        <ShieldCheck className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
        <div className="text-xs text-blue-950 leading-relaxed">
          <strong>Authentication Integrity Note:</strong> SPF, DKIM, and DMARC confirm whether the sending mail server was authorized by the domain owner.
          <span className="block mt-1 text-blue-800 font-medium">
            Passing authentication does NOT guarantee an email is safe (e.g., lookalike domains or compromised accounts can pass all three checks).
          </span>
        </div>
      </div>

      {/* 3 Dedicated Protocol Cards */}
      <div className="space-y-4">
        {protocols.map((proto, idx) => {
          const Icon = proto.icon;
          const isPass = proto.status.toLowerCase() === 'pass';
          const isFail = proto.status.toLowerCase() === 'fail';

          return (
            <div
              key={idx}
              className={`bg-white rounded-xl border p-6 shadow-sm transition-all ${
                isFail ? 'border-red-200' : isPass ? 'border-emerald-100' : 'border-slate-200'
              }`}
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-100">
                <div className="flex items-center gap-3">
                  <div
                    className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                      isFail
                        ? 'bg-red-50 text-red-600'
                        : isPass
                        ? 'bg-emerald-50 text-emerald-600'
                        : 'bg-slate-100 text-slate-600'
                    }`}
                  >
                    <Icon className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-slate-900">{proto.name}</h4>
                    <p className="text-xs text-slate-400 font-mono mt-0.5">Protocol: {proto.short}</p>
                  </div>
                </div>

                <div>{getStatusBadge(proto.status)}</div>
              </div>

              {/* Protocol Explanation & Raw Output */}
              <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-slate-50 p-4 rounded-lg border border-slate-100">
                  <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 block mb-1">
                    Technical Explanation
                  </span>
                  <p className="text-xs text-slate-700 leading-relaxed font-medium">
                    {proto.explanation}
                  </p>
                </div>

                <div className="bg-slate-900 text-slate-200 p-4 rounded-lg border border-slate-800">
                  <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-slate-400 block mb-1">
                    Raw Header Record
                  </span>
                  <p className="text-xs font-mono text-emerald-400 break-all leading-relaxed">
                    {proto.rawOutput}
                  </p>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
