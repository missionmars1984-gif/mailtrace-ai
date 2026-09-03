import React, { useState } from 'react';
import {
  ShieldAlert,
  Copy,
  Check,
  Globe,
  Link2,
  Mail,
  FileCode,
  Paperclip,
  Download,
} from 'lucide-react';
import type { CaseRecord, IOCItem } from '../../types.js';

interface IndicatorsTabProps {
  caseData: CaseRecord;
}

export const IndicatorsTab: React.FC<IndicatorsTabProps> = ({ caseData }) => {
  const { iocs } = caseData;
  const [activeCategory, setActiveCategory] = useState<string>('ALL');
  const [copiedVal, setCopiedVal] = useState<string | null>(null);

  const categories = ['ALL', 'IP', 'DOMAIN', 'URL', 'EMAIL', 'HASH', 'ATTACHMENT'];

  const filteredIocs =
    activeCategory === 'ALL' ? iocs : iocs.filter((ioc) => ioc.type === activeCategory);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedVal(text);
    setTimeout(() => setCopiedVal(null), 2000);
  };

  const exportAllIocs = () => {
    const text = JSON.stringify(iocs, null, 2);
    const blob = new Blob([text], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `IOCs-${caseData.caseNumber}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'IP':
        return <Globe className="w-3.5 h-3.5 text-indigo-600" />;
      case 'DOMAIN':
        return <Globe className="w-3.5 h-3.5 text-blue-600" />;
      case 'URL':
        return <Link2 className="w-3.5 h-3.5 text-orange-600" />;
      case 'EMAIL':
        return <Mail className="w-3.5 h-3.5 text-purple-600" />;
      case 'HASH':
        return <FileCode className="w-3.5 h-3.5 text-emerald-600" />;
      case 'ATTACHMENT':
        return <Paperclip className="w-3.5 h-3.5 text-amber-600" />;
      default:
        return <ShieldAlert className="w-3.5 h-3.5 text-slate-600" />;
    }
  };

  const getSourceFromType = (type: string) => {
    switch (type) {
      case 'IP':
        return 'Received Header';
      case 'DOMAIN':
        return 'Sender / Header';
      case 'URL':
        return 'Body Hyperlink';
      case 'EMAIL':
        return 'Envelope Header';
      case 'HASH':
      case 'ATTACHMENT':
        return 'Attachment';
      default:
        return 'Email Artifact';
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-100 gap-4">
          <div>
            <h4 className="text-sm font-bold text-slate-900 tracking-wide flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-blue-600" />
              Indicators of Compromise (IOC) Repository ({iocs.length})
            </h4>
            <p className="text-xs text-slate-500 mt-0.5">
              Actionable threat indicators extracted from envelope headers, message body, links, and payloads.
            </p>
          </div>

          <button
            onClick={exportAllIocs}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-xs font-semibold transition-colors self-start sm:self-auto"
          >
            <Download className="w-3.5 h-3.5" />
            Export IOCs (JSON)
          </button>
        </div>

        {/* Category Filter Pills */}
        <div className="flex flex-wrap gap-2 mt-4 pb-4 border-b border-slate-100">
          {categories.map((cat) => {
            const count = cat === 'ALL' ? iocs.length : iocs.filter((i) => i.type === cat).length;
            return (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                  activeCategory === cat
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                }`}
              >
                <span>{cat === 'ALL' ? 'All Indicators' : cat}</span>
                <span
                  className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono ${
                    activeCategory === cat ? 'bg-blue-700 text-white' : 'bg-slate-200 text-slate-700'
                  }`}
                >
                  {count}
                </span>
              </button>
            );
          })}
        </div>

        {/* IOCs Table */}
        <div className="overflow-x-auto mt-4">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-slate-500 font-mono">
                <th className="py-2.5 px-3 font-semibold uppercase text-[10px] w-28">Type</th>
                <th className="py-2.5 px-3 font-semibold uppercase text-[10px]">Indicator Value</th>
                <th className="py-2.5 px-3 font-semibold uppercase text-[10px] w-32">Source</th>
                <th className="py-2.5 px-3 font-semibold uppercase text-[10px] w-24">Risk</th>
                <th className="py-2.5 px-3 font-semibold uppercase text-[10px]">Case Relationship</th>
                <th className="py-2.5 px-3 font-semibold uppercase text-[10px] w-16 text-right">Copy</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredIocs.map((ioc, idx) => (
                <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                  <td className="py-3 px-3 font-bold text-slate-700">
                    <span className="flex items-center gap-1.5">
                      {getTypeIcon(ioc.type)}
                      {ioc.type}
                    </span>
                  </td>
                  <td className="py-3 px-3 font-mono text-slate-900 break-all font-semibold select-all">
                    {ioc.value}
                  </td>
                  <td className="py-3 px-3 text-slate-500 font-mono text-[11px]">
                    {getSourceFromType(ioc.type)}
                  </td>
                  <td className="py-3 px-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        ioc.severity === 'HIGH'
                          ? 'bg-red-100 text-red-700 border border-red-200'
                          : ioc.severity === 'MEDIUM'
                          ? 'bg-amber-100 text-amber-700 border border-amber-200'
                          : 'bg-slate-100 text-slate-600 border border-slate-200'
                      }`}
                    >
                      {ioc.severity}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-slate-700 font-medium">
                    {ioc.context}
                  </td>
                  <td className="py-3 px-3 text-right">
                    <button
                      onClick={() => handleCopy(ioc.value)}
                      className="p-1 hover:bg-slate-200 rounded text-slate-400 hover:text-slate-700 transition-colors"
                      title="Copy Indicator"
                    >
                      {copiedVal === ioc.value ? (
                        <Check className="w-3.5 h-3.5 text-emerald-600" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
