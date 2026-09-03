import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  FileText,
  ShieldCheck,
  ShieldAlert,
  Network,
  Globe2,
  ListFilter,
  FileCheck2,
  Printer,
  Copy,
  Check,
  ArrowLeft,
  RefreshCw,
  Fingerprint,
  MessageSquareWarning,
  Link2,
  Paperclip,
  Scale,
  Lock,
  Trash2,
} from 'lucide-react';
import { ApiService } from '../services/api.js';
import type { CaseRecord } from '../types.js';
import { RiskBadge } from '../components/common/RiskBadge.js';
import { OverviewTab } from '../components/investigation/OverviewTab.js';
import { HeadersTab } from '../components/investigation/HeadersTab.js';
import { AuthTab } from '../components/investigation/AuthTab.js';
import { RouteTab } from '../components/investigation/RouteTab.js';
import { GeoTab } from '../components/investigation/GeoTab.js';
import { IdentityTab } from '../components/investigation/IdentityTab.js';
import { ContentTab } from '../components/investigation/ContentTab.js';
import { UrlsTab } from '../components/investigation/UrlsTab.js';
import { AttachmentsTab } from '../components/investigation/AttachmentsTab.js';
import { IndicatorsTab } from '../components/investigation/IndicatorsTab.js';
import { ThreatAnalysisTab } from '../components/investigation/ThreatAnalysisTab.js';
import { EvidenceTab } from '../components/investigation/EvidenceTab.js';
import { ReportTab } from '../components/investigation/ReportTab.js';

type TabKey =
  | 'overview'
  | 'headers'
  | 'auth'
  | 'route'
  | 'geo'
  | 'identity'
  | 'content'
  | 'urls'
  | 'attachments'
  | 'iocs'
  | 'threat'
  | 'evidence'
  | 'report';

export const InvestigationPage: React.FC = () => {
  const { caseId } = useParams<{ caseId?: string }>();
  const navigate = useNavigate();
  const [caseData, setCaseData] = useState<CaseRecord | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<TabKey>('overview');
  const [copiedId, setCopiedId] = useState<boolean>(false);

  useEffect(() => {
    const fetchTargetCase = async () => {
      try {
        setLoading(true);
        if (caseId) {
          const data = await ApiService.getCaseById(caseId);
          setCaseData(data);
        } else {
          // If navigated directly to /investigation, pick the latest analyzed case
          const cases = await ApiService.getCases();
          if (cases.length > 0) {
            setCaseData(cases[0]);
          }
        }
      } catch (err) {
        console.error('Failed to fetch case data:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchTargetCase();
  }, [caseId]);

  const handleCopyCaseId = () => {
    if (caseData) {
      navigator.clipboard.writeText(caseData.caseNumber);
      setCopiedId(true);
      setTimeout(() => setCopiedId(false), 2000);
    }
  };

  const handleDeleteThisCase = async () => {
    if (!caseData) return;
    if (window.confirm(`Are you sure you want to permanently delete Case ${caseData.caseNumber}?`)) {
      try {
        await ApiService.deleteCase(caseData.id);
        navigate('/cases');
      } catch (err) {
        console.error('Failed to delete case:', err);
        alert('Could not delete case.');
      }
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="flex items-center space-x-3 text-slate-500 text-sm font-medium">
          <RefreshCw className="w-5 h-5 animate-spin text-blue-600" />
          <span>Retrieving Forensic Case Ledger...</span>
        </div>
      </div>
    );
  }

  if (!caseData) {
    return (
      <div className="p-12 text-center space-y-4 max-w-lg mx-auto">
        <ShieldAlert className="w-12 h-12 text-slate-400 mx-auto" />
        <h3 className="text-base font-bold text-slate-900">No Case Record Found</h3>
        <p className="text-xs text-slate-500">
          The requested investigation ID was not found or no emails have been analyzed yet.
        </p>
        <button
          onClick={() => navigate('/analyze')}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg text-xs font-semibold shadow"
        >
          Analyze an Email Now
        </button>
      </div>
    );
  }

  const tabs: Array<{ key: TabKey; label: string; icon: React.ComponentType<{ className?: string }> }> = [
    { key: 'overview', label: 'Overview', icon: FileText },
    { key: 'headers', label: 'Headers', icon: ShieldCheck },
    { key: 'auth', label: 'Authentication', icon: Lock },
    { key: 'route', label: 'Route', icon: Network },
    { key: 'geo', label: 'Origin / Geo', icon: Globe2 },
    { key: 'identity', label: 'Identity', icon: Fingerprint },
    { key: 'content', label: 'Content', icon: MessageSquareWarning },
    { key: 'urls', label: 'URLs & Domains', icon: Link2 },
    { key: 'attachments', label: 'Attachments', icon: Paperclip },
    { key: 'iocs', label: 'IOCs', icon: ListFilter },
    { key: 'threat', label: 'Threat Analysis', icon: Scale },
    { key: 'evidence', label: 'Evidence', icon: FileCheck2 },
    { key: 'report', label: 'Report', icon: Printer },
  ];

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      {/* Top Breadcrumb & Case Master Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
        <div className="flex items-center space-x-3">
          <button
            onClick={() => navigate('/cases')}
            className="p-1.5 rounded-lg border border-slate-200 hover:bg-slate-100 text-slate-600 transition-colors"
            title="Back to Case Registry"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-blue-600 bg-blue-50 px-2 py-0.5 rounded border border-blue-100 flex items-center gap-1.5">
                {caseData.caseNumber}
                <button
                  onClick={handleCopyCaseId}
                  className="hover:text-blue-800"
                  title="Copy Case ID"
                >
                  {copiedId ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                </button>
              </span>
              <RiskBadge
                score={caseData.riskScore}
                level={caseData.riskLevel}
                classification={caseData.classification}
                size="md"
              />
            </div>
            <h2 className="text-base font-bold text-slate-900 mt-1 truncate max-w-xl">
              {caseData.metadata.subject}
            </h2>
          </div>
        </div>

        {/* Right quick telemetry & Delete button */}
        <div className="flex items-center space-x-4 text-xs font-mono text-slate-500 self-start sm:self-auto">
          <div>
            <span className="text-[10px] text-slate-400 uppercase font-sans font-bold block">Confidence</span>
            <strong className="text-slate-800">{caseData.confidence}%</strong>
          </div>
          <div className="border-l border-slate-200 pl-4">
            <span className="text-[10px] text-slate-400 uppercase font-sans font-bold block">Artifacts</span>
            <strong className="text-slate-800">{caseData.findings.length} findings</strong>
          </div>
          <div className="border-l border-slate-200 pl-3">
            <button
              onClick={handleDeleteThisCase}
              className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors inline-flex items-center gap-1 text-xs font-sans font-semibold"
              title="Delete this forensic case"
            >
              <Trash2 className="w-4 h-4" />
              <span className="hidden sm:inline">Delete</span>
            </button>
          </div>
        </div>
      </div>

      {/* 13-Tab Navigation Bar with Clean Horizontal Scroll */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-1.5 overflow-x-auto scrollbar-thin">
        <div className="flex items-center gap-1 min-w-max">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.key;
            return (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={`flex items-center space-x-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all whitespace-nowrap ${
                  isActive
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-white' : 'text-slate-400'}`} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Active Tab Content Area */}
      <div className="min-h-[500px]">
        {activeTab === 'overview' && (
          <OverviewTab caseData={caseData} onNavigateTab={(t) => setActiveTab(t as TabKey)} />
        )}
        {activeTab === 'headers' && <HeadersTab caseData={caseData} />}
        {activeTab === 'auth' && <AuthTab auth={caseData.metadata.auth} />}
        {activeTab === 'route' && <RouteTab caseData={caseData} />}
        {activeTab === 'geo' && <GeoTab caseData={caseData} />}
        {activeTab === 'identity' && <IdentityTab caseData={caseData} />}
        {activeTab === 'content' && <ContentTab caseData={caseData} />}
        {activeTab === 'urls' && <UrlsTab caseData={caseData} />}
        {activeTab === 'attachments' && <AttachmentsTab caseData={caseData} />}
        {activeTab === 'iocs' && <IndicatorsTab caseData={caseData} />}
        {activeTab === 'threat' && <ThreatAnalysisTab caseData={caseData} />}
        {activeTab === 'evidence' && <EvidenceTab caseData={caseData} />}
        {activeTab === 'report' && <ReportTab caseData={caseData} />}
      </div>
    </div>
  );
};
