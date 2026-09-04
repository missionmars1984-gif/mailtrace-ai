import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  UploadCloud,
  FileText,
  Play,
  CheckCircle2,
  Loader2,
  AlertCircle,
  Sparkles,
  ShieldAlert,
  ArrowRight,
  Fingerprint,
  Globe2,
  Link2,
  Paperclip,
  Check,
  Copy,
  ExternalLink,
  Printer,
  RefreshCw,
} from 'lucide-react';
import { ApiService } from '../services/api.js';
import type { CaseRecord } from '../types.js';
import { RiskBadge } from '../components/common/RiskBadge.js';
import { GeoTab } from '../components/investigation/GeoTab.js';

export const AnalyzeEmail: React.FC = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'upload' | 'paste'>('upload');
  const [rawPastedEmail, setRawPastedEmail] = useState<string>('');
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [fileContent, setFileContent] = useState<string>('');

  const [analyzing, setAnalyzing] = useState<boolean>(false);
  const [analysisStep, setAnalysisStep] = useState<number>(0);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [analyzedCase, setAnalyzedCase] = useState<CaseRecord | null>(null);
  const [copiedId, setCopiedId] = useState<boolean>(false);

  const analysisStages = [
    'Parsing Email MIME & RFC822 Headers',
    'Extracting Public IPs & Validating RFC1918 Boundaries',
    'Querying GeoIP Provider & Resolving Autonomous Systems (ASN)',
    'Evaluating Claimed Identity vs Observed Technical Envelope',
    'Analyzing SPF, DKIM, and DMARC Cryptographic Alignment',
    'Scanning URLs for Lookalikes, Homoglyphs & Phishing Patterns',
    'Computing Attachment SHA-256 Digests (No-Execution Isolation)',
    'Synthesizing Deterministic Risk Engine Signals (0–100)',
    'Generating Forensic Evidence Custody Hash & Report Dossier',
  ];



  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setUploadedFile(file);
      const reader = new FileReader();
      reader.onload = (event) => {
        setFileContent(event.target?.result as string);
      };
      reader.readAsText(file);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (file) {
      setUploadedFile(file);
      const reader = new FileReader();
      reader.onload = (event) => {
        setFileContent(event.target?.result as string);
      };
      reader.readAsText(file);
    }
  };

  const runAnalysis = async () => {
    setErrorMessage(null);
    let rawContent = '';

    if (activeTab === 'upload') {
      if (!fileContent.trim()) {
        setErrorMessage('Please select or drop an .eml or raw text email file.');
        return;
      }
      rawContent = fileContent;
    } else if (activeTab === 'paste') {
      if (!rawPastedEmail.trim()) {
        setErrorMessage('Please paste the complete raw email headers and body.');
        return;
      }
      rawContent = rawPastedEmail;
    }

    try {
      setAnalyzing(true);
      setAnalysisStep(0);

      const interval = setInterval(() => {
        setAnalysisStep((prev) => {
          if (prev < analysisStages.length - 1) return prev + 1;
          return prev;
        });
      }, 350);

      const result = await ApiService.analyzeEmail({ rawEmail: rawContent });
      clearInterval(interval);
      setAnalysisStep(analysisStages.length - 1);

      setTimeout(() => {
        setAnalyzedCase(result);
        setAnalyzing(false);
      }, 500);
    } catch (err: any) {
      setErrorMessage(err.message || 'Analysis pipeline failed.');
      setAnalyzing(false);
    }
  };

  const handleCopyCaseId = () => {
    if (analyzedCase) {
      navigator.clipboard.writeText(analyzedCase.caseNumber);
      setCopiedId(true);
      setTimeout(() => setCopiedId(false), 2000);
    }
  };

  const getSeverity = (score: number) => {
    if (score >= 81) return 'Critical';
    if (score >= 61) return 'High Risk';
    if (score >= 41) return 'Suspicious';
    if (score >= 21) return 'Low Risk';
    return 'Clean';
  };

  const getConsistencyBadge = (rating: string) => {
    switch (rating) {
      case 'HIGH':
        return 'bg-emerald-50 text-emerald-800 border-emerald-200';
      case 'MEDIUM':
        return 'bg-amber-50 text-amber-800 border-amber-200';
      case 'LOW':
      default:
        return 'bg-red-50 text-red-800 border-red-200';
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[#0B1F3A] tracking-tight">Email Threat Analysis</h1>
        <p className="text-xs text-[#68809F] mt-1">
          Automated multi-layer digital forensics: MIME header parsing, Claimed vs Observed identity audit, GeoIP route telemetry, and transparent risk scoring.
        </p>
      </div>

      {errorMessage && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-xl text-red-700 text-xs flex items-center gap-2.5 shadow-2xs">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* If an email has NOT been analyzed yet, display the Email Input Console */}
      {!analyzedCase && (
        <div className="bg-white rounded-xl border border-[#E5E9F2] shadow-[0_1px_3px_rgba(11,31,58,0.03)] overflow-hidden">
          {/* Tab Selection */}
          <div className="flex border-b border-[#E5E9F2] bg-[#F7F9FC] px-6 pt-3">
            <button
              onClick={() => setActiveTab('upload')}
              className={`px-4 py-2.5 text-xs font-bold border-b-2 transition-all ${
                activeTab === 'upload'
                  ? 'border-[#246BFE] text-[#246BFE] bg-white rounded-t-xl'
                  : 'border-transparent text-[#68809F] hover:text-[#0B1F3A]'
              }`}
            >
              Upload .EML / RFC822 File
            </button>
            <button
              onClick={() => setActiveTab('paste')}
              className={`px-4 py-2.5 text-xs font-bold border-b-2 transition-all ${
                activeTab === 'paste'
                  ? 'border-[#246BFE] text-[#246BFE] bg-white rounded-t-xl'
                  : 'border-transparent text-[#68809F] hover:text-[#0B1F3A]'
              }`}
            >
              Paste Raw MIME
            </button>
          </div>

          <div className="p-6">

            {/* Tab 2: Upload File */}
            {activeTab === 'upload' && (
              <div
                onDragOver={handleDragOver}
                onDrop={handleDrop}
                className="border-2 border-dashed border-[#E5E9F2] rounded-xl p-10 text-center hover:border-[#246BFE] hover:bg-[#EEF4FF]/20 transition-all cursor-pointer relative"
              >
                <input
                  type="file"
                  accept=".eml,.txt,.msg"
                  onChange={handleFileUpload}
                  className="absolute inset-0 opacity-0 cursor-pointer w-full h-full"
                />
                <UploadCloud className="w-10 h-10 text-[#246BFE] mx-auto mb-3" />
                <div className="font-bold text-sm text-[#0B1F3A]">
                  {uploadedFile ? uploadedFile.name : 'Drop your .eml file here or click to browse'}
                </div>
                <p className="text-xs text-[#68809F] mt-1">
                  {uploadedFile
                    ? `${(uploadedFile.size / 1024).toFixed(1)} KB loaded ready for MIME parsing`
                    : 'Supports standard RFC 822 MIME .eml exported from Gmail, Microsoft 365, or Thunderbird'}
                </p>
              </div>
            )}

            {/* Tab 3: Paste Raw MIME */}
            {activeTab === 'paste' && (
              <div className="space-y-2">
                <label className="text-xs font-bold text-[#68809F] uppercase tracking-wider block">
                  Raw MIME Headers & Message Stream
                </label>
                <textarea
                  rows={11}
                  value={rawPastedEmail}
                  onChange={(e) => setRawPastedEmail(e.target.value)}
                  placeholder="Received: from mail-relay.example.com [198.51.100.42]...&#10;From: Support <support@portal-login.com>&#10;Subject: Urgent Password Expiry Notice...&#10;&#10;Please verify your credentials at http://198.51.100.42/auth/login"
                  className="w-full font-mono text-xs p-3.5 rounded-xl border border-[#E5E9F2] focus:outline-none focus:ring-2 focus:ring-[#246BFE]/30 bg-[#F7F9FC] text-[#0B1F3A]"
                />
              </div>
            )}

            {/* Action Buttons */}
            <div className="mt-6 pt-4 border-t border-[#E5E9F2] flex items-center justify-between">
              <span className="text-xs text-[#68809F] flex items-center gap-1.5">
                <Sparkles className="w-4 h-4 text-[#246BFE]" />
                Dual-Engine: Heuristic Security Engine + Google Gemini AI
              </span>

              <button
                onClick={runAnalysis}
                disabled={analyzing}
                className="inline-flex items-center gap-2 px-6 py-2.5 bg-[#246BFE] hover:bg-blue-700 text-white rounded-xl text-xs font-bold shadow-sm shadow-blue-500/20 disabled:opacity-50 transition-colors"
              >
                {analyzing ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Executing Deep Forensic Analysis...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-current" />
                    Analyze Email
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Analysis Progress Overlay */}
      {analyzing && (
        <div className="bg-white rounded-xl border border-[#246BFE]/30 p-6 shadow-md space-y-4 animate-in fade-in duration-150">
          <div className="flex items-center justify-between border-b border-[#E5E9F2] pb-3">
            <span className="text-xs font-bold text-[#246BFE] uppercase tracking-wider flex items-center gap-2">
              <Sparkles className="w-4 h-4" />
              Automated Forensic Pipeline Stages
            </span>
            <span className="font-mono text-xs text-[#246BFE] font-bold">
              {Math.round(((analysisStep + 1) / analysisStages.length) * 100)}%
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
            {analysisStages.map((stage, idx) => {
              const isDone = idx < analysisStep;
              const isCurrent = idx === analysisStep;
              return (
                <div
                  key={idx}
                  className={`p-2.5 rounded-lg text-xs flex items-center justify-between border transition-all ${
                    isDone
                      ? 'bg-emerald-50 text-emerald-800 border-emerald-200 font-medium'
                      : isCurrent
                      ? 'bg-[#EEF4FF] text-[#246BFE] border-blue-300 font-bold shadow-2xs'
                      : 'bg-[#F7F9FC] text-[#68809F] border-[#E5E9F2]'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <span className="w-4 h-4 rounded-full bg-slate-200 text-slate-700 font-bold text-[9px] flex items-center justify-center font-mono">
                      {idx + 1}
                    </span>
                    {stage}
                  </span>
                  {isDone && <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />}
                  {isCurrent && <Loader2 className="w-4 h-4 animate-spin text-[#246BFE] flex-shrink-0" />}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* IF AN EMAIL HAS BEEN ANALYZED: RENDER FORENSIC ANALYSIS DASHBOARD (Section 6 & 9) */}
      {analyzedCase && (
        <div className="space-y-6">
          {/* Top Section / Case Master Header */}
          <div className="bg-white rounded-xl border border-[#E5E9F2] p-6 shadow-[0_1px_3px_rgba(11,31,58,0.03)] space-y-6">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-[#E5E9F2]">
              <div>
                <div className="flex flex-wrap items-center gap-3">
                  <span className="text-xs font-mono font-bold text-[#246BFE] bg-[#EEF4FF] px-2.5 py-1 rounded-lg border border-blue-200 flex items-center gap-1.5">
                    {analyzedCase.caseNumber}
                    <button onClick={handleCopyCaseId} className="hover:text-blue-900" title="Copy Case ID">
                      {copiedId ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </span>
                  <RiskBadge score={analyzedCase.riskScore} classification={analyzedCase.classification} size="lg" />
                  <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-slate-100 text-slate-800 border border-slate-200">
                    Confidence: {analyzedCase.confidence}%
                  </span>
                  <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-slate-100 text-slate-800 border border-slate-200">
                    Severity: {getSeverity(analyzedCase.riskScore)}
                  </span>
                  <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-emerald-50 text-emerald-800 border border-emerald-200">
                    Delivery: Quarantine Isolated
                  </span>
                </div>
                <h2 className="text-xl font-bold text-[#0B1F3A] mt-3">
                  {analyzedCase.metadata.subject || analyzedCase.subject || '(No Subject)'}
                </h2>
                <p className="text-xs text-[#68809F] mt-1">
                  Received: {analyzedCase.metadata.date ? new Date(analyzedCase.metadata.date).toUTCString() : 'N/A'}
                </p>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-3 flex-wrap">
                <button
                  onClick={() => setAnalyzedCase(null)}
                  className="px-4 py-2 bg-white border border-[#E5E9F2] hover:bg-slate-50 text-[#0B1F3A] rounded-xl text-xs font-bold transition-colors"
                >
                  Analyze Another
                </button>
                <button
                  onClick={() => navigate(`/investigation/${analyzedCase.id}`)}
                  className="inline-flex items-center gap-1.5 px-4 py-2 bg-[#246BFE] hover:bg-blue-700 text-white rounded-xl text-xs font-bold shadow-sm shadow-blue-500/20 transition-colors"
                >
                  <span>Open 13-Tab Investigation</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Score Breakdown Bar */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="p-4 rounded-xl bg-[#F7F9FC] border border-[#E5E9F2]">
                <div className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Risk Score</div>
                <div className="text-3xl font-extrabold text-[#0B1F3A] font-mono mt-1">
                  {analyzedCase.riskScore} <span className="text-sm font-normal text-[#68809F]">/ 100</span>
                </div>
                <div className="w-full bg-slate-200 h-2 rounded-full mt-2 overflow-hidden">
                  <div
                    className={`h-full rounded-full ${
                      analyzedCase.riskScore >= 81
                        ? 'bg-[#EF4444]'
                        : analyzedCase.riskScore >= 61
                        ? 'bg-orange-500'
                        : analyzedCase.riskScore >= 41
                        ? 'bg-[#F59E0B]'
                        : 'bg-[#10B981]'
                    }`}
                    style={{ width: `${Math.max(4, analyzedCase.riskScore)}%` }}
                  />
                </div>
              </div>

              <div className="p-4 rounded-xl bg-[#F7F9FC] border border-[#E5E9F2]">
                <div className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Threat Verdict</div>
                <div className="text-2xl font-bold text-[#0B1F3A] mt-1">{analyzedCase.classification}</div>
                <p className="text-xs text-[#68809F] mt-1">
                  {analyzedCase.classification === 'Clean' ? 'Benign legitimate transmission' : 'High-risk security anomaly'}
                </p>
              </div>

              <div className="p-4 rounded-xl bg-[#F7F9FC] border border-[#E5E9F2]">
                <div className="text-xs font-bold text-[#68809F] uppercase tracking-wider">Cryptographic Custody</div>
                <div className="font-mono text-xs text-[#0B1F3A] truncate mt-1.5" title={analyzedCase.evidenceHash}>
                  SHA-256: {analyzedCase.evidenceHash.substring(0, 16)}...
                </div>
                <p className="text-[11px] text-[#68809F] mt-1">Immutable evidence hash sealed via Node.js crypto</p>
              </div>
            </div>

            {/* Forensic Executive Summary */}
            <div className="p-4 rounded-xl bg-[#F7F9FC] border border-[#E5E9F2]">
              <div className="text-xs font-bold text-[#68809F] uppercase tracking-wider mb-1.5">
                Executive Synthesis
              </div>
              <p className="text-xs text-[#0B1F3A] leading-relaxed">
                {analyzedCase.summary}
              </p>
            </div>
          </div>

          {/* WHY THIS WAS FLAGGED (Section 6) */}
          <div className="bg-white rounded-xl border border-[#E5E9F2] p-6 shadow-[0_1px_3px_rgba(11,31,58,0.03)]">
            <h3 className="text-sm font-bold text-[#0B1F3A] tracking-wide mb-3 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-[#EF4444]" />
              WHY THIS WAS FLAGGED (Evidence-Driven Findings)
            </h3>
            <div className="space-y-2.5">
              {analyzedCase.keyFindings.map((finding, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-xl bg-[#F7F9FC] border border-[#E5E9F2] flex items-start gap-3 text-xs text-[#0B1F3A]"
                >
                  <span className="w-5 h-5 rounded-full bg-red-100 text-red-700 flex items-center justify-center font-bold text-[10px] flex-shrink-0 mt-0.5">
                    {idx + 1}
                  </span>
                  <span className="font-medium leading-relaxed">{finding}</span>
                </div>
              ))}
            </div>
          </div>

          {/* CLAIMED IDENTITY VS OBSERVED TECHNICAL IDENTITY (Section 9) */}
          <div className="bg-white rounded-xl border border-[#E5E9F2] shadow-[0_1px_3px_rgba(11,31,58,0.03)] overflow-hidden">
            <div className="bg-[#0B1F3A] text-white px-6 py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <Fingerprint className="w-5 h-5 text-[#246BFE]" />
                <div>
                  <h4 className="text-sm font-bold tracking-wide">
                    CLAIMED IDENTITY vs OBSERVED TECHNICAL IDENTITY
                  </h4>
                  <p className="text-[11px] text-[#68809F]">
                    Cross-examines human-facing display headers against technical transport envelope records
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-300 font-medium">Identity Consistency:</span>
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${getConsistencyBadge(analyzedCase.identityAnalysis.consistency)}`}>
                  {analyzedCase.identityAnalysis.consistency}
                </span>
              </div>
            </div>

            <div className="p-6 grid grid-cols-1 lg:grid-cols-2 gap-6 bg-[#F7F9FC]/40">
              {/* Claimed Identity */}
              <div className="bg-white p-5 rounded-xl border border-[#E5E9F2] shadow-2xs">
                <div className="flex items-center gap-2 text-xs font-bold text-[#0B1F3A] uppercase tracking-wider pb-3 border-b border-[#E5E9F2]">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#246BFE]" />
                  Claimed Human Identity
                </div>
                <dl className="mt-4 space-y-3 text-xs">
                  <div>
                    <dt className="text-[#68809F] font-medium">Display Name:</dt>
                    <dd className="text-[#0B1F3A] font-bold mt-0.5 text-sm">
                      {analyzedCase.identityAnalysis.claimed.displayName || '(None Specified)'}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-[#68809F] font-medium">From Address:</dt>
                    <dd className="font-mono text-[#0B1F3A] mt-0.5 break-all">
                      {analyzedCase.identityAnalysis.claimed.email}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-[#68809F] font-medium">Claimed Sender Domain:</dt>
                    <dd className="font-mono text-[#246BFE] font-bold mt-0.5">
                      @{analyzedCase.identityAnalysis.claimed.domain}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-[#68809F] font-medium">Reply-To Address:</dt>
                    <dd className={`font-mono mt-0.5 break-all ${analyzedCase.identityAnalysis.replyToMismatch ? 'text-red-600 font-bold' : 'text-[#0B1F3A]'}`}>
                      {analyzedCase.metadata.replyTo?.address || '(Same as From)'}
                    </dd>
                  </div>
                </dl>
              </div>

              {/* Observed Technical Identity */}
              <div className="bg-white p-5 rounded-xl border border-[#E5E9F2] shadow-2xs">
                <div className="flex items-center gap-2 text-xs font-bold text-[#0B1F3A] uppercase tracking-wider pb-3 border-b border-[#E5E9F2]">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#0B1F3A]" />
                  Observed Technical Identity
                </div>
                <dl className="mt-4 space-y-3 text-xs">
                  <div>
                    <dt className="text-[#68809F] font-medium">Return-Path (Envelope Sender):</dt>
                    <dd className={`font-mono mt-0.5 break-all ${analyzedCase.identityAnalysis.returnPathMismatch ? 'text-amber-600 font-bold' : 'text-[#0B1F3A]'}`}>
                      {analyzedCase.identityAnalysis.observed.returnPath || 'Not Specified'}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-[#68809F] font-medium">Sending Origin IP:</dt>
                    <dd className="font-mono text-[#0B1F3A] font-bold mt-0.5 flex items-center gap-1.5">
                      {analyzedCase.observedOriginRelay?.ip || analyzedCase.identityAnalysis.observed.sendingIp || 'Not Available'}
                      {analyzedCase.observedOriginRelay?.geo?.countryCode && (
                        <span className="text-[10px] px-1.5 py-0.2 bg-blue-50 text-blue-700 rounded border border-blue-200">
                          {analyzedCase.observedOriginRelay.geo.countryCode}
                        </span>
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-[#68809F] font-medium">Observed Mail Relay Host:</dt>
                    <dd className="font-mono text-[#0B1F3A] mt-0.5 truncate" title={analyzedCase.observedOriginRelay?.from || analyzedCase.hops[0]?.from}>
                      {analyzedCase.observedOriginRelay?.from || analyzedCase.hops[0]?.from || 'Inbound Mail Gateway'}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-[#68809F] font-medium">Authentication Alignment:</dt>
                    <dd className="flex items-center gap-2 mt-1">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${analyzedCase.metadata.auth.spf.status === 'pass' ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'}`}>
                        SPF: {analyzedCase.metadata.auth.spf.status.toUpperCase()}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${analyzedCase.metadata.auth.dkim.status === 'pass' ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'}`}>
                        DKIM: {analyzedCase.metadata.auth.dkim.status.toUpperCase()}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${analyzedCase.metadata.auth.dmarc.status === 'pass' ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'}`}>
                        DMARC: {analyzedCase.metadata.auth.dmarc.status.toUpperCase()}
                      </span>
                    </dd>
                  </div>
                </dl>
              </div>
            </div>

            {/* Inconsistency Rationale & Forensic Guidance */}
            <div className="p-6 bg-white border-t border-[#E5E9F2]">
              <div className="text-xs font-bold text-[#68809F] uppercase tracking-wider mb-2">
                Identity Inconsistency Explanation:
              </div>
              <ul className="space-y-1.5 text-xs text-[#0B1F3A]">
                {analyzedCase.identityAnalysis.reasons.map((reason, idx) => (
                  <li key={idx} className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444]" />
                    <span>{reason}</span>
                  </li>
                ))}
              </ul>

              <div className="mt-4 p-3 bg-amber-50 border border-amber-200 rounded-xl text-xs text-amber-900 flex items-start gap-2">
                <AlertCircle className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
                <div>
                  <strong>Important Forensic Context:</strong> Do not automatically classify an email as malicious solely because identities differ. Legitimate mailing lists, corporate forwards, and automated ticket trackers routinely employ differing Return-Path and Reply-To addresses.
                </div>
              </div>
            </div>
          </div>

          {/* OBSERVED INFRASTRUCTURE & GEOLOCATION (Section 11 & 12) */}
          <div className="bg-white rounded-xl border border-[#E5E9F2] p-6 shadow-[0_1px_3px_rgba(11,31,58,0.03)] space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#E5E9F2]">
              <div>
                <h3 className="text-sm font-bold text-[#0B1F3A] tracking-wide flex items-center gap-2">
                  <Globe2 className="w-4 h-4 text-[#246BFE]" />
                  OBSERVED EMAIL INFRASTRUCTURE
                </h3>
                <span className="text-[11px] text-[#68809F]">SOURCE: Email Received Technical Header | GEOLOCATION: Approximate</span>
              </div>
              <span className="font-mono text-xs text-[#246BFE] font-bold">
                {analyzedCase.hops.length} Hops Traced
              </span>
            </div>

            {/* Embedded Interactive Geolocation Map & Telemetry */}
            <GeoTab caseData={analyzedCase} />

            {/* Detailed Transport Hops Breakdown */}
            <div className="pt-2">
              <div className="text-xs font-bold text-[#0B1F3A] mb-2 uppercase tracking-wider">
                Full Technical Transport Route Table:
              </div>
            </div>

            {/* Hops Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-[#E5E9F2] bg-[#F7F9FC] text-[#68809F] font-bold">
                    <th className="py-2.5 px-3 uppercase text-[10px]">Hop</th>
                    <th className="py-2.5 px-3 uppercase text-[10px]">Observed IP</th>
                    <th className="py-2.5 px-3 uppercase text-[10px]">Relay Host</th>
                    <th className="py-2.5 px-3 uppercase text-[10px]">Jurisdiction</th>
                    <th className="py-2.5 px-3 uppercase text-[10px]">ASN & ISP</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E5E9F2]">
                  {analyzedCase.hops.map((hop) => (
                    <tr key={hop.hopNumber} className="hover:bg-slate-50">
                      <td className="py-2.5 px-3 font-mono font-bold text-[#0B1F3A]">#{hop.hopNumber}</td>
                      <td className="py-2.5 px-3 font-mono text-[#246BFE] font-bold">
                        {hop.ip || 'Unavailable'}
                      </td>
                      <td className="py-2.5 px-3 text-[#0B1F3A] max-w-[200px] truncate" title={hop.from}>
                        {hop.from || 'Internal Gateway'}
                      </td>
                      <td className="py-2.5 px-3 text-[#0B1F3A]">
                        {hop.isPrivate ? (
                          <span className="text-[#68809F]">NON-PUBLIC IP (Geolocation unavailable)</span>
                        ) : (
                          `${hop.geo?.city ? hop.geo.city + ', ' : ''}${hop.geo?.country || 'Unknown'}`
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-[#68809F] max-w-[220px] truncate" title={hop.geo?.org}>
                        {hop.geo?.asn ? `${hop.geo.asn} (${hop.geo.org || hop.geo.isp || 'Provider'})` : 'Internal Subnet'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Quick Metrics Bar: IOCs & Attachments */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-white p-4 rounded-xl border border-[#E5E9F2] shadow-2xs">
              <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider block">URLs Extracted</span>
              <span className="text-2xl font-bold font-mono text-[#0B1F3A] mt-1 block">{analyzedCase.urls.length}</span>
            </div>
            <div className="bg-white p-4 rounded-xl border border-[#E5E9F2] shadow-2xs">
              <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider block">Attachments</span>
              <span className="text-2xl font-bold font-mono text-[#0B1F3A] mt-1 block">{analyzedCase.attachments.length}</span>
            </div>
            <div className="bg-white p-4 rounded-xl border border-[#E5E9F2] shadow-2xs">
              <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider block">IOCs Ingested</span>
              <span className="text-2xl font-bold font-mono text-[#0B1F3A] mt-1 block">{analyzedCase.iocs.length}</span>
            </div>
            <div className="bg-white p-4 rounded-xl border border-[#E5E9F2] shadow-2xs">
              <span className="text-xs font-bold text-[#68809F] uppercase tracking-wider block">Transport Hops</span>
              <span className="text-2xl font-bold font-mono text-[#0B1F3A] mt-1 block">{analyzedCase.hops.length}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
